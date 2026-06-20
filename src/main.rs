use std::collections::BTreeMap;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use clap::{Parser, Subcommand, ValueEnum};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use registry_config_report::{ConfigValueClassification, ReportStatus, RequiredEnvStatus};
use registry_platform_httpsec::Problem;
use registry_trust_connector::config::{self, ConnectorConfig, LoadedConfig, Mode};
use registry_trust_connector::errors::ConnectorError;
use registry_trust_connector::logging::init_tracing;
use registry_trust_connector::proxy::{router, ProxyState};
use registry_trust_connector::tls::{self, PeerCertificateChain};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info};

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);
const TRUST_CONNECTOR_CONFIG_SCHEMA_VERSION: &str = "registry.trust_connector.config.v1";

#[derive(Debug, Parser)]
#[command(author, version, about = "Registry Trust Connector")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate connector configuration and certificate files.
    Validate {
        /// YAML config path.
        #[arg(short, long)]
        config: PathBuf,
        /// Validate required env vars for upstream credentials.
        #[arg(long)]
        require_env: bool,
        /// Override mode detection.
        #[arg(long, value_enum)]
        mode: Option<CliMode>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ValidationOutputFormat::Text)]
        format: ValidationOutputFormat,
    },
    /// Run local client-side connector.
    Client {
        /// YAML config path.
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run remote server-side connector.
    Server {
        /// YAML config path.
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMode {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ValidationOutputFormat {
    Text,
    Json,
}

impl From<CliMode> for Mode {
    fn from(value: CliMode) -> Self {
        match value {
            CliMode::Client => Mode::Client,
            CliMode::Server => Mode::Server,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(error = %err, "registry-trust-connector exiting with failure");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ConnectorError> {
    match Args::parse().command {
        Command::Validate {
            config,
            require_env,
            mode,
            format,
        } => run_validate(config, require_env, mode, format),
        Command::Client { config } => {
            let loaded = config::load(config)?;
            validate_or_error(&loaded, Mode::Client, false)?;
            config::warn_certificate_expiry(&loaded.config, Mode::Client);
            run_client(loaded).await
        }
        Command::Server { config } => {
            let loaded = config::load(config)?;
            validate_or_error(&loaded, Mode::Server, true)?;
            config::warn_certificate_expiry(&loaded.config, Mode::Server);
            run_server(loaded).await
        }
    }
}

fn run_validate(
    config_path: PathBuf,
    require_env: bool,
    mode: Option<CliMode>,
    format: ValidationOutputFormat,
) -> Result<(), ConnectorError> {
    match format {
        ValidationOutputFormat::Text => {
            let loaded = config::load(config_path)?;
            let mode = mode.map(Mode::from).unwrap_or_else(|| detect_mode(&loaded));
            validate_or_error(&loaded, mode, require_env)?;
            println!("registry-trust-connector config valid for {mode:?} mode");
            Ok(())
        }
        ValidationOutputFormat::Json => run_validate_json(config_path, require_env, mode),
    }
}

fn run_validate_json(
    config_path: PathBuf,
    require_env: bool,
    mode: Option<CliMode>,
) -> Result<(), ConnectorError> {
    let raw_config = fs::read_to_string(&config_path).ok();
    let loaded = match config::load(&config_path) {
        Ok(loaded) => loaded,
        Err(err) => {
            let report = validation_report_json(
                &config_path,
                raw_config.as_deref(),
                None,
                vec![json!({
                    "code": "connector.config.load_failed",
                    "severity": "error",
                    "message": err.to_string(),
                })],
            );
            println!("{}", json_pretty(&report)?);
            return Err(err);
        }
    };
    let mode = mode.map(Mode::from).unwrap_or_else(|| detect_mode(&loaded));
    let diagnostics = match config::validate_config(&loaded.config, mode, require_env) {
        Ok(()) => vec![json!({
            "code": "connector.config.valid",
            "severity": "info",
            "message": format!("config valid for {mode:?} mode"),
        })],
        Err(errors) => errors
            .iter()
            .map(|error| {
                json!({
                    "code": "connector.config.validation_error",
                    "severity": "error",
                    "message": error,
                })
            })
            .collect(),
    };
    let report = validation_report_json(
        &config_path,
        raw_config.as_deref(),
        Some(&loaded.config),
        diagnostics,
    );
    let has_errors = report["summary"]["error_count"].as_u64().unwrap_or(0) > 0;
    println!("{}", json_pretty(&report)?);
    if has_errors {
        Err(ConnectorError::InvalidConfig(format!(
            "{} config failed validation",
            loaded.path.display()
        )))
    } else {
        Ok(())
    }
}

fn json_pretty(value: &Value) -> Result<String, ConnectorError> {
    serde_json::to_string_pretty(value).map_err(|err| {
        ConnectorError::InvalidConfig(format!("failed to render JSON report: {err}"))
    })
}

async fn run_client(loaded: LoadedConfig) -> Result<(), ConnectorError> {
    let config = Arc::new(loaded.config);
    let identity = config.client_identity.as_ref().ok_or_else(|| {
        ConnectorError::InvalidConfig("client mode requires client_identity".to_string())
    })?;
    let server = config
        .server
        .as_ref()
        .ok_or_else(|| ConnectorError::InvalidConfig("client mode requires server".to_string()))?;
    let client = tls::reqwest_mtls_client(
        identity,
        &server.trust_bundle,
        config::upstream_timeout(&config),
    )?;
    let bind = config.listen.as_tcp()?;
    let app = router(ProxyState::client(Arc::clone(&config), client));
    let listener = TcpListener::bind(bind).await?;
    info!(mode = "client", listen = %bind, "registry trust connector listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_server(loaded: LoadedConfig) -> Result<(), ConnectorError> {
    let config = Arc::new(loaded.config);
    let bind = config.listen.as_tcp()?;
    let tls_config = tls::server_config(&config)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let app = router(ProxyState::server(Arc::clone(&config))?);
    let listener = TcpListener::bind(bind).await?;
    let connection_permits = Arc::new(Semaphore::new(config.limits.max_concurrent_connections));
    let tls_handshake_timeout = config::tls_handshake_timeout(&config);
    let http1_header_read_timeout = config::http1_header_read_timeout(&config);
    info!(mode = "server", listen = %bind, "registry trust connector listening");

    loop {
        let permit = Arc::clone(&connection_permits)
            .acquire_owned()
            .await
            .map_err(|_| ConnectorError::InvalidConfig("connection limiter closed".to_string()))?;
        let (stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::error!(error = %err, "failed to accept connection");
                drop(permit);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls_stream =
                match tokio::time::timeout(tls_handshake_timeout, acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(err)) => {
                        tracing::warn!(remote = %remote_addr, error = %err, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(remote = %remote_addr, "TLS handshake timed out");
                        return;
                    }
                };
            let peer_chain = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|certs| PeerCertificateChain(certs.to_vec()));
            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |mut req: Request<Incoming>| {
                let app = app.clone();
                let peer_chain = peer_chain.clone();
                async move {
                    if let Some(chain) = peer_chain {
                        req.extensions_mut().insert(chain);
                    }
                    let (parts, incoming) = req.into_parts();
                    let req = Request::from_parts(parts, Body::new(incoming));
                    let response = app
                        .oneshot(req)
                        .await
                        .unwrap_or_else(|_| internal_problem());
                    Ok::<Response<Body>, Infallible>(response)
                }
            });
            let mut builder = HyperBuilder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(http1_header_read_timeout)
                .keep_alive(false);
            if let Err(err) = builder.serve_connection(io, service).await {
                tracing::warn!(remote = %remote_addr, error = %err, "connection failed");
            }
            drop(permit);
        });
    }
}

fn validate_or_error(
    loaded: &LoadedConfig,
    mode: Mode,
    require_env: bool,
) -> Result<(), ConnectorError> {
    config::validate_config(&loaded.config, mode, require_env).map_err(|errors| {
        ConnectorError::InvalidConfig(format!(
            "{} config failed validation:\n{}",
            loaded.path.display(),
            errors
                .iter()
                .map(|err| format!("- {err}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    })
}

fn detect_mode(loaded: &LoadedConfig) -> Mode {
    if loaded.config.server_identity.is_some()
        || loaded.config.client_trust.is_some()
        || loaded.config.upstream.is_some()
    {
        Mode::Server
    } else {
        Mode::Client
    }
}

fn validation_report_json(
    config_path: &std::path::Path,
    raw_config: Option<&str>,
    config: Option<&ConnectorConfig>,
    diagnostics: Vec<Value>,
) -> Value {
    let error_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic["severity"] == "error")
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic["severity"] == "warning")
        .count();
    let mut report = json!({
        "schema_version": "registry.config.diagnostic_report.v1",
        "product": "registry-trust-connector",
        "config_schema_version": TRUST_CONNECTOR_CONFIG_SCHEMA_VERSION,
        "source": {
            "kind": "local_file",
            "path": path_for_json(config_path),
        },
        "status": if error_count > 0 {
            ReportStatus::Error.as_str()
        } else if warning_count > 0 {
            ReportStatus::Warning.as_str()
        } else {
            ReportStatus::Ok.as_str()
        },
        "summary": {
            "error_count": error_count,
            "warning_count": warning_count,
        },
        "diagnostics": diagnostics,
        "required_env": config.map(required_env_report).unwrap_or_default(),
        "generated_at": now_rfc3339(),
    });
    if let Some(raw) = raw_config {
        report["hashes"] = json!({
            "internal_config_hash": sha256_hash(raw.as_bytes()),
        });
    }
    report
}

fn required_env_report(config: &ConnectorConfig) -> Vec<Value> {
    let mut envs = BTreeMap::new();
    if let Some(hash_secret_env) = &config.audit.hash_secret_env {
        envs.insert(hash_secret_env.clone(), ConfigValueClassification::Secret);
    }
    if let Some(upstream) = &config.upstream {
        if let Some(env) = &upstream.default_auth_header_env {
            envs.insert(env.clone(), ConfigValueClassification::Secret);
        }
    }
    for route in &config.routes {
        if let Some(env) = &route.upstream_auth_header_env {
            envs.insert(env.clone(), ConfigValueClassification::Secret);
        }
    }
    envs.into_iter()
        .map(|(name, classification)| {
            json!({
                "name": name,
                "classification": classification.as_str(),
                "status": if env::var_os(&name).is_some() {
                    RequiredEnvStatus::Present.as_str()
                } else {
                    RequiredEnvStatus::Missing.as_str()
                },
            })
        })
        .collect()
}

fn path_for_json(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

fn sha256_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("system clock timestamp formats as RFC3339")
}

fn internal_problem() -> Response<Body> {
    Problem::new(
        "urn:registry:problem:connector.internal",
        "Internal connector error",
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .detail("request failed inside registry trust connector")
    .into_response()
}
