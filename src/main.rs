use std::convert::Infallible;
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
use registry_platform_httpsec::Problem;
use registry_trust_connector::config::{self, LoadedConfig, Mode};
use registry_trust_connector::errors::ConnectorError;
use registry_trust_connector::logging::init_tracing;
use registry_trust_connector::proxy::{router, ProxyState};
use registry_trust_connector::tls::{self, PeerCertificateChain};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{error, info};

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);

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
        } => {
            let loaded = config::load(config)?;
            let mode = mode.map(Mode::from).unwrap_or_else(|| detect_mode(&loaded));
            validate_or_error(&loaded, mode, require_env)?;
            println!("registry-trust-connector config valid for {mode:?} mode");
            Ok(())
        }
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

fn internal_problem() -> Response<Body> {
    Problem::new(
        "urn:registry:problem:connector.internal",
        "Internal connector error",
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .detail("request failed inside registry trust connector")
    .into_response()
}
