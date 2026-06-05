use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http::header::HeaderName;
use http::Method;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::errors::ConnectorError;
use crate::identity::{
    certificate_summary, validate_ca_certificate, validate_leaf_certificate, EkUsage,
};
use crate::routing::validate_route_prefix;

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_UPSTREAM_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_EXPIRY_WARNING_DAYS: i64 = 30;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    pub listen: ListenConfig,
    #[serde(default)]
    pub server: Option<ClientServerConfig>,
    #[serde(default)]
    pub client_identity: Option<IdentityFiles>,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub server_identity: Option<IdentityFiles>,
    #[serde(default)]
    pub client_trust: Option<ClientTrustConfig>,
    #[serde(default)]
    pub upstream: Option<UpstreamConfig>,
    #[serde(default)]
    pub allow_non_loopback_client_listen: bool,
    #[serde(default)]
    pub allow_dns_san_identity: bool,
    #[serde(default)]
    pub connector_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ListenConfig {
    Tcp(SocketAddr),
    Unix(String),
}

impl ListenConfig {
    pub fn as_tcp(&self) -> Result<SocketAddr, ConnectorError> {
        match self {
            Self::Tcp(addr) => Ok(*addr),
            Self::Unix(_) => Err(ConnectorError::InvalidConfig(
                "unix socket listeners are not implemented in the MVP binary yet".to_string(),
            )),
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self {
            Self::Tcp(addr) => addr.ip().is_loopback(),
            Self::Unix(_) => true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientServerConfig {
    pub url: Url,
    pub trust_bundle: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    pub data_purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_upstream_timeout_seconds")]
    pub upstream_timeout_seconds: u64,
    #[serde(default = "default_expiry_warning_days")]
    pub expiry_warning_days: i64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: default_max_body_bytes(),
            upstream_timeout_seconds: default_upstream_timeout_seconds(),
            expiry_warning_days: default_expiry_warning_days(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTrustConfig {
    #[serde(default)]
    pub allowed_identities: Vec<String>,
    #[serde(default)]
    pub trust_anchors: Vec<TrustAnchorConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustAnchorConfig {
    pub ca: PathBuf,
    pub trust_domain: String,
    #[serde(default)]
    pub dns_identities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub base_url: Url,
    pub default_auth_header_env: Option<String>,
    #[serde(default = "default_auth_header_name")]
    pub auth_header_name: String,
    #[serde(default = "default_auth_header_scheme")]
    pub auth_header_scheme: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub id: String,
    #[serde(default, deserialize_with = "deserialize_methods")]
    pub methods: Vec<Method>,
    #[serde(default)]
    pub local_prefix: Option<String>,
    #[serde(default)]
    pub upstream_prefix: Option<String>,
    #[serde(default)]
    pub require_purpose: bool,
    #[serde(default)]
    pub purpose_source: Option<PurposeSource>,
    #[serde(default)]
    pub client_identity: Option<String>,
    #[serde(default)]
    pub upstream_auth_header_env: Option<String>,
    #[serde(default)]
    pub forward_client_identity_header: bool,
    #[serde(default)]
    pub purposes: Vec<String>,
    #[serde(default)]
    pub allow_forward_authorization: bool,
    #[serde(default)]
    pub allow_forward_cookie: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PurposeSource {
    ClientProvided,
    StaticRouteDefault,
    DeniedMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: ConnectorConfig,
    pub path: PathBuf,
}

pub fn load(path: impl AsRef<Path>) -> Result<LoadedConfig, ConnectorError> {
    let path = path.as_ref();
    let raw = std::fs::read_to_string(path)?;
    let config: ConnectorConfig = serde_saphyr::from_str(&raw)?;
    Ok(LoadedConfig {
        config,
        path: path.to_path_buf(),
    })
}

pub fn validate_config(
    config: &ConnectorConfig,
    mode: Mode,
    require_env: bool,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    match mode {
        Mode::Client => validate_client(config, require_env, &mut errors),
        Mode::Server => validate_server(config, require_env, &mut errors),
    }
    validate_common(config, &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn warn_certificate_expiry(config: &ConnectorConfig, mode: Mode) {
    let threshold = Duration::from_secs((config.limits.expiry_warning_days.max(0) as u64) * 86_400);
    let identities = match mode {
        Mode::Client => config.client_identity.iter().collect::<Vec<_>>(),
        Mode::Server => config.server_identity.iter().collect::<Vec<_>>(),
    };
    for identity in identities {
        if let Ok(summary) = certificate_summary(&identity.cert) {
            if summary.expires_within(threshold) {
                tracing::warn!(
                    cert = %identity.cert.display(),
                    not_after = %summary.not_after,
                    "connector certificate expires soon"
                );
            }
        }
    }
}

fn validate_common(config: &ConnectorConfig, errors: &mut Vec<String>) {
    if config.routes.is_empty() {
        errors.push("routes must not be empty".to_string());
    }
    if config.limits.upstream_timeout_seconds == 0 {
        errors.push("limits.upstream_timeout_seconds must be greater than zero".to_string());
    }
    let mut ids = BTreeSet::new();
    for route in &config.routes {
        if route.id.trim().is_empty() {
            errors.push("route without id".to_string());
        } else if !ids.insert(route.id.clone()) {
            errors.push(format!("duplicate route id '{}'", route.id));
        }
        if route.methods.is_empty() {
            errors.push(format!(
                "route '{}' must declare at least one method",
                route.id
            ));
        }
        if let Some(prefix) = route.local_prefix.as_deref() {
            collect_prefix_error(&route.id, "local_prefix", prefix, errors);
        }
        if let Some(prefix) = route.upstream_prefix.as_deref() {
            collect_prefix_error(&route.id, "upstream_prefix", prefix, errors);
        }
        for purpose in &route.purposes {
            if purpose.trim().is_empty() {
                errors.push(format!("route '{}' contains an empty purpose", route.id));
            }
        }
    }
}

fn validate_client(config: &ConnectorConfig, require_env: bool, errors: &mut Vec<String>) {
    if !config.listen.is_loopback() && !config.allow_non_loopback_client_listen {
        errors.push(
            "client listen on non-loopback interfaces requires allow_non_loopback_client_listen: true"
                .to_string(),
        );
    }
    let Some(server) = &config.server else {
        errors.push("client config requires server".to_string());
        return;
    };
    require_file("server.trust_bundle", &server.trust_bundle, errors);
    let Some(identity) = &config.client_identity else {
        errors.push("client config requires client_identity".to_string());
        return;
    };
    validate_identity_files("client_identity", identity, EkUsage::ClientAuth, errors);
    for route in &config.routes {
        if route.local_prefix.as_deref().unwrap_or_default().is_empty() {
            errors.push(format!("client route '{}' requires local_prefix", route.id));
        }
        if route
            .upstream_prefix
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            errors.push(format!(
                "client route '{}' requires upstream_prefix",
                route.id
            ));
        }
        if route.require_purpose
            && route.purpose_source == Some(PurposeSource::StaticRouteDefault)
            && config
                .defaults
                .data_purpose
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            errors.push(format!(
                "client route '{}' needs defaults.data_purpose for static_route_default",
                route.id
            ));
        }
    }
    if require_env {
        let _ = require_env;
    }
}

fn validate_server(config: &ConnectorConfig, require_env: bool, errors: &mut Vec<String>) {
    let Some(identity) = &config.server_identity else {
        errors.push("server config requires server_identity".to_string());
        return;
    };
    validate_identity_files("server_identity", identity, EkUsage::ServerAuth, errors);
    let Some(client_trust) = &config.client_trust else {
        errors.push("server config requires client_trust".to_string());
        return;
    };
    if client_trust.allowed_identities.is_empty() {
        errors.push("client_trust.allowed_identities must not be empty".to_string());
    }
    if client_trust.trust_anchors.is_empty() {
        errors.push("client_trust.trust_anchors must not be empty".to_string());
    }
    let mut trust_domains = BTreeSet::new();
    for anchor in &client_trust.trust_anchors {
        require_file("client_trust.trust_anchors[].ca", &anchor.ca, errors);
        if anchor.trust_domain.trim().is_empty() {
            errors.push("client_trust.trust_anchors[].trust_domain must not be empty".to_string());
        } else {
            trust_domains.insert(anchor.trust_domain.clone());
        }
        for identity in &anchor.dns_identities {
            if identity.trim().is_empty() {
                errors.push(
                    "client_trust.trust_anchors[].dns_identities contains an empty identity"
                        .to_string(),
                );
            }
        }
        if let Err(err) = validate_ca_certificate(&anchor.ca) {
            errors.push(format!("trust anchor '{}': {err}", anchor.ca.display()));
        }
    }
    let dns_identities = dns_identity_set(config);
    for identity in &client_trust.allowed_identities {
        if identity.trim().is_empty() {
            errors.push("client_trust.allowed_identities contains an empty identity".to_string());
            continue;
        }
        if let Some(domain) = spiffe_trust_domain(identity) {
            if !trust_domains.contains(domain) {
                errors.push(format!(
                    "client identity '{}' has no trust anchor for trust domain '{}'",
                    identity, domain
                ));
            }
        } else if !config.allow_dns_san_identity {
            errors.push(format!(
                "client identity '{}' is not a SPIFFE URI and DNS SAN fallback is disabled",
                identity
            ));
        } else if !dns_identities.contains(identity) {
            errors.push(format!(
                "DNS client identity '{}' must be bound to at least one client_trust.trust_anchors[].dns_identities entry",
                identity
            ));
        }
    }
    let Some(upstream) = &config.upstream else {
        errors.push("server config requires upstream".to_string());
        return;
    };
    validate_upstream_auth_header_name(&upstream.auth_header_name, errors);
    if matches!(upstream.default_auth_header_env.as_deref(), Some(value) if value.trim().is_empty())
    {
        errors.push("upstream.default_auth_header_env must not be empty".to_string());
    }
    for route in &config.routes {
        if matches!(route.upstream_auth_header_env.as_deref(), Some(value) if value.trim().is_empty())
        {
            errors.push(format!(
                "server route '{}' upstream_auth_header_env must not be empty",
                route.id
            ));
        }
    }
    if require_env {
        let mut required = BTreeSet::new();
        if let Some(var) = upstream.default_auth_header_env.as_deref() {
            required.insert(var.to_string());
        }
        for route in &config.routes {
            if let Some(var) = route.upstream_auth_header_env.as_deref() {
                required.insert(var.to_string());
            }
        }
        for var in required {
            match env::var(&var) {
                Ok(value) if !value.trim().is_empty() => {}
                Ok(_) => {
                    errors.push(format!("required upstream auth env var '{var}' is empty"));
                }
                Err(_) => {
                    errors.push(format!("required upstream auth env var '{var}' is missing"));
                }
            }
        }
    }
    for route in &config.routes {
        if route
            .upstream_prefix
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        {
            errors.push(format!(
                "server route '{}' requires upstream_prefix",
                route.id
            ));
        }
        let Some(identity) = route.client_identity.as_deref() else {
            errors.push(format!(
                "server route '{}' requires client_identity so route and purpose policy are identity-bound",
                route.id
            ));
            continue;
        };
        if !client_trust
            .allowed_identities
            .iter()
            .any(|allowed| allowed == identity)
        {
            errors.push(format!(
                "server route '{}' references client_identity '{}' not in client_trust.allowed_identities",
                route.id, identity
            ));
        }
    }
}

pub fn trust_domain_map(config: &ConnectorConfig) -> BTreeMap<String, Vec<PathBuf>> {
    let mut out: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    if let Some(trust) = &config.client_trust {
        for anchor in &trust.trust_anchors {
            out.entry(anchor.trust_domain.clone())
                .or_default()
                .push(anchor.ca.clone());
        }
    }
    out
}

pub fn dns_identity_map(config: &ConnectorConfig) -> BTreeMap<String, Vec<PathBuf>> {
    let mut out = BTreeMap::new();
    if let Some(trust) = &config.client_trust {
        for anchor in &trust.trust_anchors {
            for identity in &anchor.dns_identities {
                out.entry(identity.clone())
                    .or_insert_with(Vec::new)
                    .push(anchor.ca.clone());
            }
        }
    }
    out
}

fn dns_identity_set(config: &ConnectorConfig) -> BTreeSet<String> {
    dns_identity_map(config).into_keys().collect()
}

pub fn spiffe_trust_domain(identity: &str) -> Option<&str> {
    identity
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split('/').next())
        .filter(|value| !value.is_empty())
}

pub fn max_body_bytes(config: &ConnectorConfig) -> usize {
    config.limits.max_body_bytes
}

pub fn upstream_timeout(config: &ConnectorConfig) -> Duration {
    Duration::from_secs(config.limits.upstream_timeout_seconds)
}

fn validate_identity_files(
    prefix: &str,
    identity: &IdentityFiles,
    usage: EkUsage,
    errors: &mut Vec<String>,
) {
    require_file(&format!("{prefix}.cert"), &identity.cert, errors);
    require_file(&format!("{prefix}.key"), &identity.key, errors);
    if identity.cert.exists() && identity.key.exists() {
        if let Err(err) = validate_leaf_certificate(&identity.cert, &identity.key, usage) {
            errors.push(format!("{prefix}: {err}"));
        }
    }
}

fn validate_upstream_auth_header_name(name: &str, errors: &mut Vec<String>) {
    let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
        errors.push(format!(
            "upstream.auth_header_name '{name}' is not a valid HTTP header name"
        ));
        return;
    };
    if is_hop_by_hop_header(&header_name) {
        errors.push(format!(
            "upstream.auth_header_name '{name}' must not be a hop-by-hop header"
        ));
    }
    if header_name.as_str().starts_with("x-registry-connector-") {
        errors.push(format!(
            "upstream.auth_header_name '{name}' must not use the x-registry-connector-* private prefix"
        ));
    }
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn require_file(field: &str, path: &Path, errors: &mut Vec<String>) {
    if path.as_os_str().is_empty() {
        errors.push(format!("{field} must not be empty"));
    } else if !path.exists() {
        errors.push(format!("{field} '{}' does not exist", path.display()));
    }
}

fn collect_prefix_error(route_id: &str, field: &str, prefix: &str, errors: &mut Vec<String>) {
    if let Err(err) = validate_route_prefix(prefix) {
        errors.push(format!("route '{route_id}' {field}: {err}"));
    }
}

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

fn default_upstream_timeout_seconds() -> u64 {
    DEFAULT_UPSTREAM_TIMEOUT_SECONDS
}

fn default_expiry_warning_days() -> i64 {
    DEFAULT_EXPIRY_WARNING_DAYS
}

fn default_auth_header_name() -> String {
    "Authorization".to_string()
}

fn default_auth_header_scheme() -> String {
    "Bearer".to_string()
}

fn deserialize_methods<'de, D>(deserializer: D) -> Result<Vec<Method>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            value
                .parse::<Method>()
                .map_err(|_| serde::de::Error::custom(format!("invalid HTTP method '{value}'")))
        })
        .collect()
}
