use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::Method;
use registry_platform_audit::AuditKeyHasher;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::errors::ConnectorError;
use crate::identity::{
    certificate_summary, validate_ca_certificate, validate_leaf_certificate, EkUsage,
};
use crate::routing::validate_route_prefix;

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_UPSTREAM_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_HTTP1_HEADER_READ_TIMEOUT_SECONDS: u64 = 10;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1024;
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_REQUESTS_PER_IDENTITY_PER_MINUTE: u32 = 600;
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
    pub audit: AuditConfig,
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub hash_secret_env: Option<String>,
    #[serde(default)]
    pub allow_unkeyed_hashing: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_upstream_timeout_seconds")]
    pub upstream_timeout_seconds: u64,
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_tls_handshake_timeout_seconds")]
    pub tls_handshake_timeout_seconds: u64,
    #[serde(default = "default_http1_header_read_timeout_seconds")]
    pub http1_header_read_timeout_seconds: u64,
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
    #[serde(default = "default_max_requests_per_identity_per_minute")]
    pub max_requests_per_identity_per_minute: u32,
    #[serde(default = "default_expiry_warning_days")]
    pub expiry_warning_days: i64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: default_max_body_bytes(),
            upstream_timeout_seconds: default_upstream_timeout_seconds(),
            request_timeout_seconds: default_request_timeout_seconds(),
            tls_handshake_timeout_seconds: default_tls_handshake_timeout_seconds(),
            http1_header_read_timeout_seconds: default_http1_header_read_timeout_seconds(),
            max_concurrent_requests: default_max_concurrent_requests(),
            max_concurrent_connections: default_max_concurrent_connections(),
            max_requests_per_identity_per_minute: default_max_requests_per_identity_per_minute(),
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
    #[serde(default)]
    pub denied_certificate_fingerprints_sha256: Vec<String>,
    #[serde(default)]
    pub trust_context_entitlements: Vec<TrustContextEntitlementConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustContextEntitlementConfig {
    pub client_identity: String,
    #[serde(default)]
    pub trusted_context: GovernedTrustedContextConfig,
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
    pub client_identities: Vec<String>,
    #[serde(default)]
    pub upstream_auth_header_env: Option<String>,
    #[serde(default)]
    pub forward_client_identity_header: bool,
    #[serde(default)]
    pub purposes: Vec<String>,
    #[serde(default)]
    pub governed_policy: Option<GovernedRoutePolicyConfig>,
    #[serde(default)]
    pub allow_forward_authorization: bool,
    #[serde(default)]
    pub allow_forward_cookie: bool,
    #[serde(skip)]
    pub policy_hash: PolicyHashCache,
}

#[derive(Debug, Default)]
pub struct PolicyHashCache {
    inner: Mutex<Option<(String, String)>>,
}

impl Clone for PolicyHashCache {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl PolicyHashCache {
    pub fn get_or_compute<F>(&self, material: String, compute: F) -> String
    where
        F: FnOnce(&str) -> String,
    {
        let mut cached = self
            .inner
            .lock()
            .expect("route policy hash cache is healthy");
        if let Some((cached_material, cached_hash)) = cached.as_ref() {
            if cached_material == &material {
                return cached_hash.clone();
            }
        }
        let hash = compute(&material);
        *cached = Some((material, hash.clone()));
        hash
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernedRoutePolicyConfig {
    #[serde(default)]
    pub permitted_purposes: Vec<String>,
    #[serde(default)]
    pub permitted_jurisdictions: Vec<String>,
    #[serde(default)]
    pub allowed_assurance: Vec<String>,
    #[serde(default)]
    pub minimum_assurance: Option<String>,
    #[serde(default)]
    pub max_source_age_seconds: Option<u64>,
    #[serde(default)]
    pub require_legal_basis: bool,
    #[serde(default)]
    pub require_consent: bool,
    #[serde(default)]
    pub redaction_fields: Vec<String>,
    #[serde(default)]
    pub unsupported_odrl_terms: Vec<String>,
    #[serde(default)]
    pub trusted_context: GovernedTrustedContextConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GovernedTrustedContextConfig {
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub asserted_assurance: Option<String>,
    #[serde(default)]
    pub legal_basis_ref: Option<String>,
    #[serde(default)]
    pub consent_ref: Option<String>,
    #[serde(default)]
    pub source_observed_age_seconds: Option<u64>,
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
    if config.limits.request_timeout_seconds == 0 {
        errors.push("limits.request_timeout_seconds must be greater than zero".to_string());
    }
    if config.limits.tls_handshake_timeout_seconds == 0 {
        errors.push("limits.tls_handshake_timeout_seconds must be greater than zero".to_string());
    }
    if config.limits.http1_header_read_timeout_seconds == 0 {
        errors
            .push("limits.http1_header_read_timeout_seconds must be greater than zero".to_string());
    }
    if config.limits.max_concurrent_requests == 0 {
        errors.push("limits.max_concurrent_requests must be greater than zero".to_string());
    }
    if config.limits.max_concurrent_connections == 0 {
        errors.push("limits.max_concurrent_connections must be greater than zero".to_string());
    }
    if config.limits.max_requests_per_identity_per_minute == 0 {
        errors.push(
            "limits.max_requests_per_identity_per_minute must be greater than zero".to_string(),
        );
    }
    match config.audit.hash_secret_env.as_deref() {
        Some(value) if value.trim().is_empty() => {
            errors.push("audit.hash_secret_env must not be empty".to_string());
        }
        Some(_) => {}
        None if !config.audit.allow_unkeyed_hashing => {
            errors.push(
                "audit.hash_secret_env is required unless audit.allow_unkeyed_hashing is true"
                    .to_string(),
            );
        }
        None => {}
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
        for identity in &route.client_identities {
            if identity.trim().is_empty() {
                errors.push(format!(
                    "route '{}' contains an empty client_identity",
                    route.id
                ));
            }
        }
        if let Some(policy) = route.governed_policy.as_ref() {
            validate_governed_route_policy(&route.id, policy, errors);
        }
    }
}

fn validate_governed_route_policy(
    route_id: &str,
    policy: &GovernedRoutePolicyConfig,
    errors: &mut Vec<String>,
) {
    if !governed_route_policy_has_gate(policy) {
        errors.push(format!(
            "route '{route_id}' governed_policy must enforce at least one gate"
        ));
    }
    for purpose in &policy.permitted_purposes {
        if purpose.trim().is_empty() {
            errors.push(format!(
                "route '{route_id}' governed_policy contains an empty permitted_purpose"
            ));
        }
    }
    for jurisdiction in &policy.permitted_jurisdictions {
        if jurisdiction.trim().is_empty() {
            errors.push(format!(
                "route '{route_id}' governed_policy contains an empty permitted_jurisdiction"
            ));
        }
    }
    for assurance in &policy.allowed_assurance {
        if assurance.trim().is_empty() {
            errors.push(format!(
                "route '{route_id}' governed_policy contains an empty allowed_assurance"
            ));
        }
    }
    if matches!(policy.minimum_assurance.as_deref(), Some(value) if value.trim().is_empty()) {
        errors.push(format!(
            "route '{route_id}' governed_policy minimum_assurance must not be empty"
        ));
    }
    if policy.max_source_age_seconds == Some(0) {
        errors.push(format!(
            "route '{route_id}' governed_policy max_source_age_seconds must be greater than zero"
        ));
    }
    for field in &policy.redaction_fields {
        if field.trim().is_empty() {
            errors.push(format!(
                "route '{route_id}' governed_policy contains an empty redaction_field"
            ));
        }
    }
    for term in &policy.unsupported_odrl_terms {
        if term.trim().is_empty() {
            errors.push(format!(
                "route '{route_id}' governed_policy contains an empty unsupported_odrl_term"
            ));
        }
    }
    validate_trusted_context_fields(
        &format!("route '{route_id}' governed_policy trusted_context"),
        &policy.trusted_context,
        errors,
    );
}

fn governed_route_policy_has_gate(policy: &GovernedRoutePolicyConfig) -> bool {
    policy
        .permitted_purposes
        .iter()
        .any(|value| !value.trim().is_empty())
        || policy
            .permitted_jurisdictions
            .iter()
            .any(|value| !value.trim().is_empty())
        || policy
            .allowed_assurance
            .iter()
            .any(|value| !value.trim().is_empty())
        || policy
            .minimum_assurance
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || policy.max_source_age_seconds.is_some_and(|value| value > 0)
        || policy.require_legal_basis
        || policy.require_consent
        || policy
            .redaction_fields
            .iter()
            .any(|value| !value.trim().is_empty())
        || policy
            .unsupported_odrl_terms
            .iter()
            .any(|value| !value.trim().is_empty())
}

fn validate_trusted_context_fields(
    prefix: &str,
    trusted: &GovernedTrustedContextConfig,
    errors: &mut Vec<String>,
) {
    if matches!(trusted.jurisdiction.as_deref(), Some(value) if value.trim().is_empty()) {
        errors.push(format!("{prefix}.jurisdiction must not be empty"));
    }
    if matches!(trusted.asserted_assurance.as_deref(), Some(value) if value.trim().is_empty()) {
        errors.push(format!("{prefix}.asserted_assurance must not be empty"));
    }
    if matches!(trusted.legal_basis_ref.as_deref(), Some(value) if value.trim().is_empty()) {
        errors.push(format!("{prefix}.legal_basis_ref must not be empty"));
    }
    if matches!(trusted.consent_ref.as_deref(), Some(value) if value.trim().is_empty()) {
        errors.push(format!("{prefix}.consent_ref must not be empty"));
    }
    if trusted.source_observed_age_seconds == Some(0) {
        errors.push(format!(
            "{prefix}.source_observed_age_seconds must be greater than zero"
        ));
    }
}

fn trusted_context_has_assertion(trusted: &GovernedTrustedContextConfig) -> bool {
    trusted
        .jurisdiction
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || trusted
            .asserted_assurance
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || trusted
            .legal_basis_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || trusted
            .consent_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || trusted
            .source_observed_age_seconds
            .is_some_and(|value| value > 0)
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
    if server.url.scheme() != "https" {
        errors.push("client server.url must use https".to_string());
    }
    if !is_root_url_path(&server.url) {
        errors.push("client server.url must not include a path".to_string());
    }
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
        require_audit_hash_env(config, errors);
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
    for fingerprint in &client_trust.denied_certificate_fingerprints_sha256 {
        if !is_sha256_fingerprint(fingerprint) {
            errors.push(
                "client_trust.denied_certificate_fingerprints_sha256 contains an invalid SHA-256 fingerprint"
                    .to_string(),
            );
        }
    }
    let mut entitlement_identities = BTreeSet::new();
    for entitlement in &client_trust.trust_context_entitlements {
        validate_trust_context_entitlement(
            client_trust,
            entitlement,
            &mut entitlement_identities,
            errors,
        );
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
    if !is_root_url_path(&upstream.base_url) {
        errors.push("upstream.base_url must not include a path".to_string());
    }
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
        require_audit_hash_env(config, errors);
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
                Ok(value) if !value.trim().is_empty() => {
                    if HeaderValue::from_str(&value).is_err() {
                        errors.push(format!(
                            "required upstream auth env var '{var}' contains invalid characters for an HTTP header value"
                        ));
                    }
                }
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
        let route_identities = route_client_identities(route);
        if route_identities.is_empty() {
            errors.push(format!(
                "server route '{}' requires client_identity so route and purpose policy are identity-bound",
                route.id
            ));
            continue;
        }
        for identity in route_identities {
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
}

fn validate_trust_context_entitlement(
    client_trust: &ClientTrustConfig,
    entitlement: &TrustContextEntitlementConfig,
    seen_identities: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let identity = entitlement.client_identity.trim();
    if identity.is_empty() {
        errors.push(
            "client_trust.trust_context_entitlements[].client_identity must not be empty"
                .to_string(),
        );
        return;
    }
    if !seen_identities.insert(identity.to_string()) {
        errors.push(format!(
            "duplicate client_trust.trust_context_entitlements client_identity '{}'",
            entitlement.client_identity
        ));
    }
    if !client_trust
        .allowed_identities
        .iter()
        .any(|allowed| allowed == identity)
    {
        errors.push(format!(
            "client_trust.trust_context_entitlements client_identity '{}' not in client_trust.allowed_identities",
            entitlement.client_identity
        ));
    }
    if !trusted_context_has_assertion(&entitlement.trusted_context) {
        errors.push(format!(
            "client_trust.trust_context_entitlements for '{}' must grant at least one trust context assertion",
            entitlement.client_identity
        ));
    }
    validate_trusted_context_fields(
        "client_trust.trust_context_entitlements[].trusted_context",
        &entitlement.trusted_context,
        errors,
    );
}

fn route_client_identities(route: &RouteConfig) -> BTreeSet<&str> {
    let mut identities = BTreeSet::new();
    if let Some(identity) = route
        .client_identity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        identities.insert(identity);
    }
    for identity in &route.client_identities {
        let identity = identity.trim();
        if !identity.is_empty() {
            identities.insert(identity);
        }
    }
    identities
}

fn require_audit_hash_env(config: &ConnectorConfig, errors: &mut Vec<String>) {
    let Some(var) = config.audit.hash_secret_env.as_deref() else {
        return;
    };
    if let Err(err) = AuditKeyHasher::from_env(var) {
        errors.push(format!(
            "required audit hash env var '{var}' is invalid: {err}"
        ));
    }
}

fn is_root_url_path(url: &Url) -> bool {
    matches!(url.path(), "" | "/")
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

pub fn request_timeout(config: &ConnectorConfig) -> Duration {
    Duration::from_secs(config.limits.request_timeout_seconds)
}

pub fn tls_handshake_timeout(config: &ConnectorConfig) -> Duration {
    Duration::from_secs(config.limits.tls_handshake_timeout_seconds)
}

pub fn http1_header_read_timeout(config: &ConnectorConfig) -> Duration {
    Duration::from_secs(config.limits.http1_header_read_timeout_seconds)
}

fn validate_identity_files(
    prefix: &str,
    identity: &IdentityFiles,
    usage: EkUsage,
    errors: &mut Vec<String>,
) {
    require_file(&format!("{prefix}.cert"), &identity.cert, errors);
    require_file(&format!("{prefix}.key"), &identity.key, errors);
    validate_private_key_permissions(prefix, &identity.key, errors);
    if identity.cert.exists() && identity.key.exists() {
        if let Err(err) = validate_leaf_certificate(&identity.cert, &identity.key, usage) {
            errors.push(format!("{prefix}: {err}"));
        }
    }
}

#[cfg(unix)]
fn validate_private_key_permissions(prefix: &str, path: &Path, errors: &mut Vec<String>) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.permissions().mode() & 0o077 != 0 {
        errors.push(format!(
            "{prefix}.key must not be readable or writable by group or others"
        ));
    }
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_prefix: &str, _path: &Path, _errors: &mut Vec<String>) {}

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

fn default_request_timeout_seconds() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECONDS
}

fn default_tls_handshake_timeout_seconds() -> u64 {
    DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECONDS
}

fn default_http1_header_read_timeout_seconds() -> u64 {
    DEFAULT_HTTP1_HEADER_READ_TIMEOUT_SECONDS
}

fn default_max_concurrent_requests() -> usize {
    DEFAULT_MAX_CONCURRENT_REQUESTS
}

fn default_max_concurrent_connections() -> usize {
    DEFAULT_MAX_CONCURRENT_CONNECTIONS
}

fn default_max_requests_per_identity_per_minute() -> u32 {
    DEFAULT_MAX_REQUESTS_PER_IDENTITY_PER_MINUTE
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

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
