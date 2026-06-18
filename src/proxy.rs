use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use registry_platform_audit::AuditKeyHasher;
use registry_platform_httputil::{
    filter_proxy_request_headers, filter_proxy_response_headers, read_bounded,
    OutboundClientBuilder, ProxyHeaderPolicy,
};
use registry_platform_pdp::{
    decide as pdp_decide, Decision as PdpDecision, EvidenceRequestContext as PdpRequestContext,
    PolicyInput as PdpPolicyInput,
};
use tower::limit::ConcurrencyLimitLayer;
use ulid::Ulid;
use url::Url;

use crate::config::{
    max_body_bytes, request_timeout, upstream_timeout, ConnectorConfig, Mode, PurposeSource,
};
use crate::errors::{ConnectorError, ConnectorProblem};
use crate::identity::{sha256_hex, PeerIdentity};
use crate::routing::{find_client_route, find_server_route, RouteMatch};
use crate::tls::{PeerCertificateChain, ServerTrustPolicy};

const DATA_PURPOSE: &str = "data-purpose";
const REQUEST_ID: &str = "x-request-id";
const CONNECTOR_ID: &str = "x-registry-connector-id";
const CONNECTOR_VERSION: &str = "x-registry-connector-version";
const CONNECTOR_CLIENT_IDENTITY: &str = "x-registry-connector-client-identity";

#[derive(Clone)]
pub struct ProxyState {
    config: Arc<ConnectorConfig>,
    mode: Mode,
    client: reqwest::Client,
    server_trust: Option<Arc<ServerTrustPolicy>>,
    audit_hasher: Option<AuditKeyHasher>,
    rate_limiter: Arc<RequestRateLimiter>,
}

impl ProxyState {
    pub fn client(config: Arc<ConnectorConfig>, client: reqwest::Client) -> Self {
        Self {
            config,
            mode: Mode::Client,
            client,
            server_trust: None,
            audit_hasher: None,
            rate_limiter: Arc::new(RequestRateLimiter::default()),
        }
    }

    pub fn server(config: Arc<ConnectorConfig>) -> Result<Self, ConnectorError> {
        let timeout = upstream_timeout(&config);
        let client = OutboundClientBuilder::new()
            .timeout(timeout)
            .user_agent("registry-trust-connector/0.1")
            .build();
        Ok(Self {
            server_trust: Some(Arc::new(ServerTrustPolicy::from_config(&config)?)),
            audit_hasher: Some(crate::redaction::audit_key_hasher(&config)?),
            config,
            mode: Mode::Server,
            client,
            rate_limiter: Arc::new(RequestRateLimiter::default()),
        })
    }
}

pub fn router(state: ProxyState) -> Router {
    let max_concurrent_requests = state.config.limits.max_concurrent_requests;
    Router::new()
        .fallback(any(proxy_handler))
        .with_state(Arc::new(state))
        .layer(ConcurrencyLimitLayer::new(max_concurrent_requests))
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(str::to_string);
    let request_id = request_id(request.headers());
    let timeout = request_timeout(&state.config);
    let result = tokio::time::timeout(timeout, async {
        match state.mode {
            Mode::Client => {
                handle_client(state.clone(), request, &path, query.as_deref(), &request_id).await
            }
            Mode::Server => {
                handle_server(state.clone(), request, &path, query.as_deref(), &request_id).await
            }
        }
    })
    .await
    .unwrap_or(Err(ConnectorProblem::RequestTimeout));
    let problem = result.as_ref().err().copied();
    let problem_code = problem.map(|problem| problem.code());
    let outcome = problem
        .map(ConnectorProblem::audit_outcome)
        .unwrap_or("forwarded");
    let denial_stage = problem
        .and_then(ConnectorProblem::denial_stage)
        .unwrap_or("");
    let denial_reason = problem
        .and_then(ConnectorProblem::denial_reason)
        .unwrap_or("");
    let response = match result {
        Ok(response) => response,
        Err(problem) => problem.response(),
    };
    let status = response.status();
    tracing::info!(
        mode = ?state.mode,
        method = %method,
        path_len = path.len(),
        query_present = query.is_some(),
        request_id = %request_id,
        status = status.as_u16(),
        status_class = status.as_u16() / 100,
        outcome = outcome,
        problem_code = problem_code.unwrap_or(""),
        denial_stage = denial_stage,
        denial_reason = denial_reason,
        latency_ms = started.elapsed().as_millis() as u64,
        "connector request completed"
    );
    response
}

async fn handle_client(
    state: Arc<ProxyState>,
    request: Request<Body>,
    path: &str,
    query: Option<&str>,
    request_id: &str,
) -> Result<Response<Body>, ConnectorProblem> {
    let route_match = find_client_route(&state.config.routes, request.method(), path)
        .map_err(|_| ConnectorProblem::RouteDenied)?;
    let purpose = resolve_client_purpose(&state.config, &route_match, request.headers())?;
    let (parts, body) = request.into_parts();
    let body = read_limited_body(body, max_body_bytes(&state.config)).await?;
    let server = state
        .config
        .server
        .as_ref()
        .ok_or(ConnectorProblem::ConfigInvalid)?;
    let url = build_url(&server.url, &route_match.upstream_path, query)
        .map_err(|_| ConnectorProblem::ConfigInvalid)?;
    let mut headers = filtered_headers(&parts.headers, &route_match);
    headers.insert(REQUEST_ID, header_value(request_id)?);
    headers.insert(
        CONNECTOR_VERSION,
        HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    if let Some(connector_id) = state.config.connector_id.as_deref() {
        headers.insert(CONNECTOR_ID, header_value(connector_id)?);
    }
    if let Some(purpose) = purpose {
        headers.insert(DATA_PURPOSE, header_value(&purpose)?);
    }
    send_upstream(
        &state.client,
        parts.method,
        url,
        headers,
        body,
        max_body_bytes(&state.config),
    )
    .await
}

async fn handle_server(
    state: Arc<ProxyState>,
    request: Request<Body>,
    path: &str,
    query: Option<&str>,
    request_id: &str,
) -> Result<Response<Body>, ConnectorProblem> {
    let chain = request
        .extensions()
        .get::<PeerCertificateChain>()
        .cloned()
        .ok_or(ConnectorProblem::ClientIdentityMissing)?;
    let trust = state
        .server_trust
        .as_ref()
        .ok_or(ConnectorProblem::ConfigInvalid)?;
    let identity = trust
        .verify_peer(&chain)
        .map_err(|_| ConnectorProblem::ClientIdentityDenied)?;
    let allowed = state
        .config
        .client_trust
        .as_ref()
        .map(|trust| {
            trust
                .allowed_identities
                .iter()
                .any(|allowed| allowed == &identity.value)
        })
        .unwrap_or(false);
    if !allowed {
        return Err(ConnectorProblem::ClientIdentityDenied);
    }
    let route_match = find_server_route(
        &state.config.routes,
        request.method(),
        path,
        &identity.value,
    )
    .map_err(|_| ConnectorProblem::RouteDenied)?;
    let authorized_purpose = authorize_server_purpose(&route_match, request.headers())?;
    state.rate_limiter.check(
        &identity.value,
        &route_match.route.id,
        state.config.limits.max_requests_per_identity_per_minute,
    )?;
    let (parts, body) = request.into_parts();
    let body = read_limited_body(body, max_body_bytes(&state.config)).await?;
    let upstream = state
        .config
        .upstream
        .as_ref()
        .ok_or(ConnectorProblem::ConfigInvalid)?;
    let url = build_url(&upstream.base_url, &route_match.upstream_path, query)
        .map_err(|_| ConnectorProblem::ConfigInvalid)?;
    let mut headers = filter_proxy_request_headers(
        &parts.headers,
        &ProxyHeaderPolicy::strict().strip_private_prefix("x-registry-connector-"),
    );
    headers.remove(DATA_PURPOSE);
    if let Some(purpose) = authorized_purpose {
        headers.insert(DATA_PURPOSE, header_value(&purpose)?);
    }
    headers.insert(REQUEST_ID, header_value(request_id)?);
    let auth_value = upstream_auth_header(&state.config, &route_match)?;
    headers.insert(
        HeaderName::from_bytes(upstream.auth_header_name.as_bytes())
            .map_err(|_| ConnectorProblem::ConfigInvalid)?,
        auth_value,
    );
    if route_match.route.forward_client_identity_header {
        headers.insert(CONNECTOR_CLIENT_IDENTITY, header_value(&identity.value)?);
    }
    tracing::info!(
        route_id = %route_match.route.id,
        client_identity_hash = %crate::redaction::identity_hash_for_log(
            state.audit_hasher.as_ref().ok_or(ConnectorProblem::ConfigInvalid)?,
            &identity.value,
        ),
        client_cert_ref_hash = %crate::redaction::certificate_hash_for_log(
            state.audit_hasher.as_ref().ok_or(ConnectorProblem::ConfigInvalid)?,
            &identity.fingerprint_sha256,
        ),
        request_id = %request_id,
        "server connector authorized request"
    );
    send_upstream(
        &state.client,
        parts.method,
        url,
        headers,
        body,
        max_body_bytes(&state.config),
    )
    .await
}

fn resolve_client_purpose(
    config: &ConnectorConfig,
    route_match: &RouteMatch<'_>,
    headers: &HeaderMap,
) -> Result<Option<String>, ConnectorProblem> {
    if route_match.route.require_purpose {
        match route_match
            .route
            .purpose_source
            .unwrap_or(PurposeSource::DeniedMissing)
        {
            PurposeSource::StaticRouteDefault => config
                .defaults
                .data_purpose
                .clone()
                .filter(|value| !value.trim().is_empty())
                .map(Some)
                .ok_or(ConnectorProblem::PurposeRequired),
            PurposeSource::ClientProvided => headers
                .get(DATA_PURPOSE)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.trim().is_empty())
                .map(|value| Some(value.to_string()))
                .ok_or(ConnectorProblem::PurposeRequired),
            PurposeSource::DeniedMissing => Err(ConnectorProblem::PurposeRequired),
        }
    } else {
        Ok(headers
            .get(DATA_PURPOSE)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned))
    }
}

fn authorize_server_purpose(
    route_match: &RouteMatch<'_>,
    headers: &HeaderMap,
) -> Result<Option<String>, ConnectorProblem> {
    let purpose = single_data_purpose(headers)?;
    let governed_policy = route_match.route.governed_policy.as_ref();
    if route_match.route.purposes.is_empty()
        && !route_match.route.require_purpose
        && governed_policy.is_none()
    {
        return Ok(purpose);
    }
    let purpose = purpose.ok_or(ConnectorProblem::PurposeRequired)?;
    let mut purpose_constraints = if route_match.route.purposes.is_empty() {
        Vec::new()
    } else {
        vec![route_match.route.purposes.clone()]
    };
    if let Some(configured_purposes) = governed_policy
        .map(|policy| policy.permitted_purposes.clone())
        .filter(|purposes| !purposes.is_empty())
    {
        purpose_constraints.push(configured_purposes);
    }
    if route_match.route.require_purpose && purpose_constraints.is_empty() {
        return Err(ConnectorProblem::PurposeDenied);
    }
    let context = PdpRequestContext {
        purpose: purpose.clone(),
        legal_basis_ref: governed_policy
            .and_then(|policy| policy.trusted_context.legal_basis_ref.clone()),
        consent_ref: governed_policy.and_then(|policy| policy.trusted_context.consent_ref.clone()),
        asserted_assurance: governed_policy
            .and_then(|policy| policy.trusted_context.asserted_assurance.clone()),
        jurisdiction: governed_policy
            .and_then(|policy| policy.trusted_context.jurisdiction.clone()),
        source_observed_age_seconds: governed_policy
            .and_then(|policy| policy.trusted_context.source_observed_age_seconds),
    };
    let policy = PdpPolicyInput {
        policy_id: format!("trust-connector.route.{}", route_match.route.id),
        policy_hash: route_purpose_policy_hash(route_match),
        rule_ids: vec![format!("route-purpose:{}", route_match.route.id)],
        purpose_constraints,
        permitted_jurisdictions: governed_policy
            .map(|policy| policy.permitted_jurisdictions.clone())
            .unwrap_or_default(),
        allowed_assurance: governed_policy
            .map(|policy| policy.allowed_assurance.clone())
            .unwrap_or_default(),
        minimum_assurance: governed_policy.and_then(|policy| policy.minimum_assurance.clone()),
        max_source_age_seconds: governed_policy.and_then(|policy| policy.max_source_age_seconds),
        require_legal_basis: governed_policy.is_some_and(|policy| policy.require_legal_basis),
        require_consent: governed_policy.is_some_and(|policy| policy.require_consent),
        redaction_fields: governed_policy
            .map(|policy| policy.redaction_fields.iter().cloned().collect())
            .unwrap_or_default(),
        unsupported_odrl_terms: Vec::new(),
    };
    match pdp_decide(&context, &policy) {
        PdpDecision::Permit(_) | PdpDecision::PermitWithRedaction { .. } => Ok(Some(purpose)),
        PdpDecision::Deny { audit, .. } => {
            tracing::info!(
                route_id = %route_match.route.id,
                pdp_policy_id = %audit.policy_id,
                pdp_policy_hash = %audit.policy_hash,
                pdp_evaluated_rule_ids = ?audit.evaluated_rule_ids,
                "server connector denied purpose by pdp"
            );
            Err(ConnectorProblem::PurposeDenied)
        }
    }
}

fn route_purpose_policy_hash(route_match: &RouteMatch<'_>) -> String {
    let route = route_match.route;
    let mut material = String::new();
    push_hash_field(&mut material, "schema", "route-purpose-policy-v3");
    push_hash_field(&mut material, "route_id", &route.id);
    push_hash_field(
        &mut material,
        "client_identity",
        route.client_identity.as_deref().unwrap_or(""),
    );
    push_hash_field(
        &mut material,
        "local_prefix",
        route.local_prefix.as_deref().unwrap_or(""),
    );
    push_hash_field(
        &mut material,
        "upstream_prefix",
        route.upstream_prefix.as_deref().unwrap_or(""),
    );
    push_hash_field(
        &mut material,
        "require_purpose",
        if route.require_purpose {
            "true"
        } else {
            "false"
        },
    );
    for method in route
        .methods
        .iter()
        .map(Method::as_str)
        .collect::<BTreeSet<_>>()
    {
        push_hash_field(&mut material, "method", method);
    }
    for purpose in route.purposes.iter().collect::<BTreeSet<_>>() {
        push_hash_field(&mut material, "purpose", purpose);
    }
    if let Some(policy) = route.governed_policy.as_ref() {
        push_hash_field(&mut material, "governed_policy", "true");
        push_hash_field(
            &mut material,
            "governed_minimum_assurance",
            policy.minimum_assurance.as_deref().unwrap_or(""),
        );
        push_hash_field(
            &mut material,
            "governed_max_source_age_seconds",
            &policy
                .max_source_age_seconds
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        push_hash_field(
            &mut material,
            "governed_require_legal_basis",
            if policy.require_legal_basis {
                "true"
            } else {
                "false"
            },
        );
        push_hash_field(
            &mut material,
            "governed_require_consent",
            if policy.require_consent {
                "true"
            } else {
                "false"
            },
        );
        for purpose in policy.permitted_purposes.iter().collect::<BTreeSet<_>>() {
            push_hash_field(&mut material, "governed_permitted_purpose", purpose);
        }
        for jurisdiction in policy
            .permitted_jurisdictions
            .iter()
            .collect::<BTreeSet<_>>()
        {
            push_hash_field(
                &mut material,
                "governed_permitted_jurisdiction",
                jurisdiction,
            );
        }
        for assurance in policy.allowed_assurance.iter().collect::<BTreeSet<_>>() {
            push_hash_field(&mut material, "governed_allowed_assurance", assurance);
        }
        for field in policy.redaction_fields.iter().collect::<BTreeSet<_>>() {
            push_hash_field(&mut material, "governed_redaction_field", field);
        }
        push_hash_field(
            &mut material,
            "trusted_jurisdiction",
            policy.trusted_context.jurisdiction.as_deref().unwrap_or(""),
        );
        push_hash_field(
            &mut material,
            "trusted_asserted_assurance",
            policy
                .trusted_context
                .asserted_assurance
                .as_deref()
                .unwrap_or(""),
        );
        push_hash_field(
            &mut material,
            "trusted_legal_basis_ref",
            policy
                .trusted_context
                .legal_basis_ref
                .as_deref()
                .unwrap_or(""),
        );
        push_hash_field(
            &mut material,
            "trusted_consent_ref",
            policy.trusted_context.consent_ref.as_deref().unwrap_or(""),
        );
        push_hash_field(
            &mut material,
            "trusted_source_observed_age_seconds",
            &policy
                .trusted_context
                .source_observed_age_seconds
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
    }
    route.policy_hash.get_or_compute(material, |material| {
        format!("sha256:{}", sha256_hex(material.as_bytes()))
    })
}

fn push_hash_field(material: &mut String, name: &str, value: &str) {
    material.push_str(name);
    material.push(':');
    material.push_str(&value.len().to_string());
    material.push(':');
    material.push_str(value);
    material.push('\n');
}

fn single_data_purpose(headers: &HeaderMap) -> Result<Option<String>, ConnectorProblem> {
    let mut values = headers.get_all(DATA_PURPOSE).iter().filter_map(|value| {
        value
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    });
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ConnectorProblem::PurposeDenied);
    }
    Ok(Some(first))
}

fn upstream_auth_header(
    config: &ConnectorConfig,
    route_match: &RouteMatch<'_>,
) -> Result<HeaderValue, ConnectorProblem> {
    let upstream = config
        .upstream
        .as_ref()
        .ok_or(ConnectorProblem::ConfigInvalid)?;
    let env_var = route_match
        .route
        .upstream_auth_header_env
        .as_deref()
        .or(upstream.default_auth_header_env.as_deref())
        .ok_or(ConnectorProblem::UpstreamAuthMissing)?;
    let secret = env::var(env_var)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConnectorProblem::UpstreamAuthMissing)?;
    let value = if upstream.auth_header_scheme.trim().is_empty() {
        secret
    } else {
        format!("{} {}", upstream.auth_header_scheme, secret)
    };
    header_value(&value)
}

async fn read_limited_body(body: Body, max_bytes: usize) -> Result<Bytes, ConnectorProblem> {
    to_bytes(body, max_bytes)
        .await
        .map_err(|_| ConnectorProblem::BodyTooLarge)
}

async fn send_upstream(
    client: &reqwest::Client,
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Bytes,
    max_body_bytes: usize,
) -> Result<Response<Body>, ConnectorProblem> {
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|_| ConnectorProblem::ConfigInvalid)?;
    let mut request = client.request(reqwest_method, url).body(body);
    for (name, value) in headers {
        if let Some(name) = name {
            request = request.header(name.as_str(), value.as_bytes());
        }
    }
    let response = request
        .send()
        .await
        .map_err(|_| ConnectorProblem::UpstreamUnavailable)?;
    let status = StatusCode::from_u16(response.status().as_u16())
        .map_err(|_| ConnectorProblem::UpstreamUnavailable)?;
    let mut builder = Response::builder().status(status);
    let response_headers = filter_proxy_response_headers(response.headers());
    for (name, value) in &response_headers {
        builder = builder.header(name, value);
    }
    let body = read_bounded(response, max_body_bytes as u64)
        .await
        .map_err(|_| ConnectorProblem::UpstreamUnavailable)?;
    builder
        .body(Body::from(body))
        .map_err(|_| ConnectorProblem::UpstreamUnavailable)
}

fn filtered_headers(headers: &HeaderMap, route_match: &RouteMatch<'_>) -> HeaderMap {
    let policy = ProxyHeaderPolicy::strict()
        .allow_authorization(route_match.route.allow_forward_authorization)
        .allow_cookie(route_match.route.allow_forward_cookie)
        .strip_private_prefix("x-registry-connector-");
    filter_proxy_request_headers(headers, &policy)
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_request_id(value))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Ulid::new().to_string())
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn header_value(value: &str) -> Result<HeaderValue, ConnectorProblem> {
    HeaderValue::from_str(value).map_err(|_| ConnectorProblem::ConfigInvalid)
}

#[derive(Default)]
struct RequestRateLimiter {
    windows: Mutex<BTreeMap<String, RateWindow>>,
}

struct RateWindow {
    started: Instant,
    count: u32,
}

impl RequestRateLimiter {
    fn check(&self, identity: &str, route_id: &str, limit: u32) -> Result<(), ConnectorProblem> {
        let now = Instant::now();
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| ConnectorProblem::ConfigInvalid)?;
        let key = format!("{identity}\0{route_id}");
        let window = windows.entry(key).or_insert(RateWindow {
            started: now,
            count: 0,
        });
        if now.duration_since(window.started).as_secs() >= 60 {
            window.started = now;
            window.count = 0;
        }
        if window.count >= limit {
            return Err(ConnectorProblem::RateLimited);
        }
        window.count += 1;
        Ok(())
    }
}

fn build_url(base: &Url, path: &str, query: Option<&str>) -> Result<Url, url::ParseError> {
    let mut raw = format!("{}{}", &base[..url::Position::BeforePath], path);
    if let Some(query) = query {
        raw.push('?');
        raw.push_str(query);
    }
    Url::parse(&raw)
}

#[allow(dead_code)]
fn _identity_marker(_: &PeerIdentity) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GovernedRoutePolicyConfig, GovernedTrustedContextConfig, RouteConfig};

    #[test]
    fn denied_server_purpose_uses_stable_pdp_audit_provenance() {
        let route = test_route();
        let route_match = RouteMatch {
            route: &route,
            upstream_path: "/relay/packages/records".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(DATA_PURPOSE, HeaderValue::from_static("marketing"));

        assert_eq!(
            authorize_server_purpose(&route_match, &headers),
            Err(ConnectorProblem::PurposeDenied)
        );
        assert_eq!(
            route_purpose_policy_hash(&route_match),
            route_purpose_policy_hash(&route_match)
        );
        assert!(route_purpose_policy_hash(&route_match).starts_with("sha256:"));
    }

    #[test]
    fn governed_route_policy_denies_when_required_trusted_context_is_missing() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                require_legal_basis: true,
                ..GovernedRoutePolicyConfig::default()
            }),
            ..test_route()
        };
        let route_match = RouteMatch {
            route: &route,
            upstream_path: "/relay/packages/records".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(DATA_PURPOSE, HeaderValue::from_static("operations"));

        assert_eq!(
            authorize_server_purpose(&route_match, &headers),
            Err(ConnectorProblem::PurposeDenied)
        );
    }

    #[test]
    fn required_purpose_denies_when_no_allowed_purpose_is_configured() {
        let route = RouteConfig {
            purposes: Vec::new(),
            governed_policy: Some(GovernedRoutePolicyConfig::default()),
            ..test_route()
        };
        let route_match = RouteMatch {
            route: &route,
            upstream_path: "/relay/packages/records".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(DATA_PURPOSE, HeaderValue::from_static("operations"));

        assert_eq!(
            authorize_server_purpose(&route_match, &headers),
            Err(ConnectorProblem::PurposeDenied)
        );
    }

    #[test]
    fn governed_route_policy_permits_when_trusted_context_satisfies_policy() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                permitted_jurisdictions: vec!["ZZ".to_string()],
                allowed_assurance: vec!["substantial".to_string()],
                require_legal_basis: true,
                require_consent: true,
                trusted_context: GovernedTrustedContextConfig {
                    jurisdiction: Some("ZZ".to_string()),
                    asserted_assurance: Some("substantial".to_string()),
                    legal_basis_ref: Some("law:test".to_string()),
                    consent_ref: Some("consent:test".to_string()),
                    source_observed_age_seconds: None,
                },
                ..GovernedRoutePolicyConfig::default()
            }),
            ..test_route()
        };
        let route_match = RouteMatch {
            route: &route,
            upstream_path: "/relay/packages/records".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(DATA_PURPOSE, HeaderValue::from_static("operations"));

        assert_eq!(
            authorize_server_purpose(&route_match, &headers),
            Ok(Some("operations".to_string()))
        );
    }

    #[test]
    fn route_purpose_policy_hash_changes_for_client_identity() {
        let route = test_route();
        let baseline = hash_for_route(&route);
        let changed = hash_for_route(&RouteConfig {
            client_identity: Some("spiffe://openspp.example/client-b".to_string()),
            ..route
        });

        assert_ne!(baseline, changed);
    }

    #[test]
    fn route_purpose_policy_hash_changes_for_method_set() {
        let route = test_route();
        let baseline = hash_for_route(&route);
        let changed = hash_for_route(&RouteConfig {
            methods: vec![Method::GET],
            ..route
        });

        assert_ne!(baseline, changed);
    }

    #[test]
    fn route_purpose_policy_hash_changes_for_upstream_route_material() {
        let route = test_route();
        let baseline = hash_for_route(&route);
        let changed = hash_for_route(&RouteConfig {
            upstream_prefix: Some("/relay/search".to_string()),
            ..route
        });

        assert_ne!(baseline, changed);
    }

    #[test]
    fn route_purpose_policy_hash_changes_for_governed_policy_material() {
        let route = test_route();
        let baseline = hash_for_route(&route);
        let changed = hash_for_route(&RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_jurisdictions: vec!["ZZ".to_string()],
                require_legal_basis: true,
                trusted_context: GovernedTrustedContextConfig {
                    jurisdiction: Some("ZZ".to_string()),
                    legal_basis_ref: Some("law:test".to_string()),
                    ..GovernedTrustedContextConfig::default()
                },
                ..GovernedRoutePolicyConfig::default()
            }),
            ..route
        });

        assert_ne!(baseline, changed);
    }

    #[test]
    fn route_purpose_policy_hash_is_stable_for_set_ordering() {
        let route = test_route();
        let reordered = RouteConfig {
            methods: vec![Method::POST, Method::GET],
            purposes: vec!["eligibility".to_string(), "operations".to_string()],
            ..test_route()
        };

        assert_eq!(hash_for_route(&route), hash_for_route(&reordered));
    }

    fn hash_for_route(route: &RouteConfig) -> String {
        route_purpose_policy_hash(&RouteMatch {
            route,
            upstream_path: "/relay/packages/records".to_string(),
        })
    }

    fn test_route() -> RouteConfig {
        RouteConfig {
            id: "server-route".to_string(),
            methods: vec![Method::GET, Method::POST],
            local_prefix: None,
            upstream_prefix: Some("/relay/packages".to_string()),
            require_purpose: true,
            purpose_source: None,
            client_identity: Some("spiffe://openspp.example/client-a".to_string()),
            upstream_auth_header_env: Some("REGISTRY_PROXY_POLICY_TOKEN".to_string()),
            forward_client_identity_header: false,
            purposes: vec!["operations".to_string(), "eligibility".to_string()],
            governed_policy: None,
            allow_forward_authorization: false,
            allow_forward_cookie: false,
            policy_hash: Default::default(),
        }
    }
}
