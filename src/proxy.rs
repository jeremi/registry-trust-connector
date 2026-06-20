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
    if route_match.route.purposes.is_empty() && !route_match.route.require_purpose {
        return Ok(purpose);
    }
    let purpose = purpose.ok_or(ConnectorProblem::PurposeRequired)?;
    let purpose_constraints = if route_match.route.purposes.is_empty() {
        vec![Vec::new()]
    } else {
        vec![route_match.route.purposes.clone()]
    };
    let context = PdpRequestContext {
        purpose: purpose.clone(),
        legal_basis_ref: None,
        consent_ref: None,
        asserted_assurance: None,
        jurisdiction: None,
        requester_identity: None,
        subject_ref: None,
        relationship: None,
        on_behalf_of: None,
        requested_fact: None,
        requested_disclosure: None,
        requested_credential_format: None,
        source_binding: None,
        route_identity: None,
        checked_scopes: BTreeSet::new(),
        source_observed_at_unix_seconds: None,
        source_observed_age_seconds: None,
    };
    let policy = PdpPolicyInput {
        policy_id: format!("trust-connector.route.{}", route_match.route.id),
        policy_hash: route_purpose_policy_hash(route_match),
        ecosystem_binding_id: None,
        ecosystem_binding_version: None,
        rule_ids: vec![format!("route-purpose:{}", route_match.route.id)],
        rule_ids_by_gate: Default::default(),
        permit_unconstrained: false,
        required_context: BTreeSet::new(),
        odrl_constraint_terms: Vec::new(),
        purpose_constraints,
        permitted_jurisdictions: Vec::new(),
        allowed_assurance: Vec::new(),
        minimum_assurance: None,
        max_source_age_seconds: None,
        require_legal_basis: false,
        require_consent: false,
        allowed_legal_basis_refs: Vec::new(),
        allowed_consent_refs: Vec::new(),
        redaction_fields: Default::default(),
        allowed_relationships: Vec::new(),
        relationship_purpose_constraints: Vec::new(),
        allowed_requested_facts: Vec::new(),
        allowed_requested_disclosures: Vec::new(),
        allowed_credential_formats: Vec::new(),
        allowed_source_bindings: Vec::new(),
        allowed_route_identities: Vec::new(),
        required_checked_scopes: BTreeSet::new(),
        unsupported_odrl_terms: Vec::new(),
    };
    match pdp_decide(&context, &policy) {
        PdpDecision::Permit(_) | PdpDecision::PermitWithRedaction { .. } => Ok(Some(purpose)),
        PdpDecision::Deny { .. } => Err(ConnectorProblem::PurposeDenied),
    }
}

fn route_purpose_policy_hash(route_match: &RouteMatch<'_>) -> String {
    let mut material = format!(
        "route_id={};require_purpose={};purposes=",
        route_match.route.id, route_match.route.require_purpose
    );
    for purpose in &route_match.route.purposes {
        material.push_str(purpose);
        material.push('\n');
    }
    format!("sha256:{}", sha256_hex(material.as_bytes()))
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
