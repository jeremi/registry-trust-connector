use std::env;
use std::sync::Arc;
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use registry_platform_httputil::OutboundClientBuilder;
use ulid::Ulid;
use url::Url;

use crate::config::{max_body_bytes, upstream_timeout, ConnectorConfig, Mode, PurposeSource};
use crate::errors::{ConnectorError, ConnectorProblem};
use crate::identity::PeerIdentity;
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
}

impl ProxyState {
    pub fn client(config: Arc<ConnectorConfig>, client: reqwest::Client) -> Self {
        Self {
            config,
            mode: Mode::Client,
            client,
            server_trust: None,
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
            config,
            mode: Mode::Server,
            client,
        })
    }
}

pub fn router(state: ProxyState) -> Router {
    Router::new()
        .fallback(any(proxy_handler))
        .with_state(Arc::new(state))
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
    let result = match state.mode {
        Mode::Client => {
            handle_client(state.clone(), request, &path, query.as_deref(), &request_id).await
        }
        Mode::Server => {
            handle_server(state.clone(), request, &path, query.as_deref(), &request_id).await
        }
    };
    let response = match result {
        Ok(response) => response,
        Err(problem) => problem.response(),
    };
    let status = response.status();
    tracing::info!(
        mode = ?state.mode,
        method = %method,
        path = %path,
        request_id = %request_id,
        status = status.as_u16(),
        status_class = status.as_u16() / 100,
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
    let mut headers = filtered_headers(
        &parts.headers,
        route_match.route.allow_forward_authorization,
        route_match.route.allow_forward_cookie,
    );
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
    send_upstream(&state.client, parts.method, url, headers, body).await
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
    authorize_server_purpose(&route_match, request.headers())?;
    let (parts, body) = request.into_parts();
    let body = read_limited_body(body, max_body_bytes(&state.config)).await?;
    let upstream = state
        .config
        .upstream
        .as_ref()
        .ok_or(ConnectorProblem::ConfigInvalid)?;
    let url = build_url(&upstream.base_url, &route_match.upstream_path, query)
        .map_err(|_| ConnectorProblem::ConfigInvalid)?;
    let mut headers = filtered_headers(&parts.headers, false, false);
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
        client_identity_hash = %crate::redaction::hash_for_log(&identity.value),
        client_cert_hash = %identity.fingerprint_sha256,
        request_id = %request_id,
        "server connector authorized request"
    );
    send_upstream(&state.client, parts.method, url, headers, body).await
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
) -> Result<(), ConnectorProblem> {
    if route_match.route.purposes.is_empty() && !route_match.route.require_purpose {
        return Ok(());
    }
    let purpose = headers
        .get(DATA_PURPOSE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConnectorProblem::PurposeRequired)?;
    if route_match
        .route
        .purposes
        .iter()
        .any(|allowed| allowed == purpose)
    {
        Ok(())
    } else {
        Err(ConnectorProblem::PurposeDenied)
    }
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
    let connection_tokens = connection_header_tokens(response.headers());
    for (name, value) in response.headers() {
        if should_forward_response_header(name, &connection_tokens) {
            builder = builder.header(name, value);
        }
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| ConnectorProblem::UpstreamUnavailable)?;
    builder
        .body(Body::from(body))
        .map_err(|_| ConnectorProblem::UpstreamUnavailable)
}

fn filtered_headers(headers: &HeaderMap, allow_auth: bool, allow_cookie: bool) -> HeaderMap {
    let mut out = HeaderMap::new();
    let connection_tokens = connection_header_tokens(headers);
    for (name, value) in headers {
        if is_hop_by_hop(name)
            || connection_tokens.iter().any(|token| token == name)
            || is_connector_private(name)
        {
            continue;
        }
        if !allow_auth && name == http::header::AUTHORIZATION {
            continue;
        }
        if !allow_cookie && name == http::header::COOKIE {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn should_forward_response_header(name: &HeaderName, connection_tokens: &[HeaderName]) -> bool {
    !is_hop_by_hop(name) && !connection_tokens.iter().any(|token| token == name)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
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

fn is_connector_private(name: &HeaderName) -> bool {
    name.as_str().starts_with("x-registry-connector-")
}

fn connection_header_tokens(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("").split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Ulid::new().to_string())
}

fn header_value(value: &str) -> Result<HeaderValue, ConnectorProblem> {
    HeaderValue::from_str(value).map_err(|_| ConnectorProblem::ConfigInvalid)
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
