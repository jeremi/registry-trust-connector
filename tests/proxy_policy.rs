use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use registry_trust_connector::config::{
    upstream_timeout, ClientServerConfig, ClientTrustConfig, ConnectorConfig, DefaultsConfig,
    LimitsConfig, ListenConfig, RouteConfig, TrustAnchorConfig, UpstreamConfig,
};
use registry_trust_connector::proxy::{router, ProxyState};
use registry_trust_connector::tls::PeerCertificateChain;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tower::ServiceExt;
use url::Url;

const CLIENT_IDENTITY: &str = "spiffe://openspp.example/client/benefits-system";

#[tokio::test]
async fn default_request_header_policy_strips_sensitive_hop_by_hop_and_connector_headers() {
    let (upstream, mut received) =
        start_upstream(upstream_response(StatusCode::OK, vec![], "accepted")).await;
    let app = client_app(client_config(
        upstream,
        route("/local", "/upstream", false, false),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/local/records?limit=1")
                .header("authorization", "Bearer caller-secret")
                .header("cookie", "session=caller-secret")
                .header("connection", "x-hop-token, keep-alive")
                .header("keep-alive", "timeout=5")
                .header("te", "trailers")
                .header("x-hop-token", "strip-by-connection-token")
                .header("x-registry-connector-client-identity", "spoofed")
                .header("x-registry-connector-extra", "spoofed")
                .header("x-normal", "forwarded")
                .body(Body::from("payload"))
                .expect("request"),
        )
        .await
        .expect("proxy response");

    assert_eq!(response.status(), StatusCode::OK);
    let request = received.recv().await.expect("captured upstream request");
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path_and_query, "/upstream/records?limit=1");
    assert_eq!(request.body, Bytes::from_static(b"payload"));
    assert_header_absent(&request.headers, "authorization");
    assert_header_absent(&request.headers, "cookie");
    assert_header_absent(&request.headers, "connection");
    assert_header_absent(&request.headers, "keep-alive");
    assert_header_absent(&request.headers, "te");
    assert_header_absent(&request.headers, "x-hop-token");
    assert_header_absent(&request.headers, "x-registry-connector-client-identity");
    assert_header_absent(&request.headers, "x-registry-connector-extra");
    assert_eq!(header(&request.headers, "x-normal"), Some("forwarded"));
}

#[tokio::test]
async fn route_flags_allow_authorization_and_cookie_forwarding_when_enabled() {
    let (upstream, mut received) =
        start_upstream(upstream_response(StatusCode::OK, vec![], "accepted")).await;
    let app = client_app(client_config(
        upstream,
        route("/allow", "/upstream", true, true),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/allow/records")
                .header("authorization", "Bearer caller-token")
                .header("cookie", "session=caller-cookie")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("proxy response");

    assert_eq!(response.status(), StatusCode::OK);
    let request = received.recv().await.expect("captured upstream request");
    assert_eq!(
        header(&request.headers, "authorization"),
        Some("Bearer caller-token")
    );
    assert_eq!(
        header(&request.headers, "cookie"),
        Some("session=caller-cookie")
    );
}

#[tokio::test]
async fn response_policy_strips_hop_by_hop_headers_but_preserves_normal_response_parts() {
    let (upstream, _received) = start_upstream(upstream_response(
        StatusCode::CREATED,
        vec![
            ("connection", "x-upstream-hop, keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-authenticate", "Basic realm=\"upstream\""),
            ("x-upstream-hop", "strip-by-connection-token"),
            ("x-normal-response", "forwarded"),
        ],
        "created body",
    ))
    .await;
    let app = client_app(client_config(
        upstream,
        route("/local", "/upstream", false, false),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/local/records")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("proxy response");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_header_absent(response.headers(), "connection");
    assert_header_absent(response.headers(), "keep-alive");
    assert_header_absent(response.headers(), "proxy-authenticate");
    assert_header_absent(response.headers(), "x-upstream-hop");
    assert_eq!(
        header(response.headers(), "x-normal-response"),
        Some("forwarded")
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(body, Bytes::from_static(b"created body"));
}

#[tokio::test]
async fn upstream_unavailable_returns_problem_with_stable_code() {
    let upstream = unused_local_url().await;
    let app = client_app(client_config(
        upstream,
        route("/local", "/upstream", false, false),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/local/records")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("proxy response");

    assert_problem(
        response,
        StatusCode::BAD_GATEWAY,
        "connector.upstream_unavailable",
    )
    .await;
}

#[tokio::test]
async fn upstream_timeout_returns_problem_with_stable_code() {
    let upstream = start_slow_upstream(Duration::from_millis(1_500)).await;
    let mut config = client_config(upstream, route("/local", "/upstream", false, false));
    config.limits.upstream_timeout_seconds = 1;
    let app = client_app(config);

    let response = tokio::time::timeout(
        Duration::from_secs(3),
        app.oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/local/records")
                .body(Body::empty())
                .expect("request"),
        ),
    )
    .await
    .expect("proxy should respond after upstream timeout")
    .expect("proxy response");

    assert_problem(
        response,
        StatusCode::BAD_GATEWAY,
        "connector.upstream_unavailable",
    )
    .await;
}

#[tokio::test]
async fn missing_upstream_auth_env_returns_problem_with_stable_code() {
    std::env::remove_var("REGISTRY_PROXY_POLICY_MISSING_TOKEN");
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let config = Arc::new(server_config(&certs, unused_local_url().await));
    let app = router(ProxyState::server(config).expect("server proxy state"));

    let mut request = Request::builder()
        .method(Method::GET)
        .uri("/upstream/records")
        .body(Body::empty())
        .expect("request");
    request
        .extensions_mut()
        .insert(PeerCertificateChain(vec![certs.client_der]));

    let response = app.oneshot(request).await.expect("proxy response");

    assert_problem(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "connector.upstream_auth_missing",
    )
    .await;
}

#[tokio::test]
async fn empty_upstream_auth_env_returns_problem_with_stable_code() {
    std::env::set_var("REGISTRY_PROXY_POLICY_EMPTY_TOKEN", " ");
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let mut config = server_config(&certs, unused_local_url().await);
    config.routes[0].upstream_auth_header_env =
        Some("REGISTRY_PROXY_POLICY_EMPTY_TOKEN".to_string());
    let app = router(ProxyState::server(Arc::new(config)).expect("server proxy state"));

    let mut request = Request::builder()
        .method(Method::GET)
        .uri("/upstream/records")
        .body(Body::empty())
        .expect("request");
    request
        .extensions_mut()
        .insert(PeerCertificateChain(vec![certs.client_der]));

    let response = app.oneshot(request).await.expect("proxy response");

    assert_problem(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "connector.upstream_auth_missing",
    )
    .await;
}

async fn assert_problem(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        header(response.headers(), "content-type"),
        Some("application/problem+json")
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("problem JSON");
    assert_eq!(problem["status"], status.as_u16());
    assert_eq!(problem["code"], code);
    assert_eq!(problem["type"], format!("urn:registry:problem:{code}"));
}

fn client_app(config: ConnectorConfig) -> Router {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(upstream_timeout(&config))
        .build()
        .expect("reqwest client");
    router(ProxyState::client(Arc::new(config), client))
}

fn client_config(upstream: Url, route: RouteConfig) -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:0".parse().expect("listen")),
        server: Some(ClientServerConfig {
            url: upstream,
            trust_bundle: PathBuf::from("unused-ca.pem"),
        }),
        client_identity: None,
        defaults: DefaultsConfig::default(),
        limits: LimitsConfig::default(),
        routes: vec![route],
        server_identity: None,
        client_trust: None,
        upstream: None,
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: None,
    }
}

fn server_config(certs: &TestPki, upstream: Url) -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:0".parse().expect("listen")),
        server: None,
        client_identity: None,
        defaults: DefaultsConfig::default(),
        limits: LimitsConfig::default(),
        routes: vec![RouteConfig {
            id: "server-route".to_string(),
            methods: vec![Method::GET],
            local_prefix: None,
            upstream_prefix: Some("/upstream".to_string()),
            require_purpose: false,
            purpose_source: None,
            client_identity: Some(CLIENT_IDENTITY.to_string()),
            upstream_auth_header_env: Some("REGISTRY_PROXY_POLICY_MISSING_TOKEN".to_string()),
            forward_client_identity_header: false,
            purposes: Vec::new(),
            allow_forward_authorization: false,
            allow_forward_cookie: false,
        }],
        server_identity: None,
        client_trust: Some(ClientTrustConfig {
            allowed_identities: vec![CLIENT_IDENTITY.to_string()],
            trust_anchors: vec![TrustAnchorConfig {
                ca: certs.ca_cert.clone(),
                trust_domain: "openspp.example".to_string(),
                dns_identities: Vec::new(),
            }],
        }),
        upstream: Some(UpstreamConfig {
            base_url: upstream,
            default_auth_header_env: None,
            auth_header_name: "Authorization".to_string(),
            auth_header_scheme: "Bearer".to_string(),
        }),
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: None,
    }
}

fn route(
    local_prefix: &str,
    upstream_prefix: &str,
    allow_forward_authorization: bool,
    allow_forward_cookie: bool,
) -> RouteConfig {
    RouteConfig {
        id: local_prefix.trim_start_matches('/').to_string(),
        methods: vec![Method::GET, Method::POST],
        local_prefix: Some(local_prefix.to_string()),
        upstream_prefix: Some(upstream_prefix.to_string()),
        require_purpose: false,
        purpose_source: None,
        client_identity: None,
        upstream_auth_header_env: None,
        forward_client_identity_header: false,
        purposes: Vec::new(),
        allow_forward_authorization,
        allow_forward_cookie,
    }
}

#[derive(Clone)]
struct UpstreamResponse {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
}

fn upstream_response(
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: &'static str,
) -> UpstreamResponse {
    UpstreamResponse {
        status,
        headers,
        body,
    }
}

#[derive(Clone)]
struct UpstreamState {
    response: UpstreamResponse,
    requests: mpsc::Sender<CapturedRequest>,
}

#[derive(Debug)]
struct CapturedRequest {
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Bytes,
}

async fn start_upstream(response: UpstreamResponse) -> (Url, mpsc::Receiver<CapturedRequest>) {
    let (tx, rx) = mpsc::channel(4);
    let app = Router::new()
        .fallback(any(upstream_handler))
        .with_state(UpstreamState {
            response,
            requests: tx,
        });
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream serve");
    });
    (
        Url::parse(&format!("http://{addr}")).expect("upstream URL"),
        rx,
    )
}

async fn start_slow_upstream(delay: Duration) -> Url {
    let app = Router::new().fallback(any(move || async move {
        sleep(delay).await;
        Response::new(Body::from("too late"))
    }));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind slow upstream");
    let addr = listener.local_addr().expect("slow upstream addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("slow upstream serve");
    });
    Url::parse(&format!("http://{addr}")).expect("slow upstream URL")
}

async fn upstream_handler(
    State(state): State<UpstreamState>,
    request: Request<Body>,
) -> Response<Body> {
    let method = request.method().clone();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .expect("path and query");
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("request body");
    state
        .requests
        .send(CapturedRequest {
            method,
            path_and_query,
            headers,
            body,
        })
        .await
        .expect("capture request");

    let mut builder = Response::builder().status(state.response.status);
    for (name, value) in &state.response.headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Body::from(state.response.body))
        .expect("upstream response")
}

async fn unused_local_url() -> Url {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind unused port");
    let addr: SocketAddr = listener.local_addr().expect("unused addr");
    drop(listener);
    Url::parse(&format!("http://{addr}")).expect("unused URL")
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn assert_header_absent(headers: &HeaderMap, name: &str) {
    assert!(
        !headers.contains_key(name),
        "expected header {name:?} to be absent, got {:?}",
        header(headers, name)
    );
}

struct TestPki {
    ca_cert: PathBuf,
    client_der: rustls::pki_types::CertificateDer<'static>,
}

fn write_test_pki(root: &Path) -> TestPki {
    let (ca, ca_key) = test_ca();
    let (client_cert, _client_key) = signed_client_leaf(&ca, &ca_key);
    let ca_cert = root.join("ca.pem");
    fs::write(&ca_cert, ca.pem()).expect("write ca");

    TestPki {
        ca_cert,
        client_der: client_cert.der().clone(),
    }
}

fn test_ca() -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).expect("CA params");
    params
        .distinguished_name
        .push(DnType::CommonName, "Registry Connector Test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().expect("CA key");
    let cert = params.self_signed(&key).expect("CA cert");
    (cert, key)
}

fn signed_client_leaf(ca: &Certificate, ca_key: &KeyPair) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
    params
        .distinguished_name
        .push(DnType::CommonName, "benefits-system");
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .subject_alt_names
        .push(SanType::URI(CLIENT_IDENTITY.try_into().expect("URI SAN")));
    let key = KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, ca, ca_key).expect("leaf cert");
    (cert, key)
}
