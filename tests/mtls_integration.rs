use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use registry_trust_connector::config::{
    AuditConfig, ClientServerConfig, ClientTrustConfig, ConnectorConfig, DefaultsConfig,
    IdentityFiles, LimitsConfig, ListenConfig, PurposeSource, RouteConfig, TrustAnchorConfig,
    UpstreamConfig,
};
use registry_trust_connector::proxy::{router, ProxyState};
use registry_trust_connector::tls::{self, PeerCertificateChain};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use url::Url;

const CLIENT_IDENTITY: &str = "spiffe://openspp.example/client/benefits-system";
const DNS_CLIENT_IDENTITY: &str = "benefits-client.example.test";
const PURPOSE: &str = "https://purpose.example.gov/service-delivery";
const UPSTREAM_TOKEN: &str = "relay-test-token";

#[tokio::test]
async fn client_and_server_connectors_forward_over_mtls_and_deny_missing_purpose() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    std::env::set_var("TEST_RELAY_CONNECTOR_TOKEN", UPSTREAM_TOKEN);

    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream = start_mock_upstream(Arc::clone(&upstream_hits)).await;

    let server_config = Arc::new(server_config(&certs, &upstream));
    let server_addr = start_server_connector(Arc::clone(&server_config)).await;

    let client_config = Arc::new(client_config(&certs, server_addr));
    let mtls_client = tls::reqwest_mtls_client(
        client_config.client_identity.as_ref().unwrap(),
        &client_config.server.as_ref().unwrap().trust_bundle,
        registry_trust_connector::config::upstream_timeout(&client_config),
    )
    .expect("client mTLS reqwest client");
    let direct_mtls = mtls_client.clone();
    let wrong_domain_mtls = tls::reqwest_mtls_client(
        &IdentityFiles {
            cert: certs.wrong_domain_client_cert.clone(),
            key: certs.wrong_domain_client_key.clone(),
        },
        &certs.ca_cert,
        registry_trust_connector::config::upstream_timeout(&client_config),
    )
    .expect("wrong-domain mTLS reqwest client");
    let client_addr = start_plain_connector(router(ProxyState::client(
        Arc::clone(&client_config),
        mtls_client,
    )))
    .await;

    let local = reqwest::Client::new();
    let ok = local
        .get(format!(
            "http://{client_addr}/relay/social/records?limit=1&subject=redacted"
        ))
        .header("data-purpose", PURPOSE)
        .header("x-registry-connector-client-identity", "spoofed-client")
        .header(
            "authorization",
            "Bearer caller-secret-that-must-not-forward",
        )
        .send()
        .await
        .expect("successful local client request");
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(
        ok.text().await.expect("body"),
        "upstream ok: /v1/datasets/social_registry/records?limit=1&subject=redacted"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let static_purpose = local
        .get(format!("http://{client_addr}/relay/static/records"))
        .header(
            "data-purpose",
            "https://purpose.example.gov/attempted-override",
        )
        .send()
        .await
        .expect("static-purpose local client request");
    assert_eq!(static_purpose.status(), StatusCode::OK);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "static purpose request should reach upstream with configured purpose"
    );

    let denied = local
        .get(format!("http://{client_addr}/relay/social/records"))
        .send()
        .await
        .expect("denied local client request");
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "missing-purpose request must not reach upstream"
    );

    let route_denied = local
        .get(format!("http://{client_addr}/relay/not-allowed/records"))
        .header("data-purpose", PURPOSE)
        .send()
        .await
        .expect("route-denied local client request");
    assert_eq!(route_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "disallowed route must not reach upstream"
    );

    let too_large = local
        .post(format!("http://{client_addr}/relay/social/records"))
        .header("data-purpose", PURPOSE)
        .body("x".repeat(300))
        .send()
        .await
        .expect("oversized local client request");
    assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "oversized body must not reach upstream"
    );

    let server_leg_too_large = direct_mtls
        .post(format!(
            "https://localhost:{}/v1/datasets/social_registry/records",
            server_addr.port()
        ))
        .header("data-purpose", PURPOSE)
        .body("x".repeat(300))
        .send()
        .await
        .expect("direct oversized server connector request");
    assert_eq!(server_leg_too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "server-leg oversized body must not reach upstream"
    );

    let wrong_domain = wrong_domain_mtls
        .get(format!(
            "https://localhost:{}/v1/datasets/social_registry/records",
            server_addr.port()
        ))
        .header("data-purpose", PURPOSE)
        .send()
        .await
        .expect("wrong-domain direct server connector request");
    assert_eq!(wrong_domain.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "wrong CA minted right SPIFFE domain must not reach upstream"
    );
}

#[tokio::test]
async fn dns_san_identity_fallback_requires_explicit_enablement_and_allowlist() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    std::env::set_var("TEST_RELAY_CONNECTOR_TOKEN", UPSTREAM_TOKEN);

    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream = start_mock_upstream(Arc::clone(&upstream_hits)).await;
    let dns_client = tls::reqwest_mtls_client(
        &IdentityFiles {
            cert: certs.dns_client_cert.clone(),
            key: certs.dns_client_key.clone(),
        },
        &certs.ca_cert,
        std::time::Duration::from_secs(5),
    )
    .expect("DNS SAN mTLS client");
    let wrong_anchor_dns_client = tls::reqwest_mtls_client(
        &IdentityFiles {
            cert: certs.wrong_domain_dns_client_cert.clone(),
            key: certs.wrong_domain_dns_client_key.clone(),
        },
        &certs.ca_cert,
        std::time::Duration::from_secs(5),
    )
    .expect("wrong-anchor DNS SAN mTLS client");

    let mut denied_config = server_config(&certs, &upstream);
    denied_config.allow_dns_san_identity = false;
    denied_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .allowed_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    denied_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors[0]
        .dns_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    denied_config.routes[0].client_identity = Some(DNS_CLIENT_IDENTITY.to_string());
    let denied_addr = start_server_connector(Arc::new(denied_config)).await;
    let denied = dns_client
        .get(format!(
            "https://localhost:{}/v1/datasets/social_registry/records",
            denied_addr.port()
        ))
        .header("data-purpose", PURPOSE)
        .send()
        .await
        .expect("DNS fallback disabled request");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    let mut allowed_config = server_config(&certs, &upstream);
    allowed_config.allow_dns_san_identity = true;
    allowed_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .allowed_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    allowed_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors[0]
        .dns_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    allowed_config.routes[0].client_identity = Some(DNS_CLIENT_IDENTITY.to_string());
    let allowed_addr = start_server_connector(Arc::new(allowed_config)).await;
    let allowed = dns_client
        .get(format!(
            "https://localhost:{}/v1/datasets/social_registry/records",
            allowed_addr.port()
        ))
        .header("data-purpose", PURPOSE)
        .send()
        .await
        .expect("DNS fallback allowed request");
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let mut not_allowlisted_config = server_config(&certs, &upstream);
    not_allowlisted_config.allow_dns_san_identity = true;
    not_allowlisted_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors[0]
        .dns_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    not_allowlisted_config.routes[0].client_identity = Some(DNS_CLIENT_IDENTITY.to_string());
    let not_allowlisted_addr = start_server_connector(Arc::new(not_allowlisted_config)).await;
    let not_allowlisted = dns_client
        .get(format!(
            "https://localhost:{}/v1/datasets/social_registry/records",
            not_allowlisted_addr.port()
        ))
        .header("data-purpose", PURPOSE)
        .send()
        .await
        .expect("DNS fallback not allowlisted request");
    assert_eq!(not_allowlisted.status(), StatusCode::FORBIDDEN);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let mut wrong_anchor_config = server_config(&certs, &upstream);
    wrong_anchor_config.allow_dns_san_identity = true;
    wrong_anchor_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .allowed_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    wrong_anchor_config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors[0]
        .dns_identities = vec![DNS_CLIENT_IDENTITY.to_string()];
    wrong_anchor_config.routes[0].client_identity = Some(DNS_CLIENT_IDENTITY.to_string());
    let wrong_anchor_addr = start_server_connector(Arc::new(wrong_anchor_config)).await;
    let wrong_anchor = wrong_anchor_dns_client
        .get(format!(
            "https://localhost:{}/v1/datasets/social_registry/records",
            wrong_anchor_addr.port()
        ))
        .header("data-purpose", PURPOSE)
        .send()
        .await
        .expect("wrong-anchor DNS fallback request");
    assert_eq!(wrong_anchor.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        1,
        "wrong CA minted allowlisted DNS identity must not reach upstream"
    );
}

async fn start_mock_upstream(hits: Arc<AtomicUsize>) -> Url {
    let app = Router::new()
        .fallback(any(mock_upstream_handler))
        .with_state(hits);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock upstream serve");
    });
    Url::parse(&format!("http://{addr}")).expect("upstream URL")
}

async fn mock_upstream_handler(
    State(hits): State<Arc<AtomicUsize>>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response<Body> {
    hits.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer relay-test-token")
    );
    let forwarded_identity = headers
        .get("x-registry-connector-client-identity")
        .and_then(|value| value.to_str().ok());
    assert!(
        matches!(
            forwarded_identity,
            Some(CLIENT_IDENTITY) | Some(DNS_CLIENT_IDENTITY)
        ),
        "unexpected forwarded identity: {forwarded_identity:?}"
    );
    assert_eq!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some(PURPOSE)
    );
    assert_ne!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer caller-secret-that-must-not-forward")
    );
    Response::new(Body::from(format!("upstream ok: {}", request.uri())))
}

async fn start_plain_connector(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind client connector");
    let addr = listener.local_addr().expect("client connector addr");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("client connector serve");
    });
    addr
}

async fn start_server_connector(config: Arc<ConnectorConfig>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server connector");
    let addr = listener.local_addr().expect("server connector addr");
    let tls_config = tls::server_config(&config).expect("server TLS config");
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let app = router(ProxyState::server(config).expect("server proxy state"));
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept server connector");
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let tls_stream = acceptor.accept(stream).await.expect("TLS accept");
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
                        let response = app.oneshot(req).await.expect("connector response");
                        Ok::<Response<Body>, Infallible>(response)
                    }
                });
                HyperBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                    .expect("serve TLS connection");
            });
        }
    });
    addr
}

fn client_config(certs: &TestPki, server_addr: SocketAddr) -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:0".parse().expect("listen")),
        server: Some(ClientServerConfig {
            url: Url::parse(&format!("https://localhost:{}", server_addr.port()))
                .expect("server url"),
            trust_bundle: certs.ca_cert.clone(),
        }),
        client_identity: Some(IdentityFiles {
            cert: certs.client_cert.clone(),
            key: certs.client_key.clone(),
        }),
        defaults: DefaultsConfig {
            data_purpose: Some(PURPOSE.to_string()),
        },
        audit: AuditConfig {
            hash_secret_env: None,
            allow_unkeyed_hashing: true,
        },
        limits: LimitsConfig {
            max_body_bytes: 256,
            ..LimitsConfig::default()
        },
        routes: vec![
            RouteConfig {
                id: "social-registry-read".to_string(),
                methods: vec![http::Method::GET, http::Method::POST],
                local_prefix: Some("/relay/social/".to_string()),
                upstream_prefix: Some("/v1/datasets/social_registry/".to_string()),
                require_purpose: true,
                purpose_source: Some(PurposeSource::ClientProvided),
                client_identity: None,
                upstream_auth_header_env: None,
                forward_client_identity_header: false,
                purposes: Vec::new(),
                allow_forward_authorization: false,
                allow_forward_cookie: false,
            },
            RouteConfig {
                id: "social-registry-static-read".to_string(),
                methods: vec![http::Method::GET],
                local_prefix: Some("/relay/static/".to_string()),
                upstream_prefix: Some("/v1/datasets/social_registry/".to_string()),
                require_purpose: true,
                purpose_source: Some(PurposeSource::StaticRouteDefault),
                client_identity: None,
                upstream_auth_header_env: None,
                forward_client_identity_header: false,
                purposes: Vec::new(),
                allow_forward_authorization: false,
                allow_forward_cookie: false,
            },
        ],
        server_identity: None,
        client_trust: None,
        upstream: None,
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: Some("test-client".to_string()),
    }
}

fn server_config(certs: &TestPki, upstream: &Url) -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:0".parse().expect("listen")),
        server: None,
        client_identity: None,
        defaults: DefaultsConfig::default(),
        audit: AuditConfig {
            hash_secret_env: None,
            allow_unkeyed_hashing: true,
        },
        limits: LimitsConfig {
            max_body_bytes: 256,
            ..LimitsConfig::default()
        },
        routes: vec![RouteConfig {
            id: "social-registry-read".to_string(),
            methods: vec![http::Method::GET, http::Method::POST],
            local_prefix: None,
            upstream_prefix: Some("/v1/datasets/social_registry/".to_string()),
            require_purpose: true,
            purpose_source: None,
            client_identity: Some(CLIENT_IDENTITY.to_string()),
            upstream_auth_header_env: Some("TEST_RELAY_CONNECTOR_TOKEN".to_string()),
            forward_client_identity_header: true,
            purposes: vec![PURPOSE.to_string()],
            allow_forward_authorization: false,
            allow_forward_cookie: false,
        }],
        server_identity: Some(IdentityFiles {
            cert: certs.server_cert.clone(),
            key: certs.server_key.clone(),
        }),
        client_trust: Some(ClientTrustConfig {
            allowed_identities: vec![CLIENT_IDENTITY.to_string()],
            trust_anchors: vec![
                TrustAnchorConfig {
                    ca: certs.ca_cert.clone(),
                    trust_domain: "openspp.example".to_string(),
                    dns_identities: Vec::new(),
                },
                TrustAnchorConfig {
                    ca: certs.wrong_domain_ca_cert.clone(),
                    trust_domain: "health.example".to_string(),
                    dns_identities: Vec::new(),
                },
            ],
            denied_certificate_fingerprints_sha256: Vec::new(),
        }),
        upstream: Some(UpstreamConfig {
            base_url: upstream.clone(),
            default_auth_header_env: None,
            auth_header_name: "Authorization".to_string(),
            auth_header_scheme: "Bearer".to_string(),
        }),
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: Some("test-server".to_string()),
    }
}

#[derive(Debug)]
struct TestPki {
    ca_cert: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
    dns_client_cert: PathBuf,
    dns_client_key: PathBuf,
    wrong_domain_ca_cert: PathBuf,
    wrong_domain_client_cert: PathBuf,
    wrong_domain_client_key: PathBuf,
    wrong_domain_dns_client_cert: PathBuf,
    wrong_domain_dns_client_key: PathBuf,
}

fn write_test_pki(root: &Path) -> TestPki {
    let (ca, ca_key) = test_ca();
    let (wrong_domain_ca, wrong_domain_ca_key) = test_ca();
    let (server_cert, server_key) = signed_leaf(
        &ca,
        &ca_key,
        "server",
        vec!["localhost".into()],
        vec![ExtendedKeyUsagePurpose::ServerAuth],
    );
    let (client_cert, client_key) = signed_leaf(
        &ca,
        &ca_key,
        "benefits-system",
        Vec::new(),
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );
    let (wrong_domain_client_cert, wrong_domain_client_key) = signed_leaf(
        &wrong_domain_ca,
        &wrong_domain_ca_key,
        "benefits-system",
        Vec::new(),
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );
    let (wrong_domain_dns_client_cert, wrong_domain_dns_client_key) = signed_leaf(
        &wrong_domain_ca,
        &wrong_domain_ca_key,
        "wrong-domain-dns-benefits-system",
        vec![DNS_CLIENT_IDENTITY.to_string()],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );
    let (dns_client_cert, dns_client_key) = signed_leaf(
        &ca,
        &ca_key,
        "dns-benefits-system",
        vec![DNS_CLIENT_IDENTITY.to_string()],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );

    let ca_cert = root.join("ca.pem");
    let wrong_domain_ca_cert = root.join("wrong-domain-ca.pem");
    let server_cert_path = root.join("server.pem");
    let server_key_path = root.join("server.key");
    let client_cert_path = root.join("client.pem");
    let client_key_path = root.join("client.key");
    let dns_client_cert_path = root.join("dns-client.pem");
    let dns_client_key_path = root.join("dns-client.key");
    let wrong_domain_client_cert_path = root.join("wrong-domain-client.pem");
    let wrong_domain_client_key_path = root.join("wrong-domain-client.key");
    let wrong_domain_dns_client_cert_path = root.join("wrong-domain-dns-client.pem");
    let wrong_domain_dns_client_key_path = root.join("wrong-domain-dns-client.key");

    fs::write(&ca_cert, ca.pem()).expect("write ca");
    fs::write(&wrong_domain_ca_cert, wrong_domain_ca.pem()).expect("write wrong-domain ca");
    fs::write(&server_cert_path, server_cert.pem()).expect("write server cert");
    fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
    fs::write(&client_cert_path, client_cert.pem()).expect("write client cert");
    fs::write(&client_key_path, client_key.serialize_pem()).expect("write client key");
    fs::write(&dns_client_cert_path, dns_client_cert.pem()).expect("write DNS client cert");
    fs::write(&dns_client_key_path, dns_client_key.serialize_pem()).expect("write DNS client key");
    fs::write(
        &wrong_domain_client_cert_path,
        wrong_domain_client_cert.pem(),
    )
    .expect("write wrong-domain client cert");
    fs::write(
        &wrong_domain_client_key_path,
        wrong_domain_client_key.serialize_pem(),
    )
    .expect("write wrong-domain client key");
    fs::write(
        &wrong_domain_dns_client_cert_path,
        wrong_domain_dns_client_cert.pem(),
    )
    .expect("write wrong-domain DNS client cert");
    fs::write(
        &wrong_domain_dns_client_key_path,
        wrong_domain_dns_client_key.serialize_pem(),
    )
    .expect("write wrong-domain DNS client key");

    TestPki {
        ca_cert,
        server_cert: server_cert_path,
        server_key: server_key_path,
        client_cert: client_cert_path,
        client_key: client_key_path,
        dns_client_cert: dns_client_cert_path,
        dns_client_key: dns_client_key_path,
        wrong_domain_ca_cert,
        wrong_domain_client_cert: wrong_domain_client_cert_path,
        wrong_domain_client_key: wrong_domain_client_key_path,
        wrong_domain_dns_client_cert: wrong_domain_dns_client_cert_path,
        wrong_domain_dns_client_key: wrong_domain_dns_client_key_path,
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

fn signed_leaf(
    ca: &Certificate,
    ca_key: &KeyPair,
    common_name: &str,
    dns_names: Vec<String>,
    usages: Vec<ExtendedKeyUsagePurpose>,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(dns_names).expect("leaf params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = usages;
    if common_name == "benefits-system" {
        params
            .subject_alt_names
            .push(SanType::URI(CLIENT_IDENTITY.try_into().expect("URI SAN")));
    }
    let key = KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, ca, ca_key).expect("leaf cert");
    (cert, key)
}
