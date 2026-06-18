use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use registry_trust_connector::config::{
    AuditConfig, ClientServerConfig, ConnectorConfig, DefaultsConfig, IdentityFiles, LimitsConfig,
    ListenConfig, RouteConfig,
};
use registry_trust_connector::proxy::{router, ProxyState};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;
use url::Url;

#[tokio::test(flavor = "current_thread")]
async fn completion_log_emits_audit_dimensions_without_raw_path() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_writer(SharedLogWriter(Arc::clone(&logs)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let app = router(ProxyState::client(
        Arc::new(client_config()),
        reqwest::Client::new(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/unconfigured/sensitive-subject?token=secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("proxy response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("problem body");
    assert!(
        String::from_utf8_lossy(&body).contains("connector.route_denied"),
        "expected route denial problem body, got {}",
        String::from_utf8_lossy(&body)
    );
    let logs = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf8 logs");
    assert!(logs.contains(r#""outcome":"denied""#), "{logs}");
    assert!(
        logs.contains(r#""problem_code":"connector.route_denied""#),
        "{logs}"
    );
    assert!(logs.contains(r#""denial_stage":"route""#), "{logs}");
    assert!(logs.contains(r#""denial_reason":"route_denied""#), "{logs}");
    assert!(logs.contains(r#""query_present":true"#), "{logs}");
    assert!(logs.contains(r#""path_len":"#), "{logs}");
    assert!(!logs.contains("sensitive-subject"), "{logs}");
    assert!(!logs.contains("token=secret"), "{logs}");
    assert!(!logs.contains(r#""path":"/unconfigured"#), "{logs}");
}

fn client_config() -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:0".parse::<SocketAddr>().expect("listen")),
        server: Some(ClientServerConfig {
            url: Url::parse("https://server.example.test").expect("server URL"),
            trust_bundle: PathBuf::from("unused-ca.pem"),
        }),
        client_identity: Some(IdentityFiles {
            cert: PathBuf::from("unused-client.pem"),
            key: PathBuf::from("unused-client.key"),
        }),
        defaults: DefaultsConfig::default(),
        audit: AuditConfig {
            hash_secret_env: None,
            allow_unkeyed_hashing: true,
        },
        limits: LimitsConfig::default(),
        routes: vec![RouteConfig {
            id: "configured-route".to_string(),
            methods: vec![Method::GET],
            local_prefix: Some("/configured".to_string()),
            upstream_prefix: Some("/upstream".to_string()),
            require_purpose: false,
            purpose_source: None,
            client_identity: None,
            upstream_auth_header_env: None,
            forward_client_identity_header: false,
            purposes: Vec::new(),
            governed_policy: None,
            allow_forward_authorization: false,
            allow_forward_cookie: false,
        }],
        server_identity: None,
        client_trust: None,
        upstream: None,
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: None,
    }
}

#[derive(Clone)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

struct SharedLogWriteGuard(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = SharedLogWriteGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriteGuard(Arc::clone(&self.0))
    }
}

impl Write for SharedLogWriteGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("logs").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
