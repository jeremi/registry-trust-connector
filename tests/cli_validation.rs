use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use registry_trust_connector::identity::{load_certs, load_private_key};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CLIENT_IDENTITY: &str = "spiffe://client.example/ns/default/sa/relay";

#[test]
fn validate_accepts_valid_client_config() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let config = temp.path().join("client.yaml");
    fs::write(&config, client_config_yaml(&certs)).expect("write client config");

    let output = validate_command(&config)
        .args(["--mode", "client"])
        .output()
        .expect("run validate command");

    assert_success(&output);
    assert_stdout_contains(
        &output,
        "registry-trust-connector config valid for Client mode",
    );
}

#[test]
fn validate_accepts_valid_server_config() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let config = temp.path().join("server.yaml");
    fs::write(&config, server_config_yaml(&certs, None)).expect("write server config");

    let output = validate_command(&config)
        .args(["--mode", "server"])
        .output()
        .expect("run validate command");

    assert_success(&output);
    assert_stdout_contains(
        &output,
        "registry-trust-connector config valid for Server mode",
    );
}

#[test]
fn validate_exits_nonzero_for_invalid_config() {
    let temp = TempDir::new().expect("temp dir");
    let config = temp.path().join("invalid.yaml");
    fs::write(
        &config,
        r#"
listen: "127.0.0.1:0"
routes: []
"#,
    )
    .expect("write invalid config");

    let output = validate_command(&config)
        .args(["--mode", "client"])
        .output()
        .expect("run validate command");

    assert_failure(&output);
    assert_stderr_contains(&output, "config failed validation");
    assert_stderr_contains(&output, "client config requires server");
    assert_stderr_contains(&output, "routes must not be empty");
}

#[test]
fn validate_require_env_exits_nonzero_when_required_env_is_missing() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let config = temp.path().join("server-require-env.yaml");
    fs::write(
        &config,
        server_config_yaml(&certs, Some("REGISTRY_TRUST_CONNECTOR_TEST_MISSING_ENV")),
    )
    .expect("write server config");

    let output = validate_command(&config)
        .args(["--mode", "server", "--require-env"])
        .env_remove("REGISTRY_TRUST_CONNECTOR_TEST_MISSING_ENV")
        .output()
        .expect("run validate command");

    assert_failure(&output);
    assert_stderr_contains(
        &output,
        "required upstream auth env var 'REGISTRY_TRUST_CONNECTOR_TEST_MISSING_ENV' is missing",
    );
}

#[test]
fn validate_require_env_exits_nonzero_when_required_env_is_empty() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let config = temp.path().join("server-require-env.yaml");
    fs::write(
        &config,
        server_config_yaml(&certs, Some("REGISTRY_TRUST_CONNECTOR_TEST_EMPTY_ENV")),
    )
    .expect("write server config");

    let output = validate_command(&config)
        .args(["--mode", "server", "--require-env"])
        .env("REGISTRY_TRUST_CONNECTOR_TEST_EMPTY_ENV", " ")
        .output()
        .expect("run validate command");

    assert_failure(&output);
    assert_stderr_contains(
        &output,
        "required upstream auth env var 'REGISTRY_TRUST_CONNECTOR_TEST_EMPTY_ENV' is empty",
    );
}

#[test]
fn validate_require_env_exits_nonzero_when_required_env_is_invalid_header_value() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let config = temp.path().join("server-require-env.yaml");
    fs::write(
        &config,
        server_config_yaml(
            &certs,
            Some("REGISTRY_TRUST_CONNECTOR_TEST_INVALID_HEADER_VALUE"),
        ),
    )
    .expect("write server config");

    let output = validate_command(&config)
        .args(["--mode", "server", "--require-env"])
        .env(
            "REGISTRY_TRUST_CONNECTOR_TEST_INVALID_HEADER_VALUE",
            "Bearer token\nwith-newline",
        )
        .output()
        .expect("run validate command");

    assert_failure(&output);
    assert_stderr_contains(
        &output,
        "required upstream auth env var 'REGISTRY_TRUST_CONNECTOR_TEST_INVALID_HEADER_VALUE' contains invalid characters for an HTTP header value",
    );
}

#[tokio::test]
async fn server_closes_slow_http1_headers_after_configured_timeout() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let listen = unused_loopback_addr();
    let config = temp.path().join("server-slow-headers.yaml");
    let yaml = server_config_yaml(&certs, None)
        .replacen(
            r#"listen: "127.0.0.1:0""#,
            &format!(r#"listen: "{listen}""#),
            1,
        )
        .replacen(
            "audit:",
            "limits:\n  http1_header_read_timeout_seconds: 1\n  tls_handshake_timeout_seconds: 2\naudit:",
            1,
        );
    fs::write(&config, yaml).expect("write server config");

    let child = server_command(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start server command");
    let mut server = ChildGuard(child);
    wait_for_tcp_listener(listen).await;

    let mut tls = mtls_stream(&certs, listen).await;
    tls.write_all(b"GET /v1/packages HTTP/1.1\r\nHost: server.example.test\r\n")
        .await
        .expect("write partial request");

    let mut buf = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf))
        .await
        .expect("server should close slow header connection within timeout");

    assert!(
        matches!(read, Ok(0) | Err(_)),
        "expected closed or reset connection after slow header timeout, got {read:?}"
    );
    server.kill();
}

#[tokio::test]
async fn server_disables_http1_keep_alive_after_response() {
    let temp = TempDir::new().expect("temp dir");
    let certs = write_test_pki(temp.path());
    let listen = unused_loopback_addr();
    let config = temp.path().join("server-no-keep-alive.yaml");
    let yaml = server_config_yaml(&certs, None).replacen(
        r#"listen: "127.0.0.1:0""#,
        &format!(r#"listen: "{listen}""#),
        1,
    );
    fs::write(&config, yaml).expect("write server config");

    let child = server_command(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start server command");
    let mut server = ChildGuard(child);
    wait_for_tcp_listener(listen).await;

    let mut tls = mtls_stream(&certs, listen).await;
    tls.write_all(
        b"GET /v1/packages HTTP/1.1\r\nHost: server.example.test\r\nConnection: keep-alive\r\n\r\n",
    )
    .await
    .expect("write complete request");
    let response = read_until_connection_closes(&mut tls).await;

    assert!(
        response.starts_with(b"HTTP/1.1 403 Forbidden"),
        "expected policy denial response before close, got:\n{}",
        String::from_utf8_lossy(&response)
    );
    server.kill();
}

fn validate_command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-trust-connector"));
    command.args(["validate", "--config"]);
    command.arg(config);
    command
}

fn server_command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-trust-connector"));
    command.args(["server", "--config"]);
    command.arg(config);
    command
}

fn unused_loopback_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

async fn wait_for_tcp_listener(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("server did not start listening on {addr}: {err}"),
        }
    }
}

async fn mtls_stream(
    certs: &TestPki,
    addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&certs.ca_cert).expect("load CA cert") {
        roots.add(cert).expect("add CA root");
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            load_certs(&certs.client_cert).expect("load client cert"),
            load_private_key(&certs.client_key).expect("load client key"),
        )
        .expect("client TLS config");
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(addr).await.expect("connect to server");
    let server_name = ServerName::try_from("server.example.test")
        .expect("server name")
        .to_owned();
    connector
        .connect(server_name, stream)
        .await
        .expect("mTLS handshake")
}

async fn read_until_connection_closes(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Vec<u8> {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut buf = [0_u8; 512];
        loop {
            let n = stream.read(&mut buf).await.expect("read response");
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("server should close HTTP/1 connection after one response");
    response
}

struct ChildGuard(Child);

impl ChildGuard {
    fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "expected failure, got success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_stdout_contains(output: &Output, needle: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(needle),
        "expected stdout to contain {needle:?}, got:\n{stdout}"
    );
}

fn assert_stderr_contains(output: &Output, needle: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(needle),
        "expected stderr to contain {needle:?}, got:\n{stderr}"
    );
}

#[derive(Debug)]
struct TestPki {
    ca_cert: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

fn write_test_pki(root: &Path) -> TestPki {
    let (ca, ca_key) = test_ca();
    let (server_cert, server_key) = signed_leaf(
        &ca,
        &ca_key,
        "server",
        vec!["server.example.test".to_string()],
        vec![ExtendedKeyUsagePurpose::ServerAuth],
    );
    let (client_cert, client_key) = signed_leaf(
        &ca,
        &ca_key,
        "client",
        Vec::new(),
        vec![ExtendedKeyUsagePurpose::ClientAuth],
    );

    let ca_cert_path = root.join("ca.pem");
    let server_cert_path = root.join("server.pem");
    let server_key_path = root.join("server.key");
    let client_cert_path = root.join("client.pem");
    let client_key_path = root.join("client.key");

    fs::write(&ca_cert_path, ca.pem()).expect("write ca");
    fs::write(&server_cert_path, server_cert.pem()).expect("write server cert");
    fs::write(&server_key_path, server_key.serialize_pem()).expect("write server key");
    fs::write(&client_cert_path, client_cert.pem()).expect("write client cert");
    fs::write(&client_key_path, client_key.serialize_pem()).expect("write client key");
    secure_key_file(&server_key_path);
    secure_key_file(&client_key_path);

    TestPki {
        ca_cert: ca_cert_path,
        server_cert: server_cert_path,
        server_key: server_key_path,
        client_cert: client_cert_path,
        client_key: client_key_path,
    }
}

#[cfg(unix)]
fn secure_key_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("key permissions");
}

#[cfg(not(unix))]
fn secure_key_file(_path: &Path) {}

fn test_ca() -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).expect("CA params");
    params
        .distinguished_name
        .push(DnType::CommonName, "Registry Connector CLI Test CA");
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
    let key = KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, ca, ca_key).expect("leaf cert");
    (cert, key)
}

fn client_config_yaml(certs: &TestPki) -> String {
    format!(
        r#"
listen: "127.0.0.1:0"
server:
  url: "https://server.example.test"
  trust_bundle: "{}"
client_identity:
  cert: "{}"
  key: "{}"
audit:
  allow_unkeyed_hashing: true
routes:
  - id: "packages"
    methods: ["GET"]
    local_prefix: "/relay/packages"
    upstream_prefix: "/v1/packages"
"#,
        certs.ca_cert.display(),
        certs.client_cert.display(),
        certs.client_key.display()
    )
}

fn server_config_yaml(certs: &TestPki, auth_env: Option<&str>) -> String {
    let default_auth_header_env = auth_env
        .map(|value| format!(r#"  default_auth_header_env: "{value}""#))
        .unwrap_or_default();

    format!(
        r#"
listen: "127.0.0.1:0"
server_identity:
  cert: "{}"
  key: "{}"
client_trust:
  allowed_identities:
    - "{CLIENT_IDENTITY}"
  trust_anchors:
    - ca: "{}"
      trust_domain: "client.example"
upstream:
  base_url: "http://127.0.0.1:9000"
{default_auth_header_env}
audit:
  allow_unkeyed_hashing: true
routes:
  - id: "packages"
    methods: ["GET"]
    upstream_prefix: "/v1/packages"
    client_identity: "{CLIENT_IDENTITY}"
"#,
        certs.server_cert.display(),
        certs.server_key.display(),
        certs.ca_cert.display()
    )
}
