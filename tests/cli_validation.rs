use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use tempfile::TempDir;

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

fn validate_command(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-trust-connector"));
    command.args(["validate", "--config"]);
    command.arg(config);
    command
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

    TestPki {
        ca_cert: ca_cert_path,
        server_cert: server_cert_path,
        server_key: server_key_path,
        client_cert: client_cert_path,
        client_key: client_key_path,
    }
}

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
