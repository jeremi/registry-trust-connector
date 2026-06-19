use std::path::PathBuf;

use http::Method;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use registry_trust_connector::config::{
    validate_config, AuditConfig, ClientServerConfig, ClientTrustConfig, ConnectorConfig,
    DefaultsConfig, GovernedRoutePolicyConfig, GovernedTrustedContextConfig, IdentityFiles,
    LimitsConfig, ListenConfig, Mode, RouteConfig, TrustAnchorConfig,
    TrustContextEntitlementConfig, UpstreamConfig,
};
use registry_trust_connector::identity::extract_peer_identity_from_der;
use tempfile::TempDir;
use url::Url;

fn identity(cert: &str, key: &str) -> IdentityFiles {
    IdentityFiles {
        cert: PathBuf::from(cert),
        key: PathBuf::from(key),
    }
}

fn client_route(id: &str) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        methods: vec![Method::GET],
        local_prefix: Some("/local".to_string()),
        upstream_prefix: Some("/upstream".to_string()),
        require_purpose: false,
        purpose_source: None,
        client_identity: None,
        client_identities: Vec::new(),
        upstream_auth_header_env: None,
        forward_client_identity_header: false,
        purposes: Vec::new(),
        governed_policy: None,
        allow_forward_authorization: false,
        allow_forward_cookie: false,
        policy_hash: Default::default(),
    }
}

fn server_route(id: &str, client_identity: Option<&str>) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        methods: vec![Method::GET],
        local_prefix: None,
        upstream_prefix: Some("/upstream".to_string()),
        require_purpose: false,
        purpose_source: None,
        client_identity: client_identity.map(str::to_string),
        client_identities: Vec::new(),
        upstream_auth_header_env: None,
        forward_client_identity_header: false,
        purposes: Vec::new(),
        governed_policy: None,
        allow_forward_authorization: false,
        allow_forward_cookie: false,
        policy_hash: Default::default(),
    }
}

fn client_config() -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:8080".parse().expect("socket address")),
        server: Some(ClientServerConfig {
            url: Url::parse("https://server.example.test").expect("server url"),
            trust_bundle: PathBuf::from("missing-server-ca.pem"),
        }),
        client_identity: Some(identity("missing-client.crt", "missing-client.key")),
        defaults: DefaultsConfig::default(),
        audit: AuditConfig {
            hash_secret_env: None,
            allow_unkeyed_hashing: true,
        },
        limits: LimitsConfig::default(),
        routes: vec![client_route("packages")],
        server_identity: None,
        client_trust: None,
        upstream: None,
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: None,
    }
}

fn server_config() -> ConnectorConfig {
    ConnectorConfig {
        listen: ListenConfig::Tcp("127.0.0.1:8443".parse().expect("socket address")),
        server: None,
        client_identity: None,
        defaults: DefaultsConfig::default(),
        audit: AuditConfig {
            hash_secret_env: None,
            allow_unkeyed_hashing: true,
        },
        limits: LimitsConfig::default(),
        routes: vec![server_route("packages", None)],
        server_identity: Some(identity("missing-server.crt", "missing-server.key")),
        client_trust: Some(ClientTrustConfig {
            allowed_identities: vec!["spiffe://client.example/ns/default/sa/relay".to_string()],
            trust_anchors: vec![TrustAnchorConfig {
                ca: PathBuf::from("missing-other-domain-ca.pem"),
                trust_domain: "other.example".to_string(),
                dns_identities: Vec::new(),
            }],
            denied_certificate_fingerprints_sha256: Vec::new(),
            trust_context_entitlements: Vec::new(),
        }),
        upstream: Some(UpstreamConfig {
            base_url: Url::parse("http://127.0.0.1:9000").expect("upstream url"),
            default_auth_header_env: None,
            auth_header_name: "Authorization".to_string(),
            auth_header_scheme: "Bearer".to_string(),
        }),
        allow_non_loopback_client_listen: false,
        allow_dns_san_identity: false,
        connector_id: None,
    }
}

fn validation_errors(config: &ConnectorConfig, mode: Mode) -> Vec<String> {
    validate_config(config, mode, false).expect_err("config should be rejected")
}

fn assert_error_contains(errors: &[String], needle: &str) {
    assert!(
        errors.iter().any(|err| err.contains(needle)),
        "expected an error containing {needle:?}, got {errors:#?}"
    );
}

fn assert_error_absent(errors: &[String], needle: &str) {
    assert!(
        !errors.iter().any(|err| err.contains(needle)),
        "expected no error containing {needle:?}, got {errors:#?}"
    );
}

#[test]
fn audit_hash_policy_requires_secret_env_or_explicit_unkeyed_dev_mode() {
    let mut config = client_config();
    config.audit = AuditConfig::default();

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "audit.hash_secret_env is required unless audit.allow_unkeyed_hashing is true",
    );
}

#[test]
fn require_env_validates_audit_hash_secret_env() {
    let env_var = "REGISTRY_TRUST_CONNECTOR_TEST_AUDIT_HASH_SECRET_MISSING";
    std::env::remove_var(env_var);
    let mut config = server_config();
    config.audit = AuditConfig {
        hash_secret_env: Some(env_var.to_string()),
        allow_unkeyed_hashing: false,
    };

    let errors = validate_config(&config, Mode::Server, true).expect_err("config rejected");

    assert_error_contains(&errors, "required audit hash env var");
    assert_error_contains(&errors, "is invalid");
}

#[test]
fn require_env_rejects_short_audit_hash_secret() {
    let env_var = "REGISTRY_TRUST_CONNECTOR_TEST_AUDIT_HASH_SECRET_SHORT";
    std::env::set_var(env_var, "too-short");
    let mut config = server_config();
    config.audit = AuditConfig {
        hash_secret_env: Some(env_var.to_string()),
        allow_unkeyed_hashing: false,
    };

    let errors = validate_config(&config, Mode::Server, true).expect_err("config rejected");

    assert_error_contains(&errors, "required audit hash env var");
    assert_error_contains(&errors, "at least 32 bytes");
    std::env::remove_var(env_var);
}

#[test]
fn require_env_rejects_invalid_upstream_auth_header_value() {
    let env_var = "REGISTRY_TRUST_CONNECTOR_TEST_INVALID_HEADER_VALUE";
    std::env::set_var(env_var, "Bearer token\nwith-newline");
    let mut config = server_config();
    config
        .upstream
        .as_mut()
        .expect("upstream")
        .default_auth_header_env = Some(env_var.to_string());

    let errors = validate_config(&config, Mode::Server, true).expect_err("config rejected");

    assert_error_contains(
        &errors,
        "contains invalid characters for an HTTP header value",
    );
    std::env::remove_var(env_var);
}

#[test]
fn client_config_rejects_missing_required_sections() {
    let mut config = client_config();
    config.client_identity = None;

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(&errors, "client config requires client_identity");
}

#[test]
fn client_config_rejects_plaintext_server_url() {
    let mut config = client_config();
    config.server.as_mut().unwrap().url =
        Url::parse("http://server.example.test").expect("server url");

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(&errors, "client server.url must use https");
}

#[test]
fn config_rejects_base_urls_with_paths() {
    let mut client = client_config();
    client.server.as_mut().unwrap().url =
        Url::parse("https://server.example.test/private").expect("server url");
    let client_errors = validation_errors(&client, Mode::Client);
    assert_error_contains(&client_errors, "client server.url must not include a path");

    let mut server = server_config();
    server.upstream.as_mut().unwrap().base_url =
        Url::parse("http://127.0.0.1:9000/private").expect("upstream url");
    let server_errors = validation_errors(&server, Mode::Server);
    assert_error_contains(&server_errors, "upstream.base_url must not include a path");
}

#[test]
fn server_config_rejects_missing_required_sections() {
    let mut missing_server_identity = server_config();
    missing_server_identity.server_identity = None;
    let errors = validation_errors(&missing_server_identity, Mode::Server);
    assert_error_contains(&errors, "server config requires server_identity");

    let mut missing_client_trust = server_config();
    missing_client_trust.client_trust = None;
    let errors = validation_errors(&missing_client_trust, Mode::Server);
    assert_error_contains(&errors, "server config requires client_trust");

    let mut missing_upstream = server_config();
    missing_upstream.upstream = None;
    let errors = validation_errors(&missing_upstream, Mode::Server);
    assert_error_contains(&errors, "server config requires upstream");
}

#[test]
fn config_rejects_missing_required_files() {
    let errors = validation_errors(&client_config(), Mode::Client);

    assert_error_contains(
        &errors,
        "server.trust_bundle 'missing-server-ca.pem' does not exist",
    );
    assert_error_contains(
        &errors,
        "client_identity.cert 'missing-client.crt' does not exist",
    );
    assert_error_contains(
        &errors,
        "client_identity.key 'missing-client.key' does not exist",
    );
}

#[test]
fn client_config_rejects_non_loopback_listen_without_override() {
    let mut config = client_config();
    config.listen = ListenConfig::Tcp("0.0.0.0:8080".parse().expect("socket address"));

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "client listen on non-loopback interfaces requires allow_non_loopback_client_listen",
    );
}

#[test]
fn client_config_allows_non_loopback_listen_with_explicit_override() {
    let mut config = client_config();
    config.listen = ListenConfig::Tcp("0.0.0.0:8080".parse().expect("socket address"));
    config.allow_non_loopback_client_listen = true;

    let errors = validation_errors(&config, Mode::Client);

    assert!(
        !errors
            .iter()
            .any(|err| err.contains("client listen on non-loopback interfaces")),
        "override should suppress non-loopback listen error, got {errors:#?}"
    );
}

#[test]
fn config_rejects_duplicate_route_ids() {
    let mut config = client_config();
    config.routes = vec![client_route("packages"), client_route("packages")];

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(&errors, "duplicate route id 'packages'");
}

#[test]
fn config_rejects_invalid_route_prefixes() {
    let mut config = client_config();
    config.routes = vec![RouteConfig {
        local_prefix: Some("local".to_string()),
        upstream_prefix: Some("/upstream/../private".to_string()),
        ..client_route("packages")
    }];

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "route 'packages' local_prefix: prefix must start with '/'",
    );
    assert_error_contains(
        &errors,
        "route 'packages' upstream_prefix: path contains dot segment",
    );
}

#[test]
fn config_rejects_empty_route_methods() {
    let mut config = client_config();
    config.routes = vec![RouteConfig {
        methods: Vec::new(),
        ..client_route("packages")
    }];

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(&errors, "route 'packages' must declare at least one method");
}

#[test]
fn config_rejects_empty_route_purposes() {
    let mut config = server_config();
    config.routes = vec![RouteConfig {
        client_identity: Some("spiffe://client.example/ns/default/sa/relay".to_string()),
        purposes: vec![" ".to_string()],
        ..server_route("packages", None)
    }];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: PathBuf::from("missing-client-ca.pem"),
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(&errors, "route 'packages' contains an empty purpose");
}

#[test]
fn config_rejects_empty_governed_route_policy_terms() {
    let mut config = server_config();
    config.routes = vec![RouteConfig {
        client_identity: Some("spiffe://client.example/ns/default/sa/relay".to_string()),
        governed_policy: Some(GovernedRoutePolicyConfig {
            permitted_purposes: vec![" ".to_string()],
            permitted_jurisdictions: vec![" ".to_string()],
            allowed_assurance: vec![" ".to_string()],
            minimum_assurance: Some(" ".to_string()),
            max_source_age_seconds: Some(0),
            redaction_fields: vec![" ".to_string()],
            unsupported_odrl_terms: vec![" ".to_string()],
            trusted_context: GovernedTrustedContextConfig {
                jurisdiction: Some(" ".to_string()),
                asserted_assurance: Some(" ".to_string()),
                legal_basis_ref: Some(" ".to_string()),
                consent_ref: Some(" ".to_string()),
                source_observed_age_seconds: None,
            },
            require_legal_basis: false,
            require_consent: false,
        }),
        ..server_route("packages", None)
    }];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: PathBuf::from("missing-client-ca.pem"),
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "route 'packages' governed_policy contains an empty permitted_purpose",
    );
    assert_error_contains(
        &errors,
        "route 'packages' governed_policy max_source_age_seconds must be greater than zero",
    );
    assert_error_contains(
        &errors,
        "route 'packages' governed_policy contains an empty unsupported_odrl_term",
    );
    assert_error_contains(
        &errors,
        "route 'packages' governed_policy trusted_context.legal_basis_ref must not be empty",
    );
}

#[test]
fn config_rejects_inert_governed_route_policy() {
    let mut config = server_config();
    config.routes = vec![RouteConfig {
        client_identity: Some("spiffe://client.example/ns/default/sa/relay".to_string()),
        governed_policy: Some(GovernedRoutePolicyConfig::default()),
        ..server_route("packages", None)
    }];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: PathBuf::from("missing-client-ca.pem"),
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "route 'packages' governed_policy must enforce at least one gate",
    );
}

#[test]
fn config_rejects_governed_route_policy_with_only_static_trusted_context() {
    let mut config = server_config();
    config.routes = vec![RouteConfig {
        client_identity: Some("spiffe://client.example/ns/default/sa/relay".to_string()),
        governed_policy: Some(GovernedRoutePolicyConfig {
            trusted_context: GovernedTrustedContextConfig {
                jurisdiction: Some("ZZ".to_string()),
                asserted_assurance: Some("substantial".to_string()),
                legal_basis_ref: Some("law:test".to_string()),
                consent_ref: Some("consent:test".to_string()),
                source_observed_age_seconds: Some(5),
            },
            ..GovernedRoutePolicyConfig::default()
        }),
        ..server_route("packages", None)
    }];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: PathBuf::from("missing-client-ca.pem"),
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "route 'packages' governed_policy must enforce at least one gate",
    );
}

#[test]
fn config_accepts_governed_route_policy_with_real_gate() {
    let mut config = server_config();
    config.routes = vec![RouteConfig {
        client_identity: Some("spiffe://client.example/ns/default/sa/relay".to_string()),
        governed_policy: Some(GovernedRoutePolicyConfig {
            require_legal_basis: true,
            ..GovernedRoutePolicyConfig::default()
        }),
        ..server_route("packages", None)
    }];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: PathBuf::from("missing-client-ca.pem"),
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_absent(
        &errors,
        "route 'packages' governed_policy must enforce at least one gate",
    );
}

#[test]
fn server_config_rejects_spiffe_client_identity_without_matching_trust_anchor() {
    let mut config = server_config();
    config.routes = vec![server_route(
        "packages",
        Some("spiffe://client.example/ns/default/sa/relay"),
    )];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "client identity 'spiffe://client.example/ns/default/sa/relay' has no trust anchor for trust domain 'client.example'",
    );
}

#[test]
fn server_config_rejects_route_without_client_identity() {
    let config = server_config();

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "server route 'packages' requires client_identity so route and purpose policy are identity-bound",
    );
}

#[test]
fn server_config_rejects_route_client_identity_not_in_allowlist() {
    let mut config = server_config();
    config.routes = vec![server_route(
        "packages",
        Some("spiffe://client.example/ns/default/sa/other"),
    )];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "server route 'packages' references client_identity 'spiffe://client.example/ns/default/sa/other' not in client_trust.allowed_identities",
    );
}

#[test]
fn server_config_accepts_route_client_identity_sets() {
    let mut config = server_config();
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .allowed_identities
        .push("spiffe://client.example/ns/default/sa/reporting".to_string());
    config.routes = vec![RouteConfig {
        client_identity: None,
        client_identities: vec![
            "spiffe://client.example/ns/default/sa/relay".to_string(),
            "spiffe://client.example/ns/default/sa/reporting".to_string(),
        ],
        ..server_route("packages", None)
    }];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: PathBuf::from("missing-client-ca.pem"),
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_absent(&errors, "requires client_identity");
    assert_error_absent(&errors, "not in client_trust.allowed_identities");
}

#[test]
fn server_config_rejects_invalid_trust_context_entitlements() {
    let mut config = server_config();
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_context_entitlements = vec![
        TrustContextEntitlementConfig {
            client_identity: "spiffe://client.example/ns/default/sa/other".to_string(),
            trusted_context: GovernedTrustedContextConfig {
                jurisdiction: Some("ZZ".to_string()),
                ..GovernedTrustedContextConfig::default()
            },
        },
        TrustContextEntitlementConfig {
            client_identity: "spiffe://client.example/ns/default/sa/relay".to_string(),
            trusted_context: GovernedTrustedContextConfig::default(),
        },
    ];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "client_trust.trust_context_entitlements client_identity 'spiffe://client.example/ns/default/sa/other' not in client_trust.allowed_identities",
    );
    assert_error_contains(
        &errors,
        "client_trust.trust_context_entitlements for 'spiffe://client.example/ns/default/sa/relay' must grant at least one trust context assertion",
    );
}

#[test]
fn config_rejects_zero_upstream_timeout() {
    let mut config = client_config();
    config.limits.upstream_timeout_seconds = 0;

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "limits.upstream_timeout_seconds must be greater than zero",
    );
}

#[test]
fn config_rejects_zero_inbound_runtime_limits() {
    let mut config = client_config();
    config.limits.request_timeout_seconds = 0;
    config.limits.tls_handshake_timeout_seconds = 0;
    config.limits.http1_header_read_timeout_seconds = 0;
    config.limits.max_concurrent_requests = 0;
    config.limits.max_concurrent_connections = 0;
    config.limits.max_requests_per_identity_per_minute = 0;

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "limits.request_timeout_seconds must be greater than zero",
    );
    assert_error_contains(
        &errors,
        "limits.tls_handshake_timeout_seconds must be greater than zero",
    );
    assert_error_contains(
        &errors,
        "limits.http1_header_read_timeout_seconds must be greater than zero",
    );
    assert_error_contains(
        &errors,
        "limits.max_concurrent_requests must be greater than zero",
    );
    assert_error_contains(
        &errors,
        "limits.max_concurrent_connections must be greater than zero",
    );
    assert_error_contains(
        &errors,
        "limits.max_requests_per_identity_per_minute must be greater than zero",
    );
}

#[test]
fn server_config_rejects_empty_upstream_auth_env_names() {
    let mut config = server_config();
    config.routes = vec![server_route(
        "packages",
        Some("spiffe://other.example/ns/default/sa/relay"),
    )];
    config
        .upstream
        .as_mut()
        .expect("upstream")
        .default_auth_header_env = Some(" ".to_string());
    config.routes[0].upstream_auth_header_env = Some("".to_string());

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "upstream.default_auth_header_env must not be empty",
    );
    assert_error_contains(
        &errors,
        "server route 'packages' upstream_auth_header_env must not be empty",
    );
}

#[test]
fn server_config_rejects_dns_identity_without_bound_trust_anchor() {
    let mut config = server_config();
    config.allow_dns_san_identity = true;
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .allowed_identities = vec!["benefits-client.example.test".to_string()];
    config.routes = vec![server_route(
        "packages",
        Some("benefits-client.example.test"),
    )];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "DNS client identity 'benefits-client.example.test' must be bound to at least one client_trust.trust_anchors[].dns_identities entry",
    );
}

#[test]
fn server_config_rejects_invalid_revoked_certificate_fingerprints() {
    let mut config = server_config();
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .denied_certificate_fingerprints_sha256 = vec!["not-a-sha256".to_string()];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "client_trust.denied_certificate_fingerprints_sha256 contains an invalid SHA-256 fingerprint",
    );
}

#[test]
fn server_config_rejects_unsafe_upstream_auth_header_names() {
    for header_name in [
        "Connection",
        "Proxy-Authorization",
        "X-Registry-Connector-Token",
        "bad header",
    ] {
        let mut config = server_config();
        config.routes = vec![server_route(
            "packages",
            Some("spiffe://other.example/ns/default/sa/relay"),
        )];
        config.upstream.as_mut().expect("upstream").auth_header_name = header_name.to_string();

        let errors = validation_errors(&config, Mode::Server);

        assert_error_contains(&errors, "upstream.auth_header_name");
    }
}

#[test]
fn flat_client_trust_ca_bundle_is_rejected_as_unknown_field() {
    let raw = r#"
listen: "127.0.0.1:8443"
server_identity:
  cert: "server.crt"
  key: "server.key"
client_trust:
  allowed_identities:
    - "spiffe://client.example/ns/default/sa/relay"
  ca_bundle: "ca.pem"
upstream:
  base_url: "http://127.0.0.1:9000"
routes:
  - id: "packages"
    methods: ["GET"]
    upstream_prefix: "/upstream"
"#;

    let err = serde_saphyr::from_str::<ConnectorConfig>(raw)
        .expect_err("flat ca_bundle must be denied by client_trust schema");
    let message = err.to_string();

    assert!(
        message.contains("unknown field") && message.contains("ca_bundle"),
        "unexpected error: {message}"
    );
}

#[test]
fn server_validation_rejects_multi_cert_trust_anchor_pem() {
    let temp = TempDir::new().expect("temp dir");
    let first = ca_cert_pem("first");
    let second = ca_cert_pem("second");
    let ca_path = temp.path().join("combined-ca.pem");
    std::fs::write(&ca_path, format!("{first}\n{second}")).expect("write combined CA");

    let mut config = server_config();
    config.routes = vec![server_route(
        "packages",
        Some("spiffe://client.example/ns/default/sa/relay"),
    )];
    config
        .client_trust
        .as_mut()
        .expect("client trust")
        .trust_anchors = vec![TrustAnchorConfig {
        ca: ca_path,
        trust_domain: "client.example".to_string(),
        dns_identities: Vec::new(),
    }];

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "trust anchor PEM must contain exactly one CA certificate",
    );
}

#[test]
fn client_validation_rejects_leaf_certificate_without_client_auth_eku() {
    let temp = TempDir::new().expect("temp dir");
    let key = KeyPair::generate().expect("key");
    let params = CertificateParams::new(vec!["client.example.test".to_string()])
        .expect("certificate params");
    let cert = params.self_signed(&key).expect("certificate");
    let cert_path = temp.path().join("client.pem");
    let key_path = temp.path().join("client.key");
    let ca_path = temp.path().join("server-ca.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");
    std::fs::write(&ca_path, cert.pem()).expect("write trust bundle placeholder");

    let mut config = client_config();
    config.server.as_mut().expect("server config").trust_bundle = ca_path;
    config.client_identity = Some(IdentityFiles {
        cert: cert_path,
        key: key_path,
    });

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "leaf certificate must assert Extended Key Usage clientAuth",
    );
}

#[test]
fn server_validation_rejects_leaf_certificate_without_server_auth_eku() {
    let temp = TempDir::new().expect("temp dir");
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["server.example.test".to_string()])
        .expect("certificate params");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).expect("certificate");
    let cert_path = temp.path().join("server.pem");
    let key_path = temp.path().join("server.key");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");

    let mut config = server_config();
    config.server_identity = Some(IdentityFiles {
        cert: cert_path,
        key: key_path,
    });

    let errors = validation_errors(&config, Mode::Server);

    assert_error_contains(
        &errors,
        "leaf certificate must assert Extended Key Usage serverAuth",
    );
}

#[test]
fn identity_extraction_rejects_non_spiffe_uri_san_even_with_dns_fallback_enabled() {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names.push(SanType::URI(
        "urn:example:client".try_into().expect("URI SAN"),
    ));
    let cert = params.self_signed(&key).expect("certificate");

    let err = extract_peer_identity_from_der(cert.der().as_ref(), true)
        .expect_err("non-SPIFFE URI SAN must not become a peer identity");

    assert!(
        err.contains("acceptable URI SAN identity"),
        "unexpected error: {err}"
    );
}

#[cfg(unix)]
#[test]
fn validation_rejects_group_or_world_readable_private_keys() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temp dir");
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["client.example.test".to_string()])
        .expect("certificate params");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key).expect("certificate");
    let cert_path = temp.path().join("client.pem");
    let key_path = temp.path().join("client.key");
    let ca_path = temp.path().join("server-ca.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
        .expect("key permissions");
    std::fs::write(&ca_path, cert.pem()).expect("write trust bundle placeholder");

    let mut config = client_config();
    config.server.as_mut().expect("server config").trust_bundle = ca_path;
    config.client_identity = Some(IdentityFiles {
        cert: cert_path,
        key: key_path,
    });

    let errors = validation_errors(&config, Mode::Client);

    assert_error_contains(
        &errors,
        "client_identity.key must not be readable or writable by group or others",
    );
}

fn ca_cert_pem(common_name: &str) -> String {
    let mut params = CertificateParams::new(Vec::new()).expect("ca params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().expect("ca key");
    params.self_signed(&key).expect("ca cert").pem()
}
