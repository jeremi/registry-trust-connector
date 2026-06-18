use http::Method;
use registry_trust_connector::config::RouteConfig;
use registry_trust_connector::routing::{find_client_route, prefix_matches, validate_request_path};

fn route(id: &str, local_prefix: &str, upstream_prefix: &str) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        methods: vec![Method::GET],
        local_prefix: Some(local_prefix.to_string()),
        upstream_prefix: Some(upstream_prefix.to_string()),
        require_purpose: false,
        purpose_source: None,
        client_identity: None,
        upstream_auth_header_env: None,
        forward_client_identity_header: false,
        purposes: Vec::new(),
        governed_policy: None,
        allow_forward_authorization: false,
        allow_forward_cookie: false,
        policy_hash: Default::default(),
    }
}

fn server_route(id: &str, upstream_prefix: &str, client_identity: &str) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        methods: vec![Method::GET],
        local_prefix: None,
        upstream_prefix: Some(upstream_prefix.to_string()),
        require_purpose: false,
        purpose_source: None,
        client_identity: Some(client_identity.to_string()),
        upstream_auth_header_env: None,
        forward_client_identity_header: false,
        purposes: Vec::new(),
        governed_policy: None,
        allow_forward_authorization: false,
        allow_forward_cookie: false,
        policy_hash: Default::default(),
    }
}

#[test]
fn prefix_matching_respects_segment_boundaries() {
    assert!(prefix_matches("/v1", "/v1"));
    assert!(prefix_matches("/v1/packages", "/v1"));
    assert!(prefix_matches("/v1/packages", "/v1/"));
    assert!(!prefix_matches("/v1alpha", "/v1"));

    let routes = vec![
        route("v1", "/v1", "/upstream/v1"),
        route("v1alpha", "/v1alpha", "/upstream/v1alpha"),
    ];

    let matched = find_client_route(&routes, &Method::GET, "/v1alpha/packages")
        .expect("v1 route must not consume v1alpha path");

    assert_eq!(matched.route.id, "v1alpha");
    assert_eq!(matched.upstream_path, "/upstream/v1alpha/packages");
}

#[test]
fn route_matching_uses_canonical_paths_and_most_specific_prefix() {
    let routes = vec![
        route("broad", "/v1", "/upstream/broad"),
        route("admin", "/v1/admin", "/upstream/admin"),
    ];

    let matched = find_client_route(&routes, &Method::GET, "/v1/%61dmin/records")
        .expect("encoded admin path should match canonical admin route");

    assert_eq!(matched.route.id, "admin");
    assert_eq!(matched.upstream_path, "/upstream/admin/records");
}

#[test]
fn server_route_matching_uses_canonical_paths_and_most_specific_prefix() {
    let routes = vec![
        server_route("broad", "/v1", "spiffe://client.example/workload"),
        server_route("admin", "/v1/admin", "spiffe://client.example/workload"),
    ];

    let matched = registry_trust_connector::routing::find_server_route(
        &routes,
        &Method::GET,
        "/v1/%61dmin/records",
        "spiffe://client.example/workload",
    )
    .expect("encoded admin path should match canonical admin route");

    assert_eq!(matched.route.id, "admin");
    assert_eq!(matched.upstream_path, "/v1/admin/records");
}

#[test]
fn request_paths_reject_encoded_slash_delimiters() {
    let err = validate_request_path("/v1/a%2fb").expect_err("encoded slash delimiter must fail");

    assert!(err.contains("delimiter"), "unexpected error: {err}");
}

#[test]
fn request_paths_reject_invalid_percent_encoding() {
    let err = validate_request_path("/v1/%GG/packages").expect_err("invalid escape must fail");

    assert!(err.contains("percent"), "unexpected error: {err}");
}

#[test]
fn request_paths_reject_dot_segments_after_decoding() {
    let literal =
        validate_request_path("/v1/../packages").expect_err("literal dot segment must fail");
    let encoded =
        validate_request_path("/v1/%2e%2e/packages").expect_err("encoded dot segment must fail");

    assert!(
        literal.contains("dot segment"),
        "unexpected error: {literal}"
    );
    assert!(
        encoded.contains("dot segment"),
        "unexpected error: {encoded}"
    );
}
