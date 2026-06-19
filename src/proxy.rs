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
    PolicyGate, PolicyInput as PdpPolicyInput,
};
use tower::limit::ConcurrencyLimitLayer;
use ulid::Ulid;
use url::Url;

use crate::config::{
    max_body_bytes, request_timeout, upstream_timeout, ClientTrustConfig, ConnectorConfig,
    GovernedRoutePolicyConfig, GovernedTrustedContextConfig, Mode, PurposeSource,
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
const TRUST_JURISDICTION: &str = "x-registry-trust-jurisdiction";
const TRUST_ASSURANCE: &str = "x-registry-trust-assurance";
const TRUST_LEGAL_BASIS: &str = "x-registry-trust-legal-basis";
const TRUST_CONSENT: &str = "x-registry-trust-consent";
const TRUST_SOURCE_OBSERVED_AGE_SECONDS: &str = "x-registry-source-observed-age-seconds";

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
    let authorized_purpose = authorize_server_purpose(
        &route_match,
        request.headers(),
        &identity,
        state.config.client_trust.as_ref(),
    )?;
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
    identity: &PeerIdentity,
    client_trust: Option<&ClientTrustConfig>,
) -> Result<Option<String>, ConnectorProblem> {
    let purpose = single_data_purpose(headers)?;
    let governed_policy = route_match.route.governed_policy.as_ref();
    let trusted_context_scopes =
        trusted_context_scopes(governed_policy, client_trust, &identity.value);
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
    let source_binding = format!("trust-connector:{}", route_match.upstream_path);
    let context = request_pdp_context(
        &purpose,
        headers,
        identity,
        &trusted_context_scopes,
        route_match.route.id.as_str(),
        &source_binding,
    )?;
    let policy = PdpPolicyInput {
        policy_id: format!("trust-connector.route.{}", route_match.route.id),
        policy_hash: route_purpose_policy_hash(route_match),
        ecosystem_binding_id: None,
        ecosystem_binding_version: None,
        rule_ids: vec![format!("route-purpose:{}", route_match.route.id)],
        rule_ids_by_gate: route_pdp_rule_ids_by_gate(route_match.route, governed_policy),
        permit_unconstrained: false,
        required_context: Default::default(),
        odrl_constraint_terms: Vec::new(),
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
        allowed_legal_basis_refs: Vec::new(),
        allowed_consent_refs: Vec::new(),
        redaction_fields: governed_policy
            .map(|policy| policy.redaction_fields.iter().cloned().collect())
            .unwrap_or_default(),
        allowed_relationships: Vec::new(),
        relationship_purpose_constraints: Vec::new(),
        allowed_requested_facts: vec![source_binding.clone()],
        allowed_requested_disclosures: vec!["proxy_forward".to_string()],
        allowed_credential_formats: Vec::new(),
        allowed_source_bindings: vec![source_binding],
        allowed_route_identities: vec![route_match.route.id.clone()],
        required_checked_scopes: BTreeSet::new(),
        unsupported_odrl_terms: governed_policy
            .map(|policy| policy.unsupported_odrl_terms.clone())
            .unwrap_or_default(),
    };
    match pdp_decide(&context, &policy) {
        PdpDecision::Permit(audit) => {
            tracing::info!(
                route_id = %route_match.route.id,
                pdp_policy_id = %audit.policy_id,
                pdp_policy_hash = %audit.policy_hash,
                pdp_evaluated_rule_ids = ?audit.evaluated_rule_ids,
                "server connector permitted purpose by pdp"
            );
            Ok(Some(purpose))
        }
        PdpDecision::PermitWithRedaction {
            audit, field_set, ..
        } => {
            tracing::info!(
                route_id = %route_match.route.id,
                pdp_policy_id = %audit.policy_id,
                pdp_policy_hash = %audit.policy_hash,
                pdp_evaluated_rule_ids = ?audit.evaluated_rule_ids,
                pdp_redaction_fields = ?field_set,
                pdp_stable_problem_code = %registry_platform_pdp::UNSUPPORTED_POLICY_TERM,
                "server connector denied pdp redaction decision it cannot enforce"
            );
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::UNSUPPORTED_POLICY_TERM,
            ))
        }
        PdpDecision::Deny {
            audit,
            stable_problem_code,
        } => {
            tracing::info!(
                route_id = %route_match.route.id,
                pdp_policy_id = %audit.policy_id,
                pdp_policy_hash = %audit.policy_hash,
                pdp_evaluated_rule_ids = ?audit.evaluated_rule_ids,
                pdp_stable_problem_code = %stable_problem_code,
                "server connector denied purpose by pdp"
            );
            Err(ConnectorProblem::PdpDenied(pdp_problem_code(
                &stable_problem_code,
            )))
        }
    }
}

fn route_pdp_rule_ids_by_gate(
    route: &crate::config::RouteConfig,
    governed_policy: Option<&GovernedRoutePolicyConfig>,
) -> BTreeMap<PolicyGate, Vec<String>> {
    let route_id = route.id.as_str();
    let mut rule_ids = BTreeMap::from([
        (
            PolicyGate::PolicyIdentity,
            vec![format!("trust-connector.route.{route_id}.policy_identity")],
        ),
        (
            PolicyGate::RequestedFact,
            vec![format!("trust-connector.route.{route_id}.requested_fact")],
        ),
        (
            PolicyGate::RequestedDisclosure,
            vec![format!(
                "trust-connector.route.{route_id}.requested_disclosure"
            )],
        ),
        (
            PolicyGate::SourceBinding,
            vec![format!("trust-connector.route.{route_id}.source_binding")],
        ),
        (
            PolicyGate::RouteIdentity,
            vec![format!("trust-connector.route.{route_id}.route_identity")],
        ),
    ]);
    if !route.purposes.is_empty()
        || governed_policy.is_some_and(|policy| !policy.permitted_purposes.is_empty())
    {
        rule_ids.insert(
            PolicyGate::Purpose,
            vec![format!("trust-connector.route.{route_id}.purpose")],
        );
    }
    if let Some(policy) = governed_policy {
        if !policy.permitted_jurisdictions.is_empty() {
            rule_ids.insert(
                PolicyGate::Jurisdiction,
                vec![format!("trust-connector.route.{route_id}.jurisdiction")],
            );
        }
        if !policy.allowed_assurance.is_empty() {
            rule_ids.insert(
                PolicyGate::AssuranceAllowedSet,
                vec![format!("trust-connector.route.{route_id}.assurance")],
            );
        }
        if policy.minimum_assurance.is_some() {
            rule_ids.insert(
                PolicyGate::MinimumAssurance,
                vec![format!(
                    "trust-connector.route.{route_id}.minimum_assurance"
                )],
            );
        }
        if policy.max_source_age_seconds.is_some() {
            rule_ids.insert(
                PolicyGate::SourceFreshness,
                vec![format!("trust-connector.route.{route_id}.source_freshness")],
            );
        }
        if policy.require_legal_basis {
            rule_ids.insert(
                PolicyGate::LegalBasisRequired,
                vec![format!("trust-connector.route.{route_id}.legal_basis")],
            );
        }
        if policy.require_consent {
            rule_ids.insert(
                PolicyGate::ConsentRequired,
                vec![format!("trust-connector.route.{route_id}.consent")],
            );
        }
        if !policy.unsupported_odrl_terms.is_empty() {
            rule_ids.insert(
                PolicyGate::OdrlTerms,
                vec![format!("trust-connector.route.{route_id}.odrl_terms")],
            );
        }
        if !policy.redaction_fields.is_empty() {
            rule_ids.insert(
                PolicyGate::Redaction,
                vec![format!("trust-connector.route.{route_id}.redaction")],
            );
        }
    }
    rule_ids
}

fn request_pdp_context(
    purpose: &str,
    headers: &HeaderMap,
    identity: &PeerIdentity,
    trusted_context_scopes: &BTreeSet<String>,
    route_identity: &str,
    source_binding: &str,
) -> Result<PdpRequestContext, ConnectorProblem> {
    Ok(PdpRequestContext {
        purpose: purpose.to_string(),
        legal_basis_ref: verified_trust_header_value(
            headers,
            trusted_context_scopes,
            TRUST_LEGAL_BASIS,
            "legal_basis",
        )
        .map(ToOwned::to_owned),
        consent_ref: verified_trust_header_value(
            headers,
            trusted_context_scopes,
            TRUST_CONSENT,
            "consent",
        )
        .map(ToOwned::to_owned),
        asserted_assurance: verified_trust_header_value(
            headers,
            trusted_context_scopes,
            TRUST_ASSURANCE,
            "assurance",
        )
        .map(ToOwned::to_owned),
        jurisdiction: verified_trust_header_value(
            headers,
            trusted_context_scopes,
            TRUST_JURISDICTION,
            "jurisdiction",
        )
        .map(ToOwned::to_owned),
        requester_identity: Some(identity.value.clone()),
        subject_ref: trust_header_value(headers, "x-registry-subject-ref").map(ToOwned::to_owned),
        relationship: trust_header_value(headers, "x-registry-relationship").map(ToOwned::to_owned),
        on_behalf_of: trust_header_value(headers, "x-registry-on-behalf-of").map(ToOwned::to_owned),
        requested_fact: Some(source_binding.to_string()),
        requested_disclosure: Some("proxy_forward".to_string()),
        requested_credential_format: trust_header_value(headers, "x-registry-credential-format")
            .map(ToOwned::to_owned),
        source_binding: Some(source_binding.to_string()),
        route_identity: Some(route_identity.to_string()),
        checked_scopes: BTreeSet::new(),
        source_observed_at_unix_seconds: verified_trust_header_value(
            headers,
            trusted_context_scopes,
            "x-registry-source-observed-at-unix-seconds",
            "source_observed_at_unix_seconds",
        )
        .map(parse_unix_seconds)
        .transpose()?,
        source_observed_age_seconds: source_observed_age_seconds(headers, trusted_context_scopes)?,
    })
}

fn parse_unix_seconds(value: &str) -> Result<u64, ConnectorProblem> {
    value
        .parse::<u64>()
        .map_err(|_| ConnectorProblem::PdpDenied(registry_platform_pdp::EVIDENCE_STALE))
}

fn trust_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn verified_trust_header_value<'a>(
    headers: &'a HeaderMap,
    trusted_context_scopes: &BTreeSet<String>,
    name: &str,
    field: &str,
) -> Option<&'a str> {
    let value = trust_header_value(headers, name)?;
    trusted_context_scopes
        .contains(&trust_context_scope(field, value))
        .then_some(value)
}

fn trust_context_scope(field: &str, value: &str) -> String {
    format!("registry:trust:{field}:{value}")
}

fn source_observed_age_seconds(
    headers: &HeaderMap,
    trusted_context_scopes: &BTreeSet<String>,
) -> Result<Option<u64>, ConnectorProblem> {
    let Some(value) = trust_header_value(headers, TRUST_SOURCE_OBSERVED_AGE_SECONDS) else {
        return Ok(None);
    };
    if !trusted_context_scopes.contains(&trust_context_scope("source_observed_age_seconds", value))
    {
        return Ok(None);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| ConnectorProblem::PdpDenied(registry_platform_pdp::EVIDENCE_STALE))
}

fn trusted_context_scopes(
    policy: Option<&GovernedRoutePolicyConfig>,
    client_trust: Option<&ClientTrustConfig>,
    client_identity: &str,
) -> BTreeSet<String> {
    let peer_scopes = peer_trusted_context_scopes(client_trust, client_identity);
    let route_scopes = policy.map_or_else(BTreeSet::new, |policy| {
        context_scopes(&policy.trusted_context)
    });
    if route_scopes.is_empty() {
        return peer_scopes;
    }
    peer_scopes.intersection(&route_scopes).cloned().collect()
}

fn peer_trusted_context_scopes(
    client_trust: Option<&ClientTrustConfig>,
    client_identity: &str,
) -> BTreeSet<String> {
    client_trust
        .into_iter()
        .flat_map(|trust| trust.trust_context_entitlements.iter())
        .find(|entitlement| entitlement.client_identity.trim() == client_identity)
        .map(|entitlement| context_scopes(&entitlement.trusted_context))
        .unwrap_or_default()
}

fn context_scopes(context: &GovernedTrustedContextConfig) -> BTreeSet<String> {
    let mut scopes = BTreeSet::new();
    if let Some(value) = context.jurisdiction.as_deref() {
        scopes.insert(trust_context_scope("jurisdiction", value));
    }
    if let Some(value) = context.asserted_assurance.as_deref() {
        scopes.insert(trust_context_scope("assurance", value));
    }
    if let Some(value) = context.legal_basis_ref.as_deref() {
        scopes.insert(trust_context_scope("legal_basis", value));
    }
    if let Some(value) = context.consent_ref.as_deref() {
        scopes.insert(trust_context_scope("consent", value));
    }
    if let Some(value) = context.source_observed_age_seconds {
        scopes.insert(trust_context_scope(
            "source_observed_age_seconds",
            &value.to_string(),
        ));
    }
    scopes
}

fn pdp_problem_code(code: &str) -> &'static str {
    match code {
        registry_platform_pdp::CONTEXT_REQUIRED => registry_platform_pdp::CONTEXT_REQUIRED,
        registry_platform_pdp::PURPOSE_NOT_PERMITTED => {
            registry_platform_pdp::PURPOSE_NOT_PERMITTED
        }
        registry_platform_pdp::ASSURANCE_INSUFFICIENT => {
            registry_platform_pdp::ASSURANCE_INSUFFICIENT
        }
        registry_platform_pdp::EVIDENCE_STALE => registry_platform_pdp::EVIDENCE_STALE,
        registry_platform_pdp::LEGAL_BASIS_REQUIRED => registry_platform_pdp::LEGAL_BASIS_REQUIRED,
        registry_platform_pdp::CONSENT_REQUIRED => registry_platform_pdp::CONSENT_REQUIRED,
        registry_platform_pdp::JURISDICTION_NOT_PERMITTED => {
            registry_platform_pdp::JURISDICTION_NOT_PERMITTED
        }
        registry_platform_pdp::RELATIONSHIP_NOT_PERMITTED => {
            registry_platform_pdp::RELATIONSHIP_NOT_PERMITTED
        }
        registry_platform_pdp::REQUESTED_FACT_NOT_PERMITTED => {
            registry_platform_pdp::REQUESTED_FACT_NOT_PERMITTED
        }
        registry_platform_pdp::DISCLOSURE_NOT_PERMITTED => {
            registry_platform_pdp::DISCLOSURE_NOT_PERMITTED
        }
        registry_platform_pdp::CREDENTIAL_FORMAT_NOT_PERMITTED => {
            registry_platform_pdp::CREDENTIAL_FORMAT_NOT_PERMITTED
        }
        registry_platform_pdp::SOURCE_BINDING_NOT_PERMITTED => {
            registry_platform_pdp::SOURCE_BINDING_NOT_PERMITTED
        }
        registry_platform_pdp::ROUTE_IDENTITY_NOT_PERMITTED => {
            registry_platform_pdp::ROUTE_IDENTITY_NOT_PERMITTED
        }
        registry_platform_pdp::CHECKED_SCOPE_REQUIRED => {
            registry_platform_pdp::CHECKED_SCOPE_REQUIRED
        }
        registry_platform_pdp::UNSUPPORTED_POLICY_TERM => {
            registry_platform_pdp::UNSUPPORTED_POLICY_TERM
        }
        registry_platform_pdp::POLICY_REQUIRED => registry_platform_pdp::POLICY_REQUIRED,
        registry_platform_pdp::POLICY_ID_REQUIRED => registry_platform_pdp::POLICY_ID_REQUIRED,
        registry_platform_pdp::POLICY_HASH_INVALID => registry_platform_pdp::POLICY_HASH_INVALID,
        _ => registry_platform_pdp::PURPOSE_NOT_PERMITTED,
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
    for identity in route.client_identities.iter().collect::<BTreeSet<_>>() {
        push_hash_field(&mut material, "client_identity", identity);
    }
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
        for term in policy
            .unsupported_odrl_terms
            .iter()
            .collect::<BTreeSet<_>>()
        {
            push_hash_field(&mut material, "governed_unsupported_odrl_term", term);
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
    use crate::config::{
        ClientTrustConfig, GovernedRoutePolicyConfig, GovernedTrustedContextConfig, RouteConfig,
        TrustContextEntitlementConfig,
    };
    use crate::identity::IdentityKind;
    use std::io::{self, Write};

    #[test]
    fn server_purpose_logs_pdp_audit_provenance_for_denials_and_permits() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_writer(SharedLogWriter(Arc::clone(&logs)))
            .finish();
        let route = test_route();
        let route_match = RouteMatch {
            route: &route,
            upstream_path: "/relay/packages/records".to_string(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(DATA_PURPOSE, HeaderValue::from_static("marketing"));

        tracing::subscriber::set_global_default(subscriber).expect("install test subscriber");
        tracing::callsite::rebuild_interest_cache();
        assert_eq!(
            authorize_server_purpose(
                &route_match,
                &headers,
                &test_identity(),
                Some(&test_client_trust()),
            ),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::PURPOSE_NOT_PERMITTED
            ))
        );

        let captured = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf8 logs");
        assert!(
            captured.contains(r#""route_id":"server-route""#),
            "{captured}"
        );
        assert!(
            captured.contains(r#""pdp_policy_id":"trust-connector.route.server-route""#),
            "{captured}"
        );
        assert!(
            captured.contains(r#""pdp_policy_hash":"sha256:"#),
            "{captured}"
        );
        assert!(
            captured.contains("trust-connector.route.server-route.policy_identity")
                && captured.contains("trust-connector.route.server-route.purpose"),
            "{captured}"
        );

        logs.lock().expect("logs").clear();

        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                permitted_jurisdictions: vec!["ZZ".to_string()],
                allowed_assurance: vec!["substantial".to_string()],
                require_legal_basis: true,
                require_consent: true,
                trusted_context: trusted_context_grants(),
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
        headers.insert(TRUST_JURISDICTION, HeaderValue::from_static("ZZ"));
        headers.insert(TRUST_ASSURANCE, HeaderValue::from_static("substantial"));
        headers.insert(TRUST_LEGAL_BASIS, HeaderValue::from_static("law:test"));
        headers.insert(TRUST_CONSENT, HeaderValue::from_static("consent:test"));

        assert_eq!(
            authorize_server_purpose(
                &route_match,
                &headers,
                &test_identity(),
                Some(&test_client_trust()),
            ),
            Ok(Some("operations".to_string()))
        );

        let captured = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf8 logs");
        assert!(
            captured.contains(r#""route_id":"server-route""#),
            "{captured}"
        );
        assert!(
            captured.contains(r#""pdp_policy_id":"trust-connector.route.server-route""#),
            "{captured}"
        );
        assert!(
            captured.contains(r#""pdp_policy_hash":"sha256:"#),
            "{captured}"
        );
        assert!(
            captured.contains("trust-connector.route.server-route.policy_identity")
                && captured.contains("trust-connector.route.server-route.purpose"),
            "{captured}"
        );
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
            authorize_server_purpose(&route_match, &headers, &test_identity(), None),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::LEGAL_BASIS_REQUIRED
            ))
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
            authorize_server_purpose(&route_match, &headers, &test_identity(), None),
            Err(ConnectorProblem::PurposeDenied)
        );
    }

    #[test]
    fn governed_route_policy_permits_when_request_context_satisfies_policy() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                permitted_jurisdictions: vec!["ZZ".to_string()],
                allowed_assurance: vec!["substantial".to_string()],
                require_legal_basis: true,
                require_consent: true,
                trusted_context: trusted_context_grants(),
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
        headers.insert(TRUST_JURISDICTION, HeaderValue::from_static("ZZ"));
        headers.insert(TRUST_ASSURANCE, HeaderValue::from_static("substantial"));
        headers.insert(TRUST_LEGAL_BASIS, HeaderValue::from_static("law:test"));
        headers.insert(TRUST_CONSENT, HeaderValue::from_static("consent:test"));

        assert_eq!(
            authorize_server_purpose(
                &route_match,
                &headers,
                &test_identity(),
                Some(&test_client_trust()),
            ),
            Ok(Some("operations".to_string()))
        );
    }

    #[test]
    fn governed_route_policy_denies_missing_request_source_age_despite_static_context() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                max_source_age_seconds: Some(30),
                trusted_context: GovernedTrustedContextConfig {
                    source_observed_age_seconds: Some(5),
                    ..GovernedTrustedContextConfig::default()
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
            authorize_server_purpose(&route_match, &headers, &test_identity(), None),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::EVIDENCE_STALE
            ))
        );
    }

    #[test]
    fn governed_route_policy_ignores_ungranted_trust_headers() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                permitted_jurisdictions: vec!["ZZ".to_string()],
                allowed_assurance: vec!["substantial".to_string()],
                require_legal_basis: true,
                require_consent: true,
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
        headers.insert(TRUST_JURISDICTION, HeaderValue::from_static("ZZ"));
        headers.insert(TRUST_ASSURANCE, HeaderValue::from_static("substantial"));
        headers.insert(TRUST_LEGAL_BASIS, HeaderValue::from_static("law:test"));
        headers.insert(TRUST_CONSENT, HeaderValue::from_static("consent:test"));

        assert_eq!(
            authorize_server_purpose(&route_match, &headers, &test_identity(), None),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::JURISDICTION_NOT_PERMITTED
            ))
        );
    }

    #[test]
    fn governed_route_policy_denies_mismatched_trusted_context_grants() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                permitted_jurisdictions: vec!["ZZ".to_string()],
                trusted_context: GovernedTrustedContextConfig {
                    jurisdiction: Some("RW".to_string()),
                    ..GovernedTrustedContextConfig::default()
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
        headers.insert(TRUST_JURISDICTION, HeaderValue::from_static("ZZ"));

        assert_eq!(
            authorize_server_purpose(
                &route_match,
                &headers,
                &test_identity(),
                Some(&test_client_trust()),
            ),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::JURISDICTION_NOT_PERMITTED
            ))
        );
    }

    #[test]
    fn governed_route_policy_denies_unsupported_odrl_terms() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                unsupported_odrl_terms: vec!["odrl:spatial".to_string()],
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
            authorize_server_purpose(&route_match, &headers, &test_identity(), None),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::UNSUPPORTED_POLICY_TERM
            ))
        );
    }

    #[test]
    fn governed_route_policy_denies_redaction_decisions_it_cannot_enforce() {
        let route = RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                permitted_purposes: vec!["operations".to_string()],
                redaction_fields: vec!["claims.ssn".to_string()],
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
            authorize_server_purpose(&route_match, &headers, &test_identity(), None),
            Err(ConnectorProblem::PdpDenied(
                registry_platform_pdp::UNSUPPORTED_POLICY_TERM
            ))
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
    fn route_purpose_policy_hash_changes_for_unsupported_odrl_terms() {
        let route = test_route();
        let baseline = hash_for_route(&route);
        let changed = hash_for_route(&RouteConfig {
            governed_policy: Some(GovernedRoutePolicyConfig {
                unsupported_odrl_terms: vec!["odrl:spatial".to_string()],
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
            client_identities: Vec::new(),
            upstream_auth_header_env: Some("REGISTRY_PROXY_POLICY_TOKEN".to_string()),
            forward_client_identity_header: false,
            purposes: vec!["operations".to_string(), "eligibility".to_string()],
            governed_policy: None,
            allow_forward_authorization: false,
            allow_forward_cookie: false,
            policy_hash: Default::default(),
        }
    }

    fn test_identity() -> PeerIdentity {
        PeerIdentity {
            value: "spiffe://openspp.example/client-a".to_string(),
            kind: IdentityKind::UriSan,
            fingerprint_sha256: "sha256:test".to_string(),
        }
    }

    fn test_client_trust() -> ClientTrustConfig {
        ClientTrustConfig {
            allowed_identities: vec!["spiffe://openspp.example/client-a".to_string()],
            trust_anchors: Vec::new(),
            denied_certificate_fingerprints_sha256: Vec::new(),
            trust_context_entitlements: vec![TrustContextEntitlementConfig {
                client_identity: "spiffe://openspp.example/client-a".to_string(),
                trusted_context: trusted_context_grants(),
            }],
        }
    }

    #[test]
    fn peer_trusted_context_scopes_trims_configured_identity() {
        let mut trust = test_client_trust();
        trust.trust_context_entitlements[0].client_identity =
            " spiffe://openspp.example/client-a ".to_string();

        let scopes = peer_trusted_context_scopes(Some(&trust), "spiffe://openspp.example/client-a");

        assert!(scopes.contains("registry:trust:jurisdiction:ZZ"));
        assert!(scopes.contains("registry:trust:assurance:substantial"));
    }

    fn trusted_context_grants() -> GovernedTrustedContextConfig {
        GovernedTrustedContextConfig {
            jurisdiction: Some("ZZ".to_string()),
            asserted_assurance: Some("substantial".to_string()),
            legal_basis_ref: Some("law:test".to_string()),
            consent_ref: Some("consent:test".to_string()),
            source_observed_age_seconds: Some(5),
        }
    }

    #[derive(Clone)]
    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    struct SharedLogWriteGuard(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogWriter {
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
}
