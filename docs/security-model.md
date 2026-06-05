---
title: Security model
doc_type: explanation
product: Registry Trust Connector
layer: federation
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: src/proxy.rs, src/tls.rs, src/identity.rs, src/config.rs
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE]
---

# Security model

The connector enforces a narrow trust boundary between a local client system
and a private Registry Relay. The client connector handles local HTTP traffic.
The server connector is the policy gate that verifies client certificate
identity, route authorization, purpose authorization, and upstream auth
injection before a request reaches Relay.

## Trust boundary

The client connector is not an authorization boundary for Relay. It prepares
requests, rewrites paths, applies client-side purpose policy, and authenticates
to the server connector with mTLS.

The server connector is the Relay-side authorization boundary. It accepts only
client certificates that chain to configured trust anchors and expose an
allowed identity. It then authorizes the route and purpose before forwarding.

## Identity binding

SPIFFE URI identities are the preferred client identity format. The server
connector extracts the SPIFFE trust domain from the URI and verifies that the
certificate chain is rooted in a trust anchor configured for that domain.

DNS SAN fallback is disabled by default. When fallback is enabled, each DNS
identity must also be bound to one or more trust anchors with
`client_trust.trust_anchors[].dns_identities`. Allowlisting the DNS identity is
not enough by itself.

## Route and purpose authorization

Server routes bind policy to three values:

- HTTP method.
- Segment-aware upstream path prefix.
- Exact client certificate identity.

When a route declares allowed `purposes`, the request must include a non-empty
`data-purpose` header with one of those exact values. A missing purpose returns
`connector.purpose_required`. A purpose outside the route list returns
`connector.purpose_denied`.

## Header minimization

The connector treats headers as a disclosure surface. By default it does not
forward caller-supplied `Authorization` or `Cookie` headers. It also strips
hop-by-hop headers, headers named by `Connection`, and all
`x-registry-connector-*` private headers.

Server mode injects the upstream auth header after filtering. This prevents a
caller from supplying the Relay credential directly through the connector.

## Request identifiers and connector headers

The connector preserves an inbound `x-request-id` header when it is non-empty.
If the caller omits it, the connector creates one.

Client mode may add:

- `x-registry-connector-id`, when `connector_id` is configured.
- `x-registry-connector-version`.

Server mode may add `x-registry-connector-client-identity` to the upstream
request only when the matched route sets
`forward_client_identity_header: true`.

## Limits

Both connector modes enforce `limits.max_body_bytes` before forwarding a
request. Oversized requests return `connector.body_too_large`.

Upstream response bodies are also read with `limits.max_body_bytes`. Oversized
upstream responses, timeouts, connection errors, and body read failures return
`connector.upstream_unavailable`.

Server mode logs verified client identities only as platform audit reference
hashes. Production configs should set `audit.hash_secret_env` to a secret that
is at least 32 bytes; `audit.allow_unkeyed_hashing: true` is only for local
development and demo fixtures.

## Out of scope

The connector does not replace Relay authorization, database policy, consent
record storage, audit storage, or certificate lifecycle management. Operators
still need deployment controls for key storage, certificate issuance,
certificate rotation, network policy, secret injection, and log retention.
