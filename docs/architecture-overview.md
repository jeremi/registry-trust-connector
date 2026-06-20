---
title: Architecture overview
doc_type: explanation
product: Registry Trust Connector
layer: [consultation, federation, operations]
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: ../README.md, ../src/main.rs, ../src/proxy.rs, ../src/tls.rs, ../src/config.rs
last_reviewed: "2026-06-19"
standards_referenced: [TLS, X.509, SPIFFE, RFC 9457, X-Road]
---

# Architecture overview

Registry Trust Connector is a narrow policy proxy for governed access to a
private Registry Relay. It is designed for deployments where a local client
system should not receive direct Relay credentials or call Relay without a
route, identity, and purpose check.

The connector is intentionally smaller than a full interoperability gateway. It
does not evaluate source data, issue credentials, store consent records, manage
registry data, or replace Relay authorization. It enforces the transport and
request policy boundary immediately before Relay access.

## Runtime shape

The connector runs as a pair:

```text
client system
  -> Trust Connector client
  -> mTLS
  -> Trust Connector server
  -> private Registry Relay
```

Client mode listens for local HTTP traffic, matches configured route prefixes,
rewrites the path for the server connector, and supplies a `data-purpose` value
when route policy requires one.

Server mode listens with TLS and requires client certificates. It verifies the
client certificate identity, matches the route to that identity, authorizes the
purpose, applies configured governed policy gates where present, injects the
Relay upstream auth header from environment variables, and forwards the request
to Relay.

## What it enforces

The implemented enforcement surface is:

- mTLS between the client connector and server connector.
- X.509 certificate validation for client and server identities.
- SPIFFE URI SAN identity binding by trust domain, with constrained DNS SAN
  fallback when explicitly enabled.
- Exact client identity allowlisting in server mode.
- HTTP method and segment-aware route prefix matching.
- Required and allowed `data-purpose` values on routes.
- Optional governed route policy gates for jurisdiction, assurance, source
  freshness, legal basis, consent, unsupported ODRL terms, and redaction fields.
- Header minimization before forwarding, including stripping caller-supplied
  `Authorization`, `Cookie`, hop-by-hop headers, and connector-private headers
  unless route policy explicitly allows selected caller headers.
- Upstream Relay auth injection after header filtering.
- Request size limits, upstream response size limits, request timeouts,
  connection limits, concurrency limits, and per-identity route rate limits.
- Structured problem responses for denials and upstream failures.

Redaction policy is fail-closed in this connector. If policy evaluation says a
request could proceed only with redaction, the connector denies instead of
rewriting evidence payloads.

## What it is not

The connector is not:

- A Registry Relay replacement.
- A source registry adapter.
- A credential issuer.
- A consent or legal-basis record store.
- A certificate authority or certificate lifecycle manager.
- An X-Road Security Server.
- An X-Road protocol, service metadata, central configuration, operational
  monitoring, message signing, or federation implementation.

Relay, Notary, deployment infrastructure, and any external interoperability
network still own those responsibilities.

## X-Road positioning

The safest wording is:

> Registry Trust Connector is an X-Road-adjacent Registry policy boundary, not
> an X-Road replacement.

That means the connector can be useful in environments that also use X-Road,
but it should not be presented as a smaller X-Road or as X-Road-compatible
infrastructure by itself. X-Road has its own security server, member and
subsystem identity, service metadata, global configuration, operational
monitoring, message exchange semantics, and federation model. This connector
does not implement those surfaces.

In a future X-Road deployment option, the Trust Connector should sit next to
Relay and enforce Registry-specific route, purpose, PDP, and upstream auth
policy. A real X-Road Security Server should remain responsible for X-Road
transport and X-Road conformance.

## Typical deployment modes

Baseline mode uses the connector pair directly between a local client system
and a private Relay. This is the mode covered by the local demo and example
configs.

National PKI or SPIFFE-style mode keeps the same connector shape, but operators
provide their own certificate issuance, trust anchors, key storage, rotation,
and operational controls.

X-Road-adjacent mode adds X-Road infrastructure outside the connector. The exact
placement depends on the deployment, but the responsibility split should stay
clear: X-Road handles X-Road network behavior, and the Trust Connector handles
Registry-specific policy before Relay access.
