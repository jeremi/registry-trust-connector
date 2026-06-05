---
title: Standards conformance
doc_type: standards conformance statement
product: Registry Trust Connector
layer: federation
audience: [integrator, operator, maintainer, specification editor, tooling]
status: draft
source_of_truth: src/tls.rs, src/identity.rs, src/errors.rs, src/proxy.rs
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE, RFC 9457]
---

# Standards conformance

Registry Trust Connector uses external standards at specific boundaries. These
statements do not claim full conformance for systems on either side of the
connector.

## TLS

Adoption mode: adapted.

The connector uses TLS for the server-side connector listener and for the
client connector's outbound call to the server connector. Server mode requires
client certificate authentication. Client mode disables built-in public roots
for the server connector call and uses the configured `server.trust_bundle`.

The connector does not define a public certificate authority profile, rotation
procedure, or deployment key-management standard.

## X.509

Adoption mode: profiled.

The connector uses X.509 certificate chains for mTLS. Config validation checks
that client identities are usable for client authentication and server
identities are usable for server authentication.

Server trust anchors are configured explicitly in
`client_trust.trust_anchors`. Each trust anchor binds a certificate authority
to a SPIFFE trust domain and, when DNS fallback is enabled, to specific DNS SAN
identities.

The MVP expects each trust anchor file to contain one CA certificate. Operators
can deny a specific leaf certificate by adding its SHA-256 fingerprint to
`client_trust.denied_certificate_fingerprints_sha256`. The connector does not
implement certificate revocation list or Online Certificate Status Protocol
checks.

## SPIFFE

Adoption mode: profiled.

SPIFFE URI SAN identities are the preferred client identity format. Server mode
extracts the trust domain from identities in the form
`spiffe://<trust-domain>/<path>` and verifies that the presented certificate
chains to a configured trust anchor for that trust domain.

The connector does not implement SPIFFE Workload API integration, SPIRE
registration, SVID issuance, or bundle federation. Operators provide
certificate files and trust anchor files through config.

## DNS SAN fallback

Adoption mode: adapted.

DNS SAN identity fallback exists for deployments that cannot issue SPIFFE URI
SAN certificates yet. It is disabled unless `allow_dns_san_identity: true` is
set. A DNS identity must be both allowlisted in
`client_trust.allowed_identities` and bound to a trust anchor through
`client_trust.trust_anchors[].dns_identities`.

Use SPIFFE URI identities when you can. Use DNS fallback only as a constrained
compatibility profile.

## Problem details

Adoption mode: adapted.

The connector returns structured problem responses for policy denials and
upstream failures. Each response includes a stable `code` field such as
`connector.route_denied` or `connector.purpose_required`.

The exact problem object is produced through `registry-platform-httpsec`.
Consumers should depend on the `code` field and HTTP status documented in
[Configuration reference](configuration-reference.md#problem-responses).
