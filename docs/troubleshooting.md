---
title: Troubleshooting
doc_type: troubleshooting
product: Registry Trust Connector
layer: operations
audience: [operator, integrator, maintainer, tooling]
status: draft
source_of_truth: src/errors.rs, src/config.rs, src/proxy.rs, src/tls.rs
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE]
---

# Troubleshooting

Use these recovery steps when validation, startup, or a request fails. Problem
responses include a stable `code` field. Logs include request status, request
ID, route information when available, and redacted identity hashes.

## Config validation fails

Symptom: `cargo run -- validate ...` exits with an invalid config error.

Cause: the YAML shape, required fields, certificate files, route policy, trust
anchor binding, or required environment variables failed validation.

Resolution:

1. Run validation with an explicit mode:

   ```sh
   cargo run -- validate --config examples/client.openspp.yaml --mode client
   ```

2. For server configs, include `--require-env` when you want to check upstream
   auth variables:

   ```sh
   REGISTRY_RELAY_BEARER_TOKEN=dev-replace-me \
   REGISTRY_RELAY_DCI_BEARER_TOKEN=dev-replace-me \
     cargo run -- validate --config examples/server.relay.yaml --mode server --require-env
   ```

3. Compare the failing field with
   [Configuration reference](configuration-reference.md).
4. For shared and production environments, set `audit.hash_secret_env` and
   export a secret of at least 32 bytes. Use `audit.allow_unkeyed_hashing: true`
   only in local demo configs.

## Client mode refuses to bind

Symptom: validation reports that a non-loopback client listener requires
`allow_non_loopback_client_listen: true`.

Cause: client mode defaults to loopback-only listening so a local connector is
not exposed to the network by accident.

Resolution: set `listen` to a loopback address such as `127.0.0.1:7080`, or set
`allow_non_loopback_client_listen: true` when container or host networking
requires a non-loopback listener.

## TLS handshake fails

Symptom: the client connector cannot connect to the server connector, or server
logs show a TLS handshake failure.

Cause: the server certificate, client certificate, private key, trust bundle,
or trust anchor does not match the configured topology.

Resolution:

1. Regenerate local development certificates for examples:

   ```sh
   examples/generate-dev-pki.sh --force
   ```

2. Validate the client and server configs.
3. Check that `server.trust_bundle` trusts the server connector certificate.
4. Check that `client_trust.trust_anchors[].ca` trusts the client certificate.
5. Check that the client certificate includes the identity listed in
   `client_trust.allowed_identities`.

## `connector.client_identity_denied`

Symptom: server mode returns HTTP 403 with
`code: connector.client_identity_denied`.

Cause: the client certificate identity is not allowlisted, the SPIFFE trust
domain has no matching trust anchor, the DNS SAN fallback is disabled, or the
DNS SAN identity is not bound to the CA that issued it.

Resolution:

1. Prefer a SPIFFE URI SAN identity such as
   `spiffe://openspp.example.test/client/local`.
2. Add the exact identity to `client_trust.allowed_identities`.
3. Add a trust anchor with the matching SPIFFE trust domain.
4. For DNS fallback, set `allow_dns_san_identity: true` and bind the exact DNS
   identity under `client_trust.trust_anchors[].dns_identities`.

## `connector.route_denied`

Symptom: a request returns HTTP 403 with `code: connector.route_denied`.

Cause: no route matched the HTTP method, path prefix, and, in server mode,
client certificate identity.

Resolution:

1. Confirm the route includes the request method.
2. Confirm the path starts with the configured prefix on a segment boundary.
3. In client mode, check `local_prefix` and `upstream_prefix`.
4. In server mode, check `upstream_prefix` and `client_identity`.

## `connector.purpose_required`

Symptom: a request returns HTTP 400 with `code: connector.purpose_required`.

Cause: the matched route requires a non-empty `data-purpose` value, but none
was available.

Resolution:

1. For `purpose_source: client_provided`, send a `data-purpose` header.
2. For `purpose_source: static_route_default`, set `defaults.data_purpose`.
3. In server mode, send the purpose that the route expects.

## `connector.purpose_denied`

Symptom: a request returns HTTP 403 with `code: connector.purpose_denied`.

Cause: the request included `data-purpose`, but the value is not listed in the
matched server route's `purposes`.

Resolution: add the intended purpose to the server route only when that route
and client identity should be allowed to use it.

## `connector.upstream_auth_missing`

Symptom: server mode returns HTTP 500 with
`code: connector.upstream_auth_missing`.

Cause: neither the route nor the upstream default names an auth env var, or the
named env var is missing or empty.

Resolution:

1. Set `upstream.default_auth_header_env`, or set route-level
   `upstream_auth_header_env`.
2. Export the named environment variable before starting server mode.
3. Re-run server validation with `--require-env`.

## `connector.upstream_unavailable`

Symptom: a request returns HTTP 502 with
`code: connector.upstream_unavailable`.

Cause: the private Relay upstream is unreachable, timed out, returned a
response body over `limits.max_body_bytes`, or returned a response body the
connector could not read.

Resolution:

1. Confirm `upstream.base_url` is reachable from the server connector.
2. Confirm the mock Relay or private Relay process is running.
3. Check whether the upstream response body is larger than
   `limits.max_body_bytes`.
4. Increase `limits.upstream_timeout_seconds` only when the upstream normally
   takes longer than the current timeout.

## `connector.body_too_large`

Symptom: a request returns HTTP 413 with `code: connector.body_too_large`.

Cause: the request body exceeded `limits.max_body_bytes`.

Resolution: reduce the request size or raise `limits.max_body_bytes` for both
connector modes that handle the request.
