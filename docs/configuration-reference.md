---
title: Configuration reference
doc_type: reference
product: Registry Trust Connector
layer: [consultation, federation, operations]
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: src/config.rs
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE]
---

# Configuration reference

The connector reads one YAML file. The source of truth for accepted fields,
defaults, and validation rules is `src/config.rs`. Unknown YAML fields are
rejected.

## Top-level fields

| Field | Type | Default | Modes | Description |
| --- | --- | --- | --- | --- |
| `listen` | TCP socket string or Unix socket string | Required | client, server | Listener address. TCP listeners are implemented. Unix socket listeners are schema-level only in this MVP and fail at runtime. |
| `server` | object | None | client | Server connector URL and trust bundle for the mTLS client. |
| `client_identity` | object | None | client | Client certificate and private key. The certificate must be valid for client authentication. |
| `defaults` | object | `{}` | client, server | Shared defaults. Currently only `data_purpose`. |
| `limits` | object | See [limits](#limits) | client, server | Request size, upstream timeout, and certificate expiry warning settings. |
| `routes` | array | Required | client, server | Route policy. The array must not be empty. |
| `server_identity` | object | None | server | Server certificate and private key. The certificate must be valid for server authentication. |
| `client_trust` | object | None | server | Client identity allowlist and trust anchors. |
| `upstream` | object | None | server | Private Relay upstream URL and auth header settings. |
| `allow_non_loopback_client_listen` | boolean | `false` | client | Allows client mode to bind a non-loopback TCP listener. |
| `allow_dns_san_identity` | boolean | `false` | server | Allows DNS subject alternative name (SAN) fallback for client certificates. SPIFFE URI identities are preferred. |
| `connector_id` | string | None | client, server | Optional connector identifier used in connector metadata headers and logs. |

## Listener

`listen` accepts a TCP socket address such as:

```yaml
listen: "127.0.0.1:7080"
```

Client mode rejects non-loopback listeners unless
`allow_non_loopback_client_listen: true` is set.

## Server

Client mode requires `server`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | URL | Required | HTTPS URL for the server connector. |
| `trust_bundle` | path | Required | Certificate authority bundle used to verify the server connector certificate. |

## Identity files

`client_identity` and `server_identity` use the same shape:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `cert` | path | Required | PEM certificate path. |
| `key` | path | Required | PEM private key path. |

Client mode requires `client_identity` and validates the certificate for client
authentication. Server mode requires `server_identity` and validates the
certificate for server authentication.

## Defaults

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `data_purpose` | string | None | Static purpose used by client routes with `purpose_source: static_route_default`. |

## Limits

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `max_body_bytes` | integer | `1048576` | Maximum request body size in bytes. Requests over the limit return `connector.body_too_large`. |
| `upstream_timeout_seconds` | integer | `30` | Upstream request timeout. The value must be greater than zero. |
| `expiry_warning_days` | integer | `30` | Certificate expiry warning threshold in days. Negative values are treated as zero for warning calculations. |

## Client trust

Server mode requires `client_trust`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed_identities` | array of strings | Required | Exact client identities allowed to call the server connector. |
| `trust_anchors` | array of objects | Required | Trust anchors that bind identities to certificate authorities. |

Each trust anchor has:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `ca` | path | Required | PEM certificate authority. Each file must contain one CA certificate. |
| `trust_domain` | string | Required | SPIFFE trust domain bound to this CA. |
| `dns_identities` | array of strings | `[]` | DNS SAN identities bound to this CA when DNS fallback is enabled. |

For SPIFFE identities, the trust domain from the identity must have a matching
trust anchor. For DNS identities, `allow_dns_san_identity: true` must be set and
the identity must appear in at least one `trust_anchors[].dns_identities` list.

## Upstream

Server mode requires `upstream`:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `base_url` | URL | Required | Private Relay base URL. |
| `default_auth_header_env` | string | None | Environment variable that provides the default upstream auth secret. |
| `auth_header_name` | string | `Authorization` | Header name used for upstream auth injection. Hop-by-hop headers and `x-registry-connector-*` names are rejected. |
| `auth_header_scheme` | string | `Bearer` | Prefix used before the env-var secret. Set to an empty string to send the secret as the complete header value. |

Route-level `upstream_auth_header_env` overrides
`upstream.default_auth_header_env`.

## Routes

Each route has:

| Field | Type | Default | Modes | Description |
| --- | --- | --- | --- | --- |
| `id` | string | Required | client, server | Unique route identifier. |
| `methods` | array of HTTP methods | Required | client, server | HTTP methods that match the route. |
| `local_prefix` | string | Required in client mode | client | Local path prefix accepted by the client connector. |
| `upstream_prefix` | string | Required | client, server | Upstream path prefix. Client mode rewrites `local_prefix` to this prefix. Server mode matches this prefix. |
| `require_purpose` | boolean | `false` | client, server | Requires a non-empty `data-purpose` value. |
| `purpose_source` | `client_provided`, `static_route_default`, or `denied_missing` | `denied_missing` when purpose is required | client | Defines how client mode obtains the `data-purpose` value. |
| `client_identity` | string | Required in server mode | server | Exact client identity allowed for this route. Must be in `client_trust.allowed_identities`. |
| `upstream_auth_header_env` | string | None | server | Route-specific env var for upstream auth injection. |
| `forward_client_identity_header` | boolean | `false` | server | Adds `x-registry-connector-client-identity` to the upstream request after mTLS authorization. |
| `purposes` | array of strings | `[]` | server | Allowed purpose values for the route. Empty strings are rejected. |
| `allow_forward_authorization` | boolean | `false` | client, server | Allows caller-supplied `Authorization` to pass through header filtering. Server mode still injects the configured upstream auth header after filtering. |
| `allow_forward_cookie` | boolean | `false` | client, server | Allows caller-supplied `Cookie` to pass through header filtering. |

Route prefixes must start with `/`, must not contain invalid percent encoding,
and must not contain decoded `.` or `..` path segments. Prefix matching is
segment-aware, so `/relay/v1` matches `/relay/v1/records` but not
`/relay/v10`.

## Header policy

The connector strips these request headers before forwarding:

- Hop-by-hop headers, including headers named by the `Connection` header.
- `Authorization`, unless the route sets `allow_forward_authorization: true`.
- `Cookie`, unless the route sets `allow_forward_cookie: true`.
- All headers with the `x-registry-connector-*` prefix.

The connector strips hop-by-hop response headers before returning upstream
responses to callers.

## Problem responses

Policy denials and upstream failures return problem responses with a stable
`code` field.

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `connector.config_invalid` | 500 | Runtime config state is invalid. |
| `connector.client_identity_missing` | 401 | A server-mode request did not include a client certificate chain. |
| `connector.client_identity_denied` | 403 | The client certificate identity or trust anchor binding was denied. |
| `connector.route_denied` | 403 | No route matched the method, path, and server-mode client identity. |
| `connector.purpose_required` | 400 | A required `data-purpose` value was missing or empty. |
| `connector.purpose_denied` | 403 | The provided `data-purpose` was not allowed for the server route. |
| `connector.upstream_auth_missing` | 500 | Required upstream auth environment variable was missing or empty. |
| `connector.upstream_unavailable` | 502 | The connector could not reach the upstream or read its response. |
| `connector.body_too_large` | 413 | The request body exceeded `limits.max_body_bytes`. |

## Example

Use the checked-in example configs as runnable references:

- [Client example config](../examples/client.openspp.yaml)
- [Server example config](../examples/server.relay.yaml)
