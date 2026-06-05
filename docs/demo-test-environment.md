---
title: Demo and test environment
doc_type: how-to guide
product: Registry Trust Connector
layer: [consultation, federation, operations]
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: examples/demo.sh, examples/docker-compose.yml, examples/relay/mock-relay.py
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE]
---

# Demo and test environment

Use the demo environment to show the connector's core behavior with local
containers and synthetic data. The same script is also a smoke test for the
example configs, development certificates, Docker image, mTLS path, route
policy, purpose policy, upstream auth injection, and header filtering.

## Environment design

The demo topology has three services:

| Service | Network exposure | Role |
| --- | --- | --- |
| `rtc-openspp-client` | `127.0.0.1:7080` through the host port binding | Accepts local HTTP requests and calls the server connector with mTLS. |
| `rtc-relay-server` | `9443` inside the Compose network and host port binding | Verifies client mTLS, authorizes route and purpose policy, injects upstream auth, and forwards to Relay. |
| `registry-relay` | Private Compose network only | Mock private Relay that returns synthetic records and sanitized evidence about received headers. |

The demo uses two Compose networks:

- `trust-connector`: connects the client and server connector.
- `relay-private`: connects only the server connector and mock Relay.

The Compose model binds published ports to `127.0.0.1`, pins the mock Relay
image by digest, runs services as a non-root UID, drops Linux capabilities,
sets `no-new-privileges`, uses read-only filesystems, and caps process counts.

The mock Relay never receives real secrets. It reports whether an
`Authorization` header was present and which auth scheme was used, but it does
not echo token values.

The example connector configs set `audit.allow_unkeyed_hashing: true` so the
demo can run without a secret manager. Replace that with `audit.hash_secret_env`
before using the topology outside local development.

## Run the automated demo

```sh
examples/demo.sh --regenerate-pki
```

The script:

1. Creates `examples/.env` from `examples/.env.example` when needed.
2. Generates local development public key infrastructure (PKI) under
   `examples/certs/`.
3. Validates the client and server configs.
4. Validates the Docker Compose model.
5. Builds the connector image.
6. Starts the client connector, server connector, and mock Relay.
7. Sends allowed and denied requests through `http://127.0.0.1:7080`.
8. Asserts the expected response bodies, status codes, and problem codes.
9. Stops the Compose topology unless `--keep-running` is set.

## Keep the demo running

```sh
examples/demo.sh --keep-running
```

When the script completes, try a manual request:

```sh
curl -sS \
  "http://127.0.0.1:7080/relay/v1/datasets/social_registry/entities/individual/records?limit=2"
```

Stop the topology when finished:

```sh
docker compose --env-file examples/.env -f examples/docker-compose.yml down --remove-orphans
```

## Reuse an existing image

```sh
examples/demo.sh --skip-build
```

Use `--skip-build` when `registry-trust-connector:dev` already exists locally
and you only want to rerun the smoke checks.

## Smoke-test matrix

| Flow | Expected result | What it demonstrates |
| --- | --- | --- |
| GET `/relay/v1/datasets/social_registry/entities/individual/records?limit=2` | HTTP 200 | Client route rewrite, static purpose injection, mTLS to server, server route authorization, upstream auth injection. |
| POST `/relay/dci/social/registry/sync/search` with allowed `data-purpose` | HTTP 200 | Client-provided purpose forwarding and server-side purpose allowlist. |
| POST search without `data-purpose` | HTTP 400 with `connector.purpose_required` | Client route requires a purpose before forwarding. |
| POST search with a purpose outside the server route list | HTTP 403 with `connector.purpose_denied` | Server purpose policy denies mismatched purpose values. |
| GET `/relay/not-configured` | HTTP 403 with `connector.route_denied` | Unknown local paths do not reach Relay. |
| GET with caller `Authorization`, `Cookie`, and spoofed `x-registry-connector-*` headers | HTTP 200, Relay evidence shows stripped caller headers | Sensitive and connector-private headers are minimized before forwarding. |

## Demo limitations

The demo uses synthetic certificates, synthetic records, dummy tokens, and a
mock Relay. It proves the local connector behavior and example topology. It
does not prove integration with a deployed Registry Relay, OpenSPP deployment,
production certificate authority, secret manager, network policy, or log
pipeline.
