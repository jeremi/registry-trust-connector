---
title: Run the connector
doc_type: how-to guide
product: Registry Trust Connector
layer: operations
audience: [operator, integrator, maintainer, tooling]
status: draft
source_of_truth: src/main.rs, examples/client.openspp.yaml, examples/server.relay.yaml
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509]
---

# Run the connector

Use these tasks when you already have connector configs, certificate files, and
upstream auth environment variables.

## Validate a client config

```sh
cargo run -- validate --config examples/client.openspp.yaml --mode client
```

Client validation requires:

- `listen` on a loopback address, unless
  `allow_non_loopback_client_listen: true` is set.
- `server.url` and `server.trust_bundle`.
- `client_identity.cert` and `client_identity.key`.
- At least one route with methods, `local_prefix`, and `upstream_prefix`.
- A static default purpose when a route uses
  `purpose_source: static_route_default`.
- `audit.hash_secret_env`, or explicit local-only
  `audit.allow_unkeyed_hashing: true`.

## Validate a server config

```sh
REGISTRY_RELAY_BEARER_TOKEN=dev-replace-me \
REGISTRY_RELAY_DCI_BEARER_TOKEN=dev-replace-me \
  cargo run -- validate --config examples/server.relay.yaml --mode server --require-env
```

Server validation requires:

- `server_identity.cert` and `server_identity.key`.
- `client_trust.allowed_identities`.
- `client_trust.trust_anchors`.
- `upstream.base_url`.
- At least one route with methods, `upstream_prefix`, and `client_identity`.
- Route client identities that are present in
  `client_trust.allowed_identities`.
- Non-empty upstream auth env vars when `--require-env` is set.
- `audit.hash_secret_env` with a non-empty secret of at least 32 bytes, unless
  the config explicitly sets `audit.allow_unkeyed_hashing: true` for local
  development.

## Run client mode

```sh
cargo run -- client --config examples/client.openspp.yaml
```

Client mode validates the config, warns when its certificate is near expiry,
binds the configured TCP listener, and forwards matched local requests to
`server.url` with mTLS.

By default, client mode must listen on a loopback address. Use
`allow_non_loopback_client_listen: true` only when another host or container
must reach the client connector.

## Run server mode

```sh
export REGISTRY_RELAY_BEARER_TOKEN="replace-with-development-token"
export REGISTRY_RELAY_DCI_BEARER_TOKEN="replace-with-development-token"
cargo run -- server --config examples/server.relay.yaml
```

Server mode validates the config with env-var checks enabled, warns when its
certificate is near expiry, binds the configured TCP listener, requires client
mTLS, and forwards authorized requests to `upstream.base_url`.

## Run with Docker Compose

```sh
cp examples/.env.example examples/.env
examples/generate-dev-pki.sh
docker compose --env-file examples/.env -f examples/docker-compose.yml config
docker compose --env-file examples/.env -f examples/docker-compose.yml build
docker compose --env-file examples/.env -f examples/docker-compose.yml up
```

The Compose example starts both connector modes and a mock Relay. Replace the
mock Relay service, development certificates, and dummy token values before
using the topology outside local development. Also replace the demo
`audit.allow_unkeyed_hashing: true` setting with `audit.hash_secret_env`.

## Stop Docker Compose

```sh
docker compose --env-file examples/.env -f examples/docker-compose.yml down --remove-orphans
```
