---
title: Get started with a local connector pair
doc_type: get started
product: Registry Trust Connector
layer: [consultation, federation, operations]
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: examples/docker-compose.yml, examples/client.openspp.yaml, examples/server.relay.yaml
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE]
---

# Get started with a local connector pair

Use this guide to run the client connector, the server connector, and a mock
Registry Relay on one machine. At the end, you can send requests to
`http://127.0.0.1:7080` and confirm that the connector pair enforces mTLS,
route policy, purpose policy, and upstream authentication injection.

## Prerequisites

- Rust 1.95 or later.
- Docker with Compose support.
- OpenSSL for the development certificate generator.
- A shell that can run the scripts in `examples/`.

The example certificates and tokens are for local development only. Do not use
them in a shared, hosted, or production environment.

## Generate development certificates

```sh
examples/generate-dev-pki.sh
```

The script writes local certificate authority, server, and client certificates
to `examples/certs/`. That directory is ignored by git.

## Validate both configs

```sh
cargo run -- validate --config examples/client.openspp.yaml --mode client
REGISTRY_RELAY_BEARER_TOKEN=dev-replace-me \
REGISTRY_RELAY_DCI_BEARER_TOKEN=dev-replace-me \
  cargo run -- validate --config examples/server.relay.yaml --mode server --require-env
```

The client validation checks that the local client identity certificate is
present and usable for client authentication. The server validation checks that
the server certificate is usable for server authentication, client identities
are bound to trust anchors, routes bind to allowlisted client identities, and
required upstream auth environment variables are present and non-empty.

## Start the local topology

For a scripted demo with assertions, run:

```sh
examples/demo.sh --regenerate-pki
```

To run the topology manually, use Docker Compose:

```sh
cp examples/.env.example examples/.env
docker compose --env-file examples/.env -f examples/docker-compose.yml config
docker compose --env-file examples/.env -f examples/docker-compose.yml build
docker compose --env-file examples/.env -f examples/docker-compose.yml up
```

Keep this shell open while you send the requests below.

## Send a route with a static purpose

```sh
curl -sS \
  "http://127.0.0.1:7080/relay/v1/datasets/social_registry/entities/individual/records?limit=2"
```

The client connector rewrites the local `/relay/...` prefix to the Relay path,
adds the configured static `data-purpose`, and calls the server connector with
mTLS.

## Send a route with a client-provided purpose

```sh
curl -sS \
  -H "data-purpose: https://openspp.example.test/purpose/disability-benefit-intake" \
  -H "content-type: application/json" \
  -d '{"national_id":"DEMO-123"}' \
  "http://127.0.0.1:7080/relay/dci/social/registry/sync/search"
```

The server connector allows this route only when the client certificate
identity matches the route policy and the `data-purpose` value is in the
route's allowed purpose list.

## Stop the local topology

```sh
docker compose --env-file examples/.env -f examples/docker-compose.yml down --remove-orphans
```

## Next steps

- Read [Demo and test environment](demo-test-environment.md) for the demo
  architecture and smoke-test matrix.
- Read [Run the connector](run-the-connector.md) before running the client and
  server processes outside Docker Compose.
- Read [Configuration reference](configuration-reference.md) before writing a
  deployment config.
- Read [Security model](security-model.md) before changing trust anchors,
  identity allowlists, purpose policy, or forwarded headers.
