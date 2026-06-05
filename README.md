---
title: Registry Trust Connector
doc_type: README
product: Registry Trust Connector
layer: [consultation, federation, operations]
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: src/config.rs, src/proxy.rs, src/tls.rs, examples/
last_reviewed: "2026-06-05"
standards_referenced: [TLS, X.509, SPIFFE, RFC 9457]
---

# Registry Trust Connector

Registry Trust Connector is a small policy proxy that lets a local client
system, such as an OpenSPP deployment, call a private Registry Relay through a
mutual Transport Layer Security (mTLS) boundary.

The connector runs in two modes:

- `client`: listens on local HTTP, rewrites configured routes, adds a
  `data-purpose` value when policy requires it, and calls the server connector
  over mTLS.
- `server`: listens on HTTPS with client certificate authentication, verifies
  the client identity, checks route and purpose policy, injects upstream Relay
  authentication from environment variables, and forwards the request to a
  private Registry Relay.

The example topology is:

```text
OpenSPP-style app
  -> http://localhost:7080
  -> Registry Trust Connector client
  -> https://relay-connector.example.gov:9443 with mTLS
  -> Registry Trust Connector server
  -> http://registry-relay:8080 on a private network
```

## Documentation

- [Get started with a local connector pair](docs/get-started.md)
- [Demo and test environment](docs/demo-test-environment.md)
- [Run the connector](docs/run-the-connector.md)
- [Configuration reference](docs/configuration-reference.md)
- [Security model](docs/security-model.md)
- [Standards conformance](docs/standards-conformance.md)
- [Troubleshooting](docs/troubleshooting.md)

## Example files

- [examples/client.openspp.yaml](examples/client.openspp.yaml): local
  OpenSPP-side connector config.
- [examples/server.relay.yaml](examples/server.relay.yaml): Relay-side
  connector config.
- [examples/docker-compose.yml](examples/docker-compose.yml): development-only
  Compose topology for the client connector, server connector, and mock private
  Relay service.
- [examples/relay/mock-relay.py](examples/relay/mock-relay.py): local HTTP
  Relay stub used by the Compose example.
- [examples/generate-dev-pki.sh](examples/generate-dev-pki.sh): local
  development public key infrastructure (PKI) generator.
- [examples/.env.example](examples/.env.example): dummy environment values for
  local experiments.

## Build

```sh
cargo build
```

## Validate

```sh
examples/generate-dev-pki.sh
cargo run -- validate --config examples/client.openspp.yaml --mode client
REGISTRY_RELAY_BEARER_TOKEN=dev-replace-me \
REGISTRY_RELAY_DCI_BEARER_TOKEN=dev-replace-me \
  cargo run -- validate --config examples/server.relay.yaml --mode server --require-env
```

Validation checks config shape, route policy, certificate files, certificate
extended key usage, trust anchor bindings, and, with `--require-env`, required
upstream authentication environment variables.

## Demo

```sh
examples/demo.sh --regenerate-pki
```

The demo starts the local Docker Compose topology, sends allowed and denied
requests through the connector pair, checks stable problem codes, and confirms
that sensitive caller headers are stripped before requests reach the mock Relay.
