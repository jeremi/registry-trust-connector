---
title: Registry Trust Connector documentation
doc_type: landing
product: Registry Trust Connector
layer: [consultation, federation, operations]
audience: [integrator, operator, maintainer, tooling]
status: draft
source_of_truth: ../README.md, architecture-overview.md, configuration-reference.md
last_reviewed: "2026-06-19"
standards_referenced: [TLS, X.509, SPIFFE, RFC 9457, X-Road]
---

# Registry Trust Connector documentation

Registry Trust Connector is a small governed proxy for Registry Relay access. It
adds an mTLS boundary, checks caller identity, applies route and purpose policy,
filters sensitive headers, and forwards authorized requests to a private Relay.

It is not an X-Road Security Server and does not replace X-Road. In an X-Road
deployment, X-Road remains the transport and federation layer; the Trust
Connector can sit beside Relay as a Registry-specific policy gate.

## Start here

- [Architecture overview](architecture-overview.md): what the connector is,
  what it enforces, and how it relates to X-Road.
- [Get started with a local connector pair](get-started.md): generate demo PKI,
  validate configs, start the demo topology, and send test requests.
- [Run the connector](run-the-connector.md): validate and run client or server
  mode outside the guided demo.

## Configure and operate

- [Configuration reference](configuration-reference.md): accepted YAML fields,
  validation rules, route policy, governed policy, header behavior, and problem
  responses.
- [Security model](security-model.md): trust boundary, identity binding, route
  and purpose authorization, header minimization, limits, and out-of-scope
  controls.
- [Demo and test environment](demo-test-environment.md): local Compose topology,
  smoke tests, and demo limitations.
- [Troubleshooting](troubleshooting.md): common validation, TLS, routing,
  purpose, upstream auth, and size-limit failures.

## Maintain

- [Standards conformance](standards-conformance.md): how the connector profiles
  TLS, X.509, SPIFFE, DNS SAN fallback, RFC 9457 problem details, and X-Road
  positioning.
- [CI and security gates](ci-security-gates.md): required checks, dependency
  policy, and deferred gates.

