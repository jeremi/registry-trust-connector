---
title: CI and security gates
doc_type: reference
product: Registry Trust Connector
layer: operations
audience: [maintainer, operator, security reviewer]
status: draft
source_of_truth: .github/workflows/ci.yml, deny.toml
last_reviewed: "2026-06-05"
standards_referenced: []
---

# CI and security gates

The connector CI checks out `registry-platform` beside this repository because
the connector uses platform crates through local path dependencies and the
Dockerfile uses `registry-platform` as an additional build context.

## Required gates

The `ci` workflow runs these gates on pushes to `main` and on pull requests:

- Rust formatting: `cargo fmt --all -- --check`.
- Rust compilation: `cargo check --locked --all-targets`.
- Rust linting: `cargo clippy --locked --all-targets -- -D warnings`.
- Rust tests: `cargo test --locked --all-targets`.
- Release build: `cargo build --locked`.
- Example PKI generation and config validation for client and server modes.
- Dependency policy: `cargo deny check`.
- Advisory scan:
  `cargo audit --db "$RUNNER_TEMP/cargo-audit-db" --deny warnings --ignore RUSTSEC-2025-0134`.
- Secret scan: `gitleaks dir --no-banner --redact --verbose --timeout 120 .`.
- Docker Compose model validation.
- Docker image build.
- Trivy scan of the locally built connector image for high and critical
  vulnerabilities.

## Dependency policy

`deny.toml` inherits the platform policy shape and adds one documented advisory
ignore:

- `RUSTSEC-2025-0134` for `rustls-pemfile`, reviewed because the connector only
  parses configured PEM files during startup or validation. Revisit before
  accepting dynamic caller-supplied PEM input or when the Rustls ecosystem has a
  maintained replacement.

## Deferred gates

These gates are intentionally not claimed yet:

- CodeQL source analysis. The Rust workflow currently relies on clippy, tests,
  dependency policy, cargo-audit, secret scanning, and container scanning.
- SBOM generation and artifact signing or attestation. Add them when release
  publishing is wired for this repository.
- Commit-SHA pinning for third-party GitHub Actions. Current workflow actions
  are tag-pinned to match the platform repo convention; SHA pinning should be
  handled across public repos together.
