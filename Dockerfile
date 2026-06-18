# syntax=docker/dockerfile:1.7

# Keep the tag for humans and the digest for reproducible pulls.
FROM rust:1-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

WORKDIR /workspace/registry-trust-connector

COPY --from=registry-platform Cargo.toml Cargo.lock /workspace/registry-platform/
COPY --from=registry-platform crates /workspace/registry-platform/crates
COPY Cargo.toml Cargo.lock README.md ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    CARGO_TARGET_DIR=/workspace/target cargo build --release --locked \
    && mkdir -p /workspace/out \
    && cp /workspace/target/release/registry-trust-connector /workspace/out/registry-trust-connector

# Distroless cc keeps glibc and CA certificates while dropping shell/package tools.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985 AS runtime

COPY --from=builder /workspace/out/registry-trust-connector /usr/local/bin/registry-trust-connector

EXPOSE 7080 9443

ENTRYPOINT ["/usr/local/bin/registry-trust-connector"]
