# PledgeGuard — multi-stage Docker image
# Build from source for reproducibility, then copy the binary into a minimal runtime image.

FROM rust:1.82-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release -p pledgeguard-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/pledgeguard /usr/local/bin/pledgeguard

ENTRYPOINT ["pledgeguard"]
CMD ["scan", "."]
