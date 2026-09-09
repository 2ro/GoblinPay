# Multi-stage build for the GoblinPay server, run as a non-root user.
#
# Build context is the WORKSPACE PARENT, the directory that holds GoblinPay/.
# docker-compose.yml already sets `build.context: ../..` for this; to build by
# hand:
#
#   cd "<parent directory containing GoblinPay>"
#   docker build -f GoblinPay/deploy/Dockerfile -t goblinpay:latest .
#
# No sibling checkout is required: the NIP-44 v3 companion crate now comes from
# crates.io (`nip44 = "0.3.2"` in crates/gp-nostr/Cargo.toml).
#
# Only `-p gp-server` is built, which EXCLUDES the gp-goblin-sender dev crate
# (it needs the goblin wallet tree, absent on servers). gp-wallet's grin_wallet
# crates are fetched from git during the build.

# ---- builder ----
FROM rust:1-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# The repo itself. Everything the gp-server graph needs beyond it comes from
# crates.io or git.
COPY GoblinPay ./GoblinPay

WORKDIR /build/GoblinPay
# Build ONLY gp-server (and its deps); never the goblin-tree dev crate.
RUN cargo build --release --locked -p gp-server

# ---- runtime ----
FROM debian:bookworm-slim AS runtime
# ca-certificates for outbound TLS (node reads, CoinGecko, relays); curl for the
# healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user; wallet files, seed-at-rest, and the SQLite db live under /data.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin goblinpay \
    && mkdir -p /data \
    && chown -R goblinpay:goblinpay /data

COPY --from=builder /build/GoblinPay/target/release/gp-server /usr/local/bin/gp-server

USER goblinpay
WORKDIR /data
VOLUME ["/data"]

# Bind on all interfaces inside the container (Caddy is the only thing in front);
# keep state under the /data volume. Money/identity secrets are injected at run
# time via the *_FILE mounted-secret variants, never baked into the image.
ENV GP_BIND=0.0.0.0:8080 \
    GP_DB_PATH=/data/goblinpay.db \
    GP_DATA_DIR=/data/gp-data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/gp-server"]
