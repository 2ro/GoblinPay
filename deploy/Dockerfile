# Multi-stage build for the GoblinPay server, run as a non-root user.
#
# IMPORTANT — build context is the WORKSPACE PARENT, not the repo.
# The Nostr/Nym money path depends on two crates that live next to this repo,
# not inside it (see crates/gp-nostr/Cargo.toml):
#   nip44  -> ../nip44          (the NIP-44 v3 companion crate)
#   smolmix-> ../nym/smolmix/core (the in-process Nym mixnet)
# So the image must be built from the directory that contains GoblinPay/,
# nip44/, and nym/ side by side. docker-compose.yml already sets
# `build.context: ../..` for this; to build by hand:
#
#   cd "<workspace parent containing GoblinPay, nip44, nym>"
#   docker build -f GoblinPay/deploy/Dockerfile -t goblinpay:latest .
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

# The three trees the gp-server dependency graph needs, in the same relative
# layout the path deps expect (nip44 and nym are siblings of GoblinPay).
COPY GoblinPay ./GoblinPay
COPY nip44 ./nip44
COPY nym ./nym

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
