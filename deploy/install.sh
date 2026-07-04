#!/usr/bin/env bash
# One-command bare-metal bootstrap for the GoblinPay server:
#   - builds the release binary (gp-server only; never the goblin-tree dev crate)
#   - installs it to /usr/local/bin
#   - creates the managed state dir and the 0700 secrets dir
#   - installs an env file from deploy/.env.example (if absent)
#   - installs and enables the hardened systemd unit
#
# Re-runnable: it never overwrites an existing /etc/goblinpay.env.
# Requires: a Rust toolchain (cargo) and root (sudo) for the install steps.
#
# BUILD PREREQUISITE: gp-server's Nostr path depends on the sibling crate
# nip44/ (see crates/gp-nostr/Cargo.toml). It must sit next to this
# repo, exactly as on the deploy host. `-p gp-server` deliberately excludes the
# gp-goblin-sender dev crate, which needs the (absent) goblin wallet tree.
#
# After it finishes, edit /etc/goblinpay.env and drop the secret files into
# /etc/goblinpay/secrets (mnemonic, wallet_password), then:
#   sudo systemctl restart gp-server

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN=/usr/local/bin/gp-server
ENV_FILE=/etc/goblinpay.env
UNIT=/etc/systemd/system/gp-server.service
STATE_DIR=/var/lib/goblinpay
SECRETS_DIR=/etc/goblinpay/secrets

say() { printf '\033[1;33m==>\033[0m %s\n' "$1"; }

if [[ $EUID -ne 0 ]]; then
	SUDO=sudo
else
	SUDO=""
fi

say "Building release binary (cargo build --release --locked -p gp-server)"
( cd "$REPO_DIR" && cargo build --release --locked -p gp-server )

say "Installing binary to $BIN"
$SUDO install -m0755 "$REPO_DIR/target/release/gp-server" "$BIN"

say "Creating state directory $STATE_DIR (0700)"
$SUDO install -d -m0700 "$STATE_DIR"

say "Creating secrets directory $SECRETS_DIR (0700)"
$SUDO install -d -m0700 "$SECRETS_DIR"

if [[ -f "$ENV_FILE" ]]; then
	say "Env file $ENV_FILE already exists — leaving it untouched"
else
	say "Installing env file to $ENV_FILE (EDIT IT: domain, node, tokens)"
	$SUDO install -m0640 "$REPO_DIR/deploy/.env.example" "$ENV_FILE"
fi

say "Installing systemd unit to $UNIT"
$SUDO install -m0644 "$REPO_DIR/deploy/gp-server.service" "$UNIT"

say "Reloading systemd and enabling the service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable gp-server

cat <<EOF

Done. Next steps:
  1. Edit $ENV_FILE — set GP_PUBLIC_URL, GP_NODE_URL, GP_BUNDLED_RELAY_URL,
     GP_API_TOKEN, GP_ADMIN_TOKEN (and GP_WEBHOOK_URL/GP_WEBHOOK_SECRET if used).
  2. Write the wallet secrets (root-owned, mode 0400):
       sudo install -m0400 /dev/stdin $SECRETS_DIR/mnemonic <<<'your 24 words'
       sudo install -m0400 /dev/stdin $SECRETS_DIR/wallet_password <<<'your password'
  3. Run the bundled relay (deploy/docker-compose.yml) or point
     GP_BUNDLED_RELAY_URL at a relay you control, and put a TLS reverse proxy
     in front (see deploy/Caddyfile).
  4. Start it:  $SUDO systemctl start gp-server
  5. Check it:  curl -s http://127.0.0.1:8080/health
EOF
