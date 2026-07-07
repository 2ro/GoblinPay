#!/usr/bin/env bash
# One-command bare-metal bootstrap for the GoblinPay server:
#   - builds the release binary (gp-server only; never the goblin-tree dev crate)
#   - installs it to /usr/local/bin
#   - creates the managed state dir and the 0700 secrets dir
#   - installs and enables the hardened systemd unit
#   - offers to run the setup wizard (`gp-server setup`), which writes the env
#     file + the wallet-password credential and creates the encrypted wallet
#
# Re-runnable: it installs the binary/unit idempotently and never overwrites an
# existing /etc/goblinpay.env (the wizard has its own --reconfigure guard).
# Requires: a Rust toolchain (cargo) and root (sudo) for the install steps.
#
# BUILD PREREQUISITE: gp-server's Nostr path depends on the sibling crate
# nip44/ (see crates/gp-nostr/Cargo.toml). It must sit next to this
# repo, exactly as on the deploy host. `-p gp-server` deliberately excludes the
# gp-goblin-sender dev crate, which needs the (absent) goblin wallet tree.

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

say "Installing systemd unit to $UNIT"
$SUDO install -m0644 "$REPO_DIR/deploy/gp-server.service" "$UNIT"

say "Reloading systemd and enabling the service"
$SUDO systemctl daemon-reload
$SUDO systemctl enable gp-server

# Offer the setup wizard: it writes $ENV_FILE + the wallet-password credential
# and creates the encrypted wallet, so the operator answers a few questions
# instead of hand-editing env vars and inventing tokens.
say "GoblinPay is installed."
if [[ -f "$ENV_FILE" ]]; then
	cat <<EOF

An existing $ENV_FILE was found, so setup is not run automatically.
To reconfigure:  $SUDO gp-server setup --reconfigure
To start:        $SUDO systemctl start gp-server
EOF
	exit 0
fi

run_setup=no
if [[ -t 0 ]]; then
	read -r -p "$(printf '\033[1;33m==>\033[0m Run the setup wizard now? [Y/n] ')" reply || reply=""
	case "${reply:-y}" in
		[Nn]*) run_setup=no ;;
		*) run_setup=yes ;;
	esac
fi

if [[ "$run_setup" == yes ]]; then
	$SUDO gp-server setup
	echo
	echo "When you are ready:  $SUDO systemctl start gp-server"
else
	cat <<EOF

Skipped the wizard. Finish setup either way:
  Guided (recommended):  $SUDO gp-server setup
  By hand (advanced):    copy deploy/.env.example to $ENV_FILE and edit it, then
                         deliver the wallet password. Prefer ENCRYPTED at rest:
                           printf '%s' 'YOUR-PASSWORD' | $SUDO systemd-creds encrypt \\
                             --name=gp_wallet_password - $SECRETS_DIR/wallet_password.cred
                         and switch the unit to LoadCredentialEncrypted (see
                         deploy/gp-server.service). Or fall back to a 0400 plaintext
                         $SECRETS_DIR/wallet_password. Bootstrap the wallet once with
                         GP_MNEMONIC_FILE (a file, never the inline env var), then
                         remove it.
Then start it:  $SUDO systemctl start gp-server
Check it:       curl -s http://127.0.0.1:8080/health
EOF
fi
