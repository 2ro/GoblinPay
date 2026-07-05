#!/usr/bin/env bash
# Package the WooCommerce connector into a ready-to-upload plugin zip:
#   goblinpay-woocommerce.zip  ->  a single top-level goblinpay-woocommerce/
#
# The shop owner's WooCommerce step is then just Upload Plugin -> Activate ->
# paste the three values the setup wizard printed. No self-zipping, no code
# change to the plugin.
#
# Usage:  deploy/package-woocommerce.sh [OUT_DIR]
#   OUT_DIR defaults to ./dist. The zip is written to OUT_DIR/goblinpay-woocommerce.zip.
#
# Run it from a release workflow or by hand; it needs only `zip`.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_DIR/connectors/woocommerce"
SLUG="goblinpay-woocommerce"
OUT_DIR="${1:-$REPO_DIR/dist}"
ZIP="$OUT_DIR/$SLUG.zip"

if ! command -v zip >/dev/null 2>&1; then
	echo "error: 'zip' is required but not installed" >&2
	exit 1
fi
if [[ ! -f "$SRC/$SLUG.php" ]]; then
	echo "error: plugin entrypoint $SRC/$SLUG.php not found" >&2
	exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Stage the plugin under its slug folder so the zip has one top-level dir (what
# WordPress expects). Ship the plugin code + its install/readme docs; exclude
# nothing else lives here.
mkdir -p "$STAGE/$SLUG"
cp -a "$SRC/." "$STAGE/$SLUG/"

mkdir -p "$OUT_DIR"
rm -f "$ZIP"
( cd "$STAGE" && zip -r -q -X "$ZIP" "$SLUG" )

echo "Wrote $ZIP"
unzip -l "$ZIP" 2>/dev/null | sed 's/^/  /' || true
