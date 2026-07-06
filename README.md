# GoblinPay

A self-hostable, receive-only Grin payment server. A merchant runs it, a
customer pays from Goblin Wallet by scanning a QR code, and the payment
travels as a gift-wrapped slatepack over Nostr. GoblinPay auto-receives,
returns the S2 reply so the payer can finalize, then confirms the
transaction on chain. An invoice moves through three states: `open` ->
`paid` (the payment has been received) -> `confirmed` (the paying kernel
reaches the house standard of 10 confirmations, set by `GP_CONFIRMATIONS`).

Beyond the core wallet + transport + on-chain confirmation path, GoblinPay
carries the full merchant surface:

- **Invoices + matching:** create an invoice against an order, matched by
  any of three modes (per-invoice override or the `GP_MATCH_MODE` default):
  the payer's memo, a per-invoice derived Nostr identity (a stateless child of
  the server nsec, recommended for stores), or an exact amount. The matcher
  runs inside the ingest pipeline, so a gift-wrapped payment resolves to its
  invoice automatically.
- **Hosted checkout:** a zero-JS `/pay/<token>` page (server-rendered
  Askama + one CSS file + a server-generated QR SVG at ECC level H) with a
  GoblinPay wordmark header and live status via `<meta http-equiv=refresh>`.
  The QR is plain by default; a center logo can be overlaid opt-in via
  `GP_QR_LOGO`. As a payment settles, the page shows its live confirmation
  progress ("Confirming n of 10"). It offers two ways to pay:
  - **Goblin Wallet (Nostr):** scan the `nprofile` QR (or copy it) and the
    payment auto-receives over Nostr.
  - **Slatepack (manual paste):** an address-less offline fallback, no Nostr
    needed. Create an S1 for the invoice amount in any Grin wallet, paste it
    into the page (offline `receive_tx`), then copy the returned S2 back into
    your wallet to finalize and broadcast it. The existing invoice matcher and
    on-chain confirmation handle the received payment like any other.

  The same renderer serves embedded and hosted use.
- **Per-user endpubs:** an admin assigns one receiving identity per user
  (a derived child keyed by `(user_id, epoch)`; only public keys and the
  rotation clock are stored, never private keys), with optional rolling rotation
  and an overlap window so a just-rotated endpub still lands. All funds still
  land in the one Grin wallet.
- **Notifications (all optional):** an HMAC-signed, idempotent, retried
  HTTP webhook (the WooCommerce contract), an authenticated admin dashboard +
  JSON API, and NIP-17 DMs to the merchant / payer.

GoblinPay reaches its relays over clearnet. That is a supported posture for a
receive-only till: the sender privacy that matters belongs to the paying
customer and rides their own Goblin Wallet's transport, not GoblinPay's, and the
payload stays gift-wrapped end to end regardless of the pipe it travels through.
An operator who wants to hide GoblinPay's own server-to-relay hop as well can
front it with their own network privacy. Encryption negotiates NIP-44 v3 (the
NIP-17 extension, via the companion `nip44` crate) per recipient, with v2 as the
mandatory baseline.

## Workspace

| Crate | Purpose |
|---|---|
| `crates/gp-wallet` | Grin wallet handoff: open from mnemonic, S1 -> `receive_tx` -> S2 (offline) |
| `crates/gp-goblin-sender` | Test-only gate helper: sends and finalizes with Goblin's wallet stack |
| `crates/gp-nostr` | Nostr transport: identity, gift wrap (NIP-44 v2/v3), ingest |
| `crates/gp-core` | Domain core: config, SQLite persistence (sqlx, raw SQL) |
| `crates/gp-server` | Actix-Web binary: routes, Askama templates, rustls TLS |

Supporting directories: `migrations/` (raw sqlx SQL), `templates/` (Askama,
zero JS), `static/` (one hand-written CSS file, no build step).

## Setup (recommended path)

The fastest way to stand up a till is the built-in wizard. Install the binary
and unit (`deploy/install.sh` does this and then offers to run the wizard for
you), then:

```
sudo gp-server setup
```

On a fresh box you can skip even that: running `gp-server` with no configuration
in an interactive terminal starts this same wizard automatically and then boots
from what it wrote. An already-configured install (or a non-interactive run) is
unaffected and starts headless exactly as before.

It asks a few questions, each with a default. It is grin-wallet-faithful about
the two things that are yours to own — your wallet password and your seed:

1. the public URL customers reach this till at,
2. your shop's website URL (used to build the webhook URL),
3. the local listen address (default `127.0.0.1:8080`; keep it loopback behind
   your reverse proxy),
4. the Grin node for confirmations and balance (press Enter to auto-pick a
   healthy node from the curated list, or enter your own `https://` node),
5. **your wallet password**: you choose it, entered twice and confirmed to
   match (hidden input; it is never auto-generated). It encrypts the seed at
   rest and is not recoverable, so if you forget it you restore from the seed;
6. **the Grin seed**: press Enter to generate a fresh 24-word seed, which is
   shown once and gated behind an acknowledgement that you wrote it down (exactly
   like `grin-wallet init`), or paste your existing recovery phrase;
7. **restart mode**: how the till comes back after a reboot (default
   **unattended**; see below);
8. the currencies your shop prices in (default `usd`),
9. an advanced yes/no for the grin1/Tor rail (default no).

Everything else it does for you:

- generates the *service* secrets — the API token, the admin token, and the
  webhook secret (you never invent or type a bearer token); the wallet password
  is the one secret you choose;
- creates the encrypted wallet on the spot from the seed, so the seed is
  consumed once and never lives in the service environment afterwards (it
  exists only encrypted at rest and in your written backup);
- when you accept the node default, probes a curated list of healthy mainnet
  Grin nodes and picks the first that answers, falling back automatically;
- defaults the relays to an external vetted pool (the wallet's proven relays);
- writes `/etc/goblinpay.env` (mode 0640, holds the config plus the bearer
  tokens) exactly where the shipped `gp-server.service` looks (`EnvironmentFile`),
  and — in unattended mode — `/etc/goblinpay/secrets/wallet_password` (mode 0400)
  where its `LoadCredential` reads it;
- prints the webhook URL and the three values to paste into WooCommerce
  (GoblinPay URL, API Token, Webhook Secret) plus the private admin token.

### Restart mode: unattended (default) or manual

The wizard asks how the till should restart after a reboot; press Enter for the
default. Both are honest about their trade-off:

- **Unattended (default).** Your chosen password is sealed to *this host* as a
  systemd credential (the 0400 file above), so the service auto-restarts with no
  human in the loop. Be clear-eyed about the trade-off: whoever fully controls
  this machine controls the wallet. Treat the till as a small hot wallet — hold
  only a working balance and sweep to your own wallet regularly (see *Secrets and
  the wallet seed*).
- **Manual.** The password lives only in your head; nothing sensitive is written
  to disk. The wizard drops in `gp-server.service.d/manual.conf`, which repoints
  the credential to a tmpfs path (`/run/goblinpay/wallet_password`). You supply
  the password at each start (and after every reboot):

  ```
  sudo install -d -m0700 /run/goblinpay
  systemd-ask-password "GoblinPay wallet password:" \
    | sudo install -m0400 /dev/stdin /run/goblinpay/wallet_password
  sudo systemctl daemon-reload && sudo systemctl start gp-server
  ```

  `/run` is tmpfs, so the password vanishes on reboot: a stolen or powered-off
  disk holds no wallet key. The service will not come back on its own until you
  re-enter it. Maximum protection against disk/machine theft, at the cost of
  hands-on restarts.

Re-running is safe: the wizard refuses to overwrite an existing wallet or config
unless you pass `--reconfigure` (which keeps the existing seed and password — the
money — untouched and never re-prompts for them, only rewriting the config/tokens).
A reconfigure keeps your current restart mode by default: the prompt shows it as
the default so pressing Enter preserves it, and you pick the other option to
switch.
Flags: `--reconfigure`, `--prefix DIR` (write under a prefix instead of `/`),
`--node URL` (skip the node probe), `--batch` (read scripted answers from a
non-terminal stdin).

The env-var reference below is the advanced path for operators who want to
configure GoblinPay by hand; the wizard hides all of it.

## Configuration

Everything is environment variables, defaults are safe for local use.

| Variable | Default | Meaning |
|---|---|---|
| `GP_BIND` | `127.0.0.1:8080` | Listen address |
| `GP_TLS` | `off` | `off` (plain HTTP) or `rustls` (in-process TLS) |
| `GP_TLS_CERT` | unset | PEM certificate chain path, required for `rustls` |
| `GP_TLS_KEY` | unset | PEM private key path, required for `rustls` |
| `GP_DB_PATH` | `./goblinpay.db` | SQLite file, created on first start |
| `GP_DATA_DIR` | `./gp-data` | Data directory (wallet files, encrypted seed) |
| `GP_NODE_URL` | `https://main.gri.mw` | External Grin node (read only) |
| `GP_CHAIN` | `mainnet` | Grin network: `mainnet` or `testnet` |
| `GP_RELAY_MODE` | `bundled` | `bundled` (GoblinPay runs its own co-located relay) or `external` |
| `GP_BUNDLED_RELAY_URL` | `ws://127.0.0.1:7777` | In `bundled` mode, the self-contained relay GoblinPay dials AND advertises in the checkout `nprofile`; set to the relay's public `wss://` URL in production |
| `GP_RELAYS` | `relay.floonet.dev, offchain.pub` | Relay URLs (comma separated): redundancy in `bundled` mode, the whole set in `external` mode. The wizard writes this vetted pair; unset in the environment it defaults empty (fine in `bundled` mode, which uses the co-located relay) |
| `GP_INGEST` | `on` | Nostr ingest service (`off` = HTTP surface only, for debugging) |
| `GP_CHECKOUT_METHODS` | `nostr,slatepack` | Which payment methods the hosted `/pay/<token>` page shows: comma list of `nostr` (Goblin Wallet) and `slatepack` (manual paste). Unset = both. Unknown tokens are ignored; an empty result falls back to both |
| `GP_CONFIRMATIONS` | `10` | House standard: on-chain depth the paying kernel must reach before an invoice flips from `paid` to `confirmed` |
| `GP_GRIN1_RAIL` | `off` | Operator opt-in grin1/Tor rail. `on` = the till also accepts payments from any Grin wallet over Tor: an onion service (identity = the till's grin1 slatepack address key, so grin1 address == onion address) serves the Grin Foreign API v2, invoices carry a native Grin invoice slatepack, and the pay page gains a two-rail switcher (Goblin stays the default tab). Off/unset = Goblin/Nostr only, byte-for-byte the pre-rail behavior |
| `GP_GRIN1_FOREIGN_PORT` | `3416` | Loopback port the Foreign API v2 binds; the onion service proxies `onion:80` to it (only used with `GP_GRIN1_RAIL=on`) |
| `GP_MATCH_MODE` | `memo` | Default matching mode: `memo`, `derived`, `amount` |
| `GP_MNEMONIC` | unset | Grin seed mnemonic (money secret). Needed only to create the wallet on first run; once the encrypted seed exists, boot needs only `GP_WALLET_PASSWORD` and you should remove this |
| `GP_WALLET_PASSWORD` | unset | Password encrypting the wallet seed and the Nostr identity at rest |
| `GP_NSEC` | unset | Nostr identity key (payment identity secret) |
| `GP_NCRYPTSEC` | unset | NIP-49 encrypted identity key (unlocked with the wallet password) |
| `GP_PUBLIC_URL` | `http://<bind>` | Public base URL for the hosted `/pay/<token>` links |
| `GP_API_TOKEN` | unset | Bearer token for the connector/create-invoice API (unset = write API closed) |
| `GP_ADMIN_TOKEN` | unset | Bearer token for the admin dashboard + endpub/webhook API |
| `GP_WEBHOOK_URL` | unset | Webhook endpoint for payment events (requires `GP_WEBHOOK_SECRET`) |
| `GP_WEBHOOK_SECRET` | unset | HMAC-SHA256 secret for signing webhooks |
| `GP_QR_LOGO` | off | Checkout QR center logo: unset/`off`/`none` = plain QR (default), `builtin` = inline Goblin mark, else an image URL |
| `GP_MERCHANT_NPUB` | unset | Merchant npub for the NIP-17 confirmed-payment DM |
| `GP_NOTIFY_MERCHANT_DM` | `off` | Send a NIP-17 DM to the merchant on a received payment |
| `GP_NOTIFY_PAYER_RECEIPT` | `off` | Send a NIP-17 receipt DM to the payer |
| `GP_ENDPUB_ROTATE_INTERVAL` | `0` | Default per-user endpub rotation interval in seconds (0 = off) |
| `GP_ENDPUB_OVERLAP_EPOCHS` | `1` | Past epochs kept watched after a rotation |
| `GP_RATE_SOURCE` | `coingecko` | Conversion-rate oracle source for pricing fiat invoices |
| `GP_RATE_CURRENCIES` | `usd` | Comma-separated fiat currencies the oracle prices (ISO codes) |
| `GP_RATE_CACHE_TTL` | `60` | Seconds a fetched rate is reused before refetching (0 = always) |
| `GP_QUOTE_TTL` | `900` | Seconds a created fiat invoice locks its Grin quote (its expiry window) |
| `GP_RATE_STALE_MAX` | `0` | Bounded stale-rate fallback in seconds if a live fetch fails (0 = off) |

### Checkout methods

`GP_CHECKOUT_METHODS` only controls what the hosted `/pay/<token>` page
advertises to a payer; it does not turn any payment processing on or off. The
Slatepack method also needs a loaded wallet to appear (it runs `receive_tx`), so
an enabled method that cannot work is simply hidden. Keep this consistent with `GP_INGEST`:
`GP_INGEST` runs the Nostr ingest service that actually receives and matches
Goblin Wallet payments, so `GP_INGEST=off` with `GP_CHECKOUT_METHODS=nostr`
would advertise a Nostr method that nothing is listening for. If you disable
ingest, drop `nostr` from `GP_CHECKOUT_METHODS`; if you advertise `nostr`, keep
ingest on. The connector `POST /invoice` JSON response still returns the
`nprofile` regardless of this setting, which affects only the hosted page.

### The grin1 rail (optional)

Off by default. `GP_GRIN1_RAIL=off` (the packaged default) runs no Tor code at
all, and the hosted pay page shows only the Goblin (Nostr) rail: byte-for-byte
the pre-rail behavior. An operator who wants the till to also accept payments
from any Grin wallet, not just Goblin Wallet, sets `GP_GRIN1_RAIL=on`.

With the rail on:

- **One key, two encodings.** GoblinPay starts an in-process Tor onion service
  whose address *is* the till's grin1 slatepack address: the same wallet key,
  encoded two ways, so the grin1 address and the onion address are one and the
  same. The onion serves the Grin Foreign API v2, which binds loopback on
  `GP_GRIN1_FOREIGN_PORT` (default 3416) and is reached through `onion:80`.
- **Two-rail pay page.** The hosted `/pay/<token>` page gains a rail switcher.
  Goblin (Nostr) stays the default-selected tab; the Grin tab carries the grin1
  address and a native Grin invoice slatepack.
- **Native invoice flow, plain-send fallback.** The invoice is a Grin invoice
  slatepack whose slate ID *is* the invoice ID, so a payer's Grin wallet pays it
  directly over Tor and the response settles against the right invoice by that
  slate ID. A wallet that only plain-sends still works: a plain-send slatepack
  lands through the normal receive path and matches like any other payment.
- **Manual paste-back (GRIM parity).** If a payer's wallet cannot deliver its
  response back automatically over Tor, the pay page's paste box accepts it and
  GoblinPay finishes the exchange server-side. Invoice responses settle by slate
  ID; plain-send slatepacks go through the receive path. This works on both
  sub-flows.

### Bundled relay

`GP_RELAY_MODE=bundled` (the default) means GoblinPay runs against its own
co-located Nostr relay, so a merchant needs no third-party relay. The relay is a
stock, unmodified `nostr-rs-relay` (a small, SQLite-backed Rust relay) vendored
as the `relay` service in `deploy/docker-compose.yml` with a config file at
`deploy/relay/nostr-rs-relay.toml` (config only, no fork). It was chosen over
writing a relay from scratch: it is battle-tested, lightweight enough for a
single-merchant till, and keeps the money path off any third-party
infrastructure.

`GP_BUNDLED_RELAY_URL` is the relay's URL. It is both dialed by the server and
advertised to payers in the checkout `nprofile`, so the payer's Goblin Wallet is
told to deliver the gift-wrapped slatepack straight to the merchant's own relay.
Set it to the relay's public `wss://` URL in production (the compose file and
`deploy/Caddyfile` serve it on `relay.<GP_DOMAIN>`); the default
`ws://127.0.0.1:7777` suits local and same-host development. Any `GP_RELAYS` are
appended for redundancy and advertised alongside the bundled relay.

`GP_RELAY_MODE=external` uses only the `GP_RELAYS` set and runs no bundled relay.

### Conversion rates (optional)

A store that prices in fiat (for example cryptodrip.com prices in USD) sends
`amount_fiat` + `currency` to `POST /invoice`. GoblinPay then quotes the Grin
amount through the configured oracle, locks it for `GP_QUOTE_TTL` seconds, and
fills the invoice `expected_amount` so the invoice matches by amount. A
Grin-denominated invoice (`amount_grin`) bypasses the oracle unchanged.

The oracle default is CoinGecko (GRIN is listed under id `grin`), queried at
`api.coingecko.com/api/v3/simple/price?ids=grin&vs_currencies=<currencies>`.
Rates are cached for `GP_RATE_CACHE_TTL` seconds so concurrent checkouts do not
hammer the source. If the source is unreachable or the currency is not enabled,
`create-invoice` fails fast with a clear error rather than creating an
unpriceable invoice; `GP_RATE_STALE_MAX` optionally permits serving the last
cached rate within a bounded window instead. The oracle fetch goes DIRECT over
normal HTTP, the same as the read-only node client.

### Secrets and the wallet seed

`GP_WALLET_PASSWORD` is required on every start: it decrypts the wallet seed,
which GoblinPay stores encrypted at rest under `GP_DATA_DIR` (mode 0600).
`GP_MNEMONIC` is used only once, to create that wallet on the first start.
After the encrypted seed exists, GoblinPay opens the wallet with the password
alone; if `GP_MNEMONIC` is still set it is only checked against the seed at
rest, never used to recreate anything, and the server logs a notice asking you
to remove it. So the steady state is: password in, seed out. Secrets read at
startup are zeroized in memory once they have been consumed, so a decrypted seed
or password does not linger in the process beyond the wallet open it performs.

Deliver both secrets as files rather than plain environment variables:
`GP_MNEMONIC_FILE`, `GP_WALLET_PASSWORD_FILE`, `GP_NSEC_FILE`, and
`GP_NCRYPTSEC_FILE` (mode 0400 recommended). Setting both a variable and its
`_FILE` variant is an error, as is setting both `GP_NSEC` and `GP_NCRYPTSEC`.
An environment variable is visible to the whole process (and via `/proc` to the
same user and root) for the life of the service; a file is not. The shipped
`deploy/gp-server.service` reads the seed and password with systemd
`LoadCredential` (they land under `$CREDENTIALS_DIRECTORY`, pointed at by the
`_FILE` variables), and `deploy/docker-compose.yml` mounts them under
`/run/secrets`, so with either deployment nothing sensitive is in the
environment.

You choose `GP_WALLET_PASSWORD` yourself (the wizard prompts for it twice and
confirms the match; it is never auto-generated). How it reaches the service on
restart is the restart-mode choice above: sealed to the host for unattended
auto-restart, or re-entered by hand each start in manual mode.

Treat the till as a small hot wallet. Grin receives are interactive, so the
till must hold live keys; keep the risk small by giving it a seed of its own,
holding only a working balance, and sweeping to your own wallet regularly. This
is the mitigation for unattended mode's honest trade-off (a full-machine
compromise means wallet compromise); manual mode trades hands-on restarts for
keeping nothing on disk.

When neither identity variable is set, a fresh random Nostr identity is
generated on first start and persisted NIP-49 encrypted at
`<GP_DATA_DIR>/nostr/identity.json` (mode 0600). The mnemonic and the nsec are
deliberately independent secrets: the mnemonic recovers the funds, the nsec
recovers the payment identity, and the Grin seed is never used for anything
Nostr.

## REST API

Public (no auth): `/health`, and the token-as-capability routes below. Bearer
auth (`Authorization: Bearer <token>`) where noted; the `_FILE` mounted-file
variant works for `GP_API_TOKEN`, `GP_ADMIN_TOKEN`, and `GP_WEBHOOK_SECRET` too.

| Method | Route | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness + version |
| POST | `/invoice` | api | Create an invoice, returns checkout info (pay_url, nprofile, QR SVG) |
| GET | `/invoice/{id}` | api | Invoice checkout info + status |
| GET | `/pay/{token}` | token | Hosted zero-JS checkout page |
| GET | `/pay/{token}/status` | token | Invoice status JSON (for polling); includes `confirmations` and `confirmations_required` |
| POST | `/pay/{token}/slatepack` | token | Manual fallback: paste S1, returns the S2 page |
| GET | `/payment/{id}` | token | Payment status JSON; includes `confirmations` and `confirmations_required` |
| GET | `/payment/{id}/receipt` | token | Server-signed verifiable receipt |
| GET | `/admin` | admin | Dashboard (payments, balances, config) |
| GET | `/admin/payments` | admin | Recent payments JSON |
| GET/POST | `/admin/users` | admin | List users / create a user + endpub |
| GET | `/admin/users/{id}` | admin | A user's current endpub + QR |
| POST | `/admin/users/{id}/rotate` | admin | Force-rotate a user's endpub |
| POST | `/admin/users/{id}/rotate-interval` | admin | Set the per-user rotation interval |
| GET | `/admin/webhooks` | admin | Webhook delivery log |

`POST /invoice` body: `{ order_ref?, amount_grin? | (amount_fiat + currency), memo?, match_mode?, expiry_secs? }`.

## Webhook contract

GoblinPay POSTs `application/json` to `GP_WEBHOOK_URL` twice over a payment's
life: `payment.received` when the payment first lands (status `received`), then
`payment.confirmed` once the paying kernel reaches `GP_CONFIRMATIONS` depth
(status `confirmed`, with `confirmed_height` populated). Both share the same
envelope:

```json
{
  "event_id": "5f3c...",              // 128-bit hex, the idempotency key
  "event_type": "payment.received",
  "created_at": "2026-07-01T12:00:00Z",
  "payment": {
    "slate_id": "...", "amount": 2000000000, "amount_grin": "2",
    "status": "received", "payer": "...hex...", "confirmed_height": null
  },
  "invoice_id": "...", "order_ref": "order-42", "user_id": "..."
}
```

Headers: `X-GoblinPay-Signature: sha256=<hex(HMAC-SHA256(secret, raw_body))>`
and `X-GoblinPay-Delivery: <event_id>`. Verify by recomputing the HMAC over the
exact received bytes (constant-time) and dedupe on the delivery id. Deliveries
are persisted and retried with exponential backoff.

## Run

```
cargo run -p gp-server
curl http://127.0.0.1:8080/health
```

## Develop

```
./ci.sh   # cargo fmt --check, clippy -D warnings, tests
```

## Connectors

Store integrations live under `connectors/` and all speak the same
create-invoice + signed-webhook contract:

- `connectors/woocommerce` - a WordPress/WooCommerce gateway (classic + Blocks),
  showing the black GoblinPay badge in the checkout payment-method row (Apple Pay
  style) on both the classic and Blocks checkout.
- `connectors/medusa` - a Medusa v2 payment-module provider.
- The generic REST connector is built in: `POST /invoice` plus the webhook.

Both the WooCommerce and Medusa connectors act on the `payment.confirmed`
webhook idempotently: they complete the order if it is not already complete,
and otherwise just note the confirmation.

Quick starts and the integrator guide live in `docs/`:

- [`docs/woocommerce-quickstart.md`](docs/woocommerce-quickstart.md) - install
  the plugin, run `gp-server setup`, paste three values, test a payment.
- [`docs/medusa-quickstart.md`](docs/medusa-quickstart.md) - the same for a
  Medusa v2 store (note: set `GP_WEBHOOK_URL` to the Medusa route after setup).
- [`docs/api-integration.md`](docs/api-integration.md) - integrate directly
  (the way magick.market does): your service calls create-invoice, the customer
  pays the till wallet-to-till over the encrypted Nostr rail (no coins pass
  through the API or your service), and you grant on confirmed status. Covers
  `POST /invoice`, `GET /invoice/{id}`, bearer auth, and the `payment.confirmed`
  webhook payload + retry semantics.

Refunds are unsupported/manual everywhere (GoblinPay is receive-only).

## Deploy

`deploy/` holds a reproducible deployment: a hardened systemd unit
(`gp-server.service`) with `deploy/install.sh` for bare metal (which ends by
offering to run `gp-server setup`), and a `docker-compose.yml` that brings up
the server, the bundled relay, and an auto-HTTPS Caddy proxy. CI (`.github` /
`.gitea` workflows) runs fmt, clippy, and tests. See `deploy/` for details.

`deploy/package-woocommerce.sh` builds `goblinpay-woocommerce.zip` (a single
top-level `goblinpay-woocommerce/` folder) for a WooCommerce release, so the
shop owner's step is Upload Plugin -> Activate -> paste the three values the
wizard printed.

## Credits

GoblinPay is developed with the help of Claude (Anthropic).

Built with AI pair-programming assistance (Claude)
