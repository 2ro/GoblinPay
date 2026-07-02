# GoblinPay

A self-hostable, receive-only Grin payment server. A merchant runs it, a
customer pays from Goblin Wallet by scanning a QR code, and the payment
travels as a gift-wrapped slatepack over Nostr (optionally over the Nym
mixnet). GoblinPay auto-receives, returns the S2 reply so the payer can
finalize, confirms the transaction on chain, and signals paid.

Beyond the core wallet + transport + on-chain confirmation path, GoblinPay
carries the full merchant surface:

- **Invoices + matching:** create an invoice against an order, matched by
  any of three modes (per-invoice override or the `GP_MATCH_MODE` default):
  the payer's memo, a per-invoice derived Nostr identity (a stateless child of
  the server nsec, recommended for stores), or an exact amount. The matcher
  runs inside the ingest pipeline, so a gift-wrapped payment resolves to its
  invoice automatically.
- **Hosted checkout:** a zero-JS `/pay/<token>` page (server-rendered
  Askama + one CSS file + a server-generated QR SVG at ECC level H with an
  optional Goblin-mark center logo), live status via `<meta http-equiv=refresh>`,
  and a manual slatepack fallback (paste S1 -> offline `receive_tx` -> copy the
  S2 back) on every page. The same renderer serves embedded and hosted use.
- **Per-user endpubs:** an admin assigns one receiving identity per user
  (a derived child keyed by `(user_id, epoch)`; only public keys and the
  rotation clock are stored, never private keys), with optional rolling rotation
  and an overlap window so a just-rotated endpub still lands. All funds still
  land in the one Grin wallet.
- **Notifications (all optional):** an HMAC-signed, idempotent, retried
  HTTP webhook (the WooCommerce contract), an authenticated admin dashboard +
  JSON API, and NIP-17 DMs to the merchant / payer.

All relay traffic rides an in-process Nym mixnet tunnel (smolmix, auto-selected
exit, mix-dns; `GP_NYM=off` is a debugging escape hatch only). Encryption
negotiates NIP-44 v3 (the NIP-17 extension, via the companion `nip44` crate) per
recipient, with v2 as the mandatory baseline.

## Workspace

| Crate | Purpose |
|---|---|
| `crates/gp-wallet` | Grin wallet handoff: open from mnemonic, S1 -> `receive_tx` -> S2 (offline) |
| `crates/gp-goblin-sender` | Test-only gate helper: sends and finalizes with Goblin's wallet stack |
| `crates/gp-nostr` | Nostr transport: identity, gift wrap (NIP-44 v2/v3), ingest, Nym mixnet |
| `crates/gp-core` | Domain core: config, SQLite persistence (sqlx, raw SQL) |
| `crates/gp-server` | Actix-Web binary: routes, Askama templates, rustls TLS |

Supporting directories: `migrations/` (raw sqlx SQL), `templates/` (Askama,
zero JS), `static/` (one hand-written CSS file, no build step).

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
| `GP_RELAY_MODE` | `bundled` | `bundled` or `external` |
| `GP_RELAYS` | unset | Comma-separated relay URLs |
| `GP_NYM` | `on` | Route Nostr traffic over the Nym mixnet (`on` or `off`) |
| `GP_INGEST` | `on` | Nostr ingest service (`off` = HTTP surface only, for debugging) |
| `GP_MATCH_MODE` | `memo` | Default matching mode: `memo`, `derived`, `amount` |
| `GP_MNEMONIC` | unset | Grin seed mnemonic (money secret) |
| `GP_WALLET_PASSWORD` | unset | Password encrypting the wallet seed and the Nostr identity at rest |
| `GP_NSEC` | unset | Nostr identity key (payment identity secret) |
| `GP_NCRYPTSEC` | unset | NIP-49 encrypted identity key (unlocked with the wallet password) |
| `GP_PUBLIC_URL` | `http://<bind>` | Public base URL for the hosted `/pay/<token>` links |
| `GP_API_TOKEN` | unset | Bearer token for the connector/create-invoice API (unset = write API closed) |
| `GP_ADMIN_TOKEN` | unset | Bearer token for the admin dashboard + endpub/webhook API |
| `GP_WEBHOOK_URL` | unset | Webhook endpoint for payment events (requires `GP_WEBHOOK_SECRET`) |
| `GP_WEBHOOK_SECRET` | unset | HMAC-SHA256 secret for signing webhooks |
| `GP_QR_LOGO` | Goblin mark | Checkout QR center logo: unset = Goblin mark, `off`/`none` = plain, else a URL/path |
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
normal HTTP, never through the Nym mixnet (the mixnet carries only the Nostr
gift-wrap layer, the same ruling as the read-only node client).

The secrets also accept mounted-file variants, `GP_MNEMONIC_FILE`,
`GP_WALLET_PASSWORD_FILE`, `GP_NSEC_FILE`, and `GP_NCRYPTSEC_FILE`
(mode 0400 recommended). Setting both the variable and its `_FILE` variant
is an error, as is setting both `GP_NSEC` and `GP_NCRYPTSEC`. When neither
identity variable is set, a fresh random identity is generated on first
start and persisted NIP-49 encrypted at `<GP_DATA_DIR>/nostr/identity.json`
(mode 0600). The mnemonic and the nsec are deliberately independent secrets:
the mnemonic recovers the funds, the nsec recovers the payment identity, and
the Grin seed is never used for anything Nostr.

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
| GET | `/pay/{token}/status` | token | Invoice status JSON (for polling) |
| POST | `/pay/{token}/slatepack` | token | Manual fallback: paste S1, returns the S2 page |
| GET | `/payment/{id}` | token | Payment status JSON |
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

On a received payment, GoblinPay POSTs `application/json` to `GP_WEBHOOK_URL`:

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

## Credits

GoblinPay is developed with the help of Claude (Anthropic).
