# Integrating with the GoblinPay API

This is the direct-integration path: your service creates an invoice, the
customer pays GoblinPay **directly, wallet-to-till**, and you grant value once
the payment reaches confirmed status. It is the same path magick.market uses.

The important property: **no coins ever pass through the API or through your
service.** Your backend only ever calls create-invoice and reads status. The
actual payment is a private, encrypted Grin transfer that travels from the
customer's Goblin wallet to the till over the Nostr gift-wrap rail (or, for
non-Goblin wallets, over the optional grin1/Tor rail). Your server is never in
the money path; it is only in the *authorization* path.

```
your service ──POST /invoice──▶ GoblinPay ──returns nprofile + pay_url──▶ you show the customer
customer's wallet ═══ encrypted Grin payment ═══▶ GoblinPay till   (never touches you)
GoblinPay ──payment.confirmed webhook──▶ your service        (or you poll GET /invoice/{id})
your service grants the goods on "confirmed"
```

## Authentication

Every API call carries a bearer token:

```
Authorization: Bearer <GP_API_TOKEN>
```

`GP_API_TOKEN` is generated for you by `gp-server setup` (shape `gp_live_…`).
With no token configured the write API is closed (returns `503`), never open.
A missing or wrong token returns `401`.

## Create an invoice

```
POST /invoice
Authorization: Bearer <GP_API_TOKEN>
Content-Type: application/json
```

Request body (provide **either** `amount_grin` **or** `amount_fiat` +
`currency`):

| Field | Type | Notes |
|---|---|---|
| `amount_grin` | integer | Exact amount in **base units (nanogrin)**. 1 GRIN = 1_000_000_000 nanogrin. |
| `amount_fiat` | string | Decimal fiat amount (e.g. `"12.50"`). Priced to Grin at create time via the rate oracle. |
| `currency` | string | ISO code for `amount_fiat` (must be in `GP_RATE_CURRENCIES`). |
| `order_ref` | string | Your order id. Used as the memo/subject match key and echoed back. Optional but recommended. |
| `memo` | string | Human note shown on the checkout page. Optional. |
| `match_mode` | string | Per-invoice override: `memo`, `derived`, or `amount`. Optional; defaults to the server's `GP_MATCH_MODE` (`derived` is recommended). |

Example:

```bash
curl -sS https://pay.myshop.com/invoice \
  -H "Authorization: Bearer $GP_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"amount_grin": 2000000000, "order_ref": "order-1042", "memo": "Order #1042"}'
```

Response (`200`):

```json
{
  "invoice_id": "…",
  "token": "…",
  "pay_url": "https://pay.myshop.com/pay/…",
  "recipient_pubkey": "…",
  "npub": "npub1…",
  "nprofile": "nprofile1…",
  "qr_svg": "<svg …>",
  "amount": "2 GRIN",
  "status": "open",
  "confirmations": 0,
  "confirmations_required": 10,
  "order_ref": "order-1042",
  "memo": "Order #1042"
}
```

To collect payment you have two choices, both in the response:

- **Redirect / link** the customer to `pay_url` (the hosted checkout page,
  which renders the QR, live status, and the manual-paste fallback), or
- **Render your own QR** from `nprofile` (a Goblin wallet scans `nostr:<nprofile>`)
  or embed the ready-made `qr_svg`.

### About the `amount` fields (read this)

Be careful, because base units and display strings both appear:

- In the **request**, `amount_grin` is **base units (nanogrin)** - an integer.
- In the **response**, `amount` is a **human display string** (e.g. `"2 GRIN"`,
  or `"12.50 usd (~150 GRIN)"` for a fiat invoice). It is for display only; do
  not parse it for accounting.
- In the **webhook** (below), `payment.amount` is **base units (nanogrin)** as
  an integer, and `payment.amount_grin` is the human decimal string.

When you reconcile, trust the base-unit integers (`amount_grin` you sent and
`payment.amount` in the webhook), not the display string.

## Read invoice status

```
GET /invoice/{invoice_id}
Authorization: Bearer <GP_API_TOKEN>
```

Returns the same JSON shape as create, with the current `status`,
`confirmations`, and `confirmations_required`. Status advances:

```
open ──▶ paid ──▶ confirmed
```

- `open`: created, not yet paid.
- `paid`: the payment was received and matched to this invoice (in the mempool
  / low confirmations).
- `confirmed`: the paying kernel reached `confirmations_required`
  (`GP_CONFIRMATIONS`, default 10). **Grant the goods on `confirmed`.**

Polling `GET /invoice/{id}` server-to-server is a complete integration on its
own if you would rather not run a webhook endpoint.

## The webhook contract

This is the canonical description of the webhook envelope. Everything else in
the repo links here.

If you set `GP_WEBHOOK_URL` (and `GP_WEBHOOK_SECRET`, which the wizard
generates), GoblinPay POSTs a signed JSON event to your endpoint on each
payment event so you do not have to poll. It fires twice over a payment's life:
`payment.received` when the payment first lands, then `payment.confirmed` once
the paying kernel reaches `GP_CONFIRMATIONS` depth on chain. Both events use the
same envelope, and every field below is always present (nullable ones are sent
as `null`, never omitted):

```json
{
  "event_id": "5f3c…",
  "event_type": "payment.confirmed",
  "created_at": "2026-07-01T12:00:00Z",
  "payment": {
    "slate_id": "…",
    "amount": 2000000000,
    "amount_grin": "2",
    "status": "confirmed",
    "payer": "…hex…",
    "confirmed_height": 2451337,
    "confirmations": 10
  },
  "invoice_id": "…",
  "order_ref": "order-1042",
  "user_id": null
}
```

| Field | Type | Notes |
|---|---|---|
| `event_id` | string | 128-bit hex. The idempotency key, repeated verbatim on every retry of this event, and also sent as the `X-GoblinPay-Delivery` header. |
| `event_type` | string | `payment.received` or `payment.confirmed`. **Grant on `payment.confirmed`.** |
| `created_at` | string | RFC 3339 / ISO 8601 UTC timestamp of when the event was built. |
| `payment.slate_id` | string | The Grin slate id of the paying transaction. |
| `payment.amount` | integer | **Base units (nanogrin).** Reconcile on this. |
| `payment.amount_grin` | string | The same amount as a human decimal string. Display only. |
| `payment.status` | string | `received` or `confirmed`, tracking `event_type`. |
| `payment.payer` | string or null | The payer's Nostr pubkey (hex), null when unknown (a slatepack paste, for example). |
| `payment.confirmed_height` | integer or null | The block the paying kernel landed at. Null on `payment.received`. |
| `payment.confirmations` | integer or null | The kernel's on-chain depth at confirm time. Null on `payment.received`. |
| `invoice_id` | string or null | Null when the payment matched no invoice. |
| `order_ref` | string or null | Your order id, echoed from create-invoice. |
| `user_id` | string or null | The per-user endpub the payment credited, when you use them. |

`confirmations_required` (your `GP_CONFIRMATIONS` threshold) is **not** in the
webhook envelope. Read it from `GET /invoice/{id}` or `GET /payment/{id}`, where
it is returned next to the live `confirmations` count. A `payment.confirmed`
event already means the threshold was reached, so a consumer that only settles
on `payment.confirmed` does not need it.

**Ignore fields you do not recognise.** New fields may be added to this envelope
in future versions; that is not a breaking change. Parse the fields you use,
leave the rest alone, and do not reject a delivery for carrying extra keys.

### Verifying the signature

Every delivery carries two headers:

```
X-GoblinPay-Signature: sha256=<hex>
X-GoblinPay-Delivery: <event_id>
```

`<hex>` is `HMAC-SHA256(GP_WEBHOOK_SECRET, raw_request_body_bytes)`. Recompute
it over the **raw bytes** you received (do not re-serialize the JSON) and
compare in constant time. Reject on mismatch.

### Retry and idempotency semantics (as implemented)

- **At-least-once.** Deliveries are persisted; a mid-retry crash resumes.
- **Ack with 2xx.** Any `2xx` marks the delivery done. Any other status, or a
  transport error, reschedules it.
- **Backoff.** `min(BASE * 2^(attempts-1), 3600s)`, doubling per failed attempt
  up to a 1-hour cap.
- **Give up after 12 attempts** (`MAX_ATTEMPTS`).
- **Deduplicate on `event_id`** (also the `X-GoblinPay-Delivery` header). A
  retried delivery repeats the same `event_id`, so make your handler
  idempotent: if you have already granted this order, just return `2xx`.

## Refunds

GoblinPay is receive-only: there is no refund API. Refunds are handled
out-of-band by sending Grin back from your wallet.
