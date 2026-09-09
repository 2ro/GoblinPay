# GoblinPay for Medusa

Accept Grin (GRIN / MimbleWimble) payments in a Medusa v2 store through a
self-hosted GoblinPay server. The customer pays from their Goblin Wallet by
scanning an `nprofile` QR code. The payment travels as a gift-wrapped slatepack
over Nostr. GoblinPay receives it, returns the
reply slatepack to the payer, watches the chain to confirm, and notifies Medusa
through a signed webhook.

This provider is a thin client. All of the Grin and Nostr work happens in
GoblinPay; Medusa only talks HTTP to your GoblinPay instance. No BTCPay, no node
exposed to the store, no wallet RPC.

## What it does

- Registers a `goblinpay` payment provider in the Medusa v2 payment module.
- On checkout, calls GoblinPay to create an invoice for the payment session and
  stores the checkout details (`pay_url`, `nprofile`, `qr_svg`) on the session
  so your storefront can render the QR or redirect to GoblinPay's hosted
  `/pay/<token>` page.
- Captures the payment when GoblinPay reports it, via a signed webhook. If a
  webhook is missed, `authorizePayment` and `getPaymentStatus` poll GoblinPay
  for the invoice status as a fallback.

## Requirements

- Medusa v2 (built against `@medusajs/framework` 2.12; 2.x expected to work).
- Node 20 or newer.
- A running GoblinPay server reachable from the Medusa host.

## Options

Set these per-provider in `medusa-config.ts` (see INSTALL.md):

- `baseUrl`: base URL of your GoblinPay server, no trailing slash, for example
  `https://pay.example`.
- `apiToken`: the GoblinPay create-invoice bearer token (`GP_API_TOKEN` on the
  server).
- `webhookSecret`: the shared HMAC secret (`GP_WEBHOOK_SECRET` on the server).
- `matchMode` (optional): how GoblinPay ties an incoming payment to the order.
  `derived` (per-invoice identity, recommended) gives each order its own QR and
  is the most reliable. `memo` and `amount` are also available. Omit to use the
  server default.
- `expirySecs` (optional): invoice expiry in seconds from creation.

## Webhook

GoblinPay reports payments to the Medusa payment module's built-in webhook
route. Point your GoblinPay server's `GP_WEBHOOK_URL` at:

```
https://YOUR-MEDUSA-HOST/hooks/payment/goblinpay_goblinpay
```

The provider verifies the `X-GoblinPay-Signature: sha256=<hmac>` header against
the exact raw body (constant-time) before acting.

## Status mapping

| GoblinPay | Medusa payment session |
|---|---|
| invoice `open` | `pending` |
| invoice `paid` | `pending` (received off-chain, not yet settled) |
| invoice `confirmed` | `captured` |
| invoice `expired` | `canceled` |
| webhook `payment.received` | acknowledged, no state change (NOT_SUPPORTED) |
| webhook `payment.confirmed` | captured (SUCCESSFUL, idempotent) |

A received payment means the slatepack was received and the reply handed back,
but the payer may never broadcast the finalized transaction, so it is not yet
fulfilment. The order settles only on `payment.confirmed`, when the paying
kernel has reached `GP_CONFIRMATIONS` on chain, exactly like the WooCommerce
connector.

## Refunds

Refunds are not automated. GoblinPay is receive-only: it never sends Grin. A
refund is therefore a manual, out-of-band Grin send by the merchant from a
wallet under their control. `refundPayment` throws to make this explicit, the
same caveat the Grin BTCPay connector carries.

## Security notes

- The webhook is authenticated by an HMAC-SHA256 signature over the exact raw
  request body, compared in constant time. A bad or missing signature is
  rejected and the payment is not flipped.
- The capture amount is read from the Medusa payment session (its own
  store-currency amount), not from untrusted webhook fields. If that session
  cannot be read, or carries no usable amount, the delivery fails instead of
  capturing: there is no zero-amount fallback.
- Each delivery is bound to the invoice the session created (`invoice_id`), and
  a delivery id already settled by this process is ignored. The id is recorded
  only after the settlement decision is complete, so a failure part-way through
  leaves GoblinPay free to retry.
- Secrets live in the provider options / environment, never in code.

## Credit

Built by Claude (Anthropic) for the Goblin project.
