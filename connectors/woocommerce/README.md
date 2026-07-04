# GoblinPay for WooCommerce

Accept Grin (GRIN / MimbleWimble) payments in WooCommerce through a self-hosted
GoblinPay server. The customer pays from their Goblin Wallet by scanning an
`nprofile` QR code. The payment travels as a gift-wrapped slatepack over Nostr.
GoblinPay receives it, returns the reply
slatepack to the payer, watches the chain to confirm, and notifies WooCommerce.

This plugin is a thin client. All of the Grin and Nostr work happens in
GoblinPay; WooCommerce only talks HTTP to your GoblinPay instance. No BTCPay, no
node exposed to the store, no wallet RPC.

## What it does

- Adds a "Grin (GRIN)" payment method to both the classic checkout and the
  WooCommerce Blocks (Cart/Checkout block) checkout.
- On checkout, calls GoblinPay to create an invoice for the order, then either
  redirects the customer to GoblinPay's hosted `/pay/<token>` page (the default)
  or shows the Goblin QR on the order-received page (the embedded option).
- Marks the order complete when GoblinPay reports the payment, via a signed
  webhook. If a webhook is missed, the plugin polls GoblinPay for the invoice
  status as a fallback.
- Declares HPOS (custom order tables) and Cart/Checkout Blocks compatibility.

## Requirements

- WordPress with WooCommerce 8.0 or newer (tested against WooCommerce 10.8).
- PHP 8.0 or newer (target host runs PHP 8.2).
- A running GoblinPay server reachable from the WordPress host.

## Settings

Open WooCommerce, then Settings, then Payments, then GoblinPay (Grin).

- GoblinPay URL: base URL of your GoblinPay server, for example
  `http://127.0.0.1:8192`. No trailing slash.
- API Token: the GoblinPay create-invoice bearer token (`GP_API_TOKEN` on the
  server).
- Webhook Secret: the shared HMAC secret (`GP_WEBHOOK_SECRET` on the server).
- Matching mode: how GoblinPay ties an incoming payment to the order. The
  default, per-invoice identity, gives each order its own QR and is the most
  reliable. Order reference (memo) and amount-only are also available.
- Checkout experience: redirect to the hosted GoblinPay checkout (the default),
  or embed the QR on the order-received page.
- Payment window: minutes before an unpaid order is cancelled. Set 0 to disable.

Point your GoblinPay server's `GP_WEBHOOK_URL` at this site's webhook endpoint,
shown in the Webhook Secret field, which is:

```
https://YOUR-SITE/wp-json/goblinpay/v1/webhook
```

## Refunds

Refunds are not automated. GoblinPay is receive-only: it never sends Grin. A
refund is therefore a manual, out-of-band Grin send by the merchant from a
wallet under their control. This plugin marks refunds as unsupported for that
reason, the same caveat the Grin BTCPay connector carries.

## Security notes

- The webhook is authenticated by an HMAC-SHA256 signature over the exact raw
  request body, compared in constant time (`hash_equals`). A bad or missing
  signature is rejected with HTTP 401.
- Webhook deliveries are deduplicated on their event id, and order completion is
  idempotent, so a retried or duplicated delivery is a no-op.
- The QR SVG rendered on the order-received page is passed through a strict
  `wp_kses` allowlist (svg, g, rect, path, image, title), so a compromised or
  misconfigured endpoint cannot inject script.
- Secrets live in the gateway settings, never in code.

## Credit

Built by Claude (Anthropic) for the Goblin project.
