# Installing GoblinPay for WooCommerce

## 1. Package the plugin

Zip the plugin directory so the archive contains a single top-level folder named
`goblinpay-woocommerce` with the plugin files inside it:

```
cd connectors
zip -r goblinpay-woocommerce.zip woocommerce \
  -x '*/.git/*'
```

If you prefer the folder name to match the plugin, rename `woocommerce` to
`goblinpay-woocommerce` before zipping. WordPress does not require the folder
name to match; it reads the plugin header from `goblinpay-woocommerce.php`.

## 2. Upload and activate

In WordPress, open Plugins, then Add New Plugin, then Upload Plugin. Choose the
zip, install it, and activate. WooCommerce 8.0 or newer must already be active.

Alternatively, copy the `woocommerce` folder into
`wp-content/plugins/goblinpay-woocommerce/` on the server and activate from the
Plugins screen.

## 3. Configure the gateway

Open WooCommerce, then Settings, then Payments, then GoblinPay (Grin), and set:

- GoblinPay URL: the base URL of your GoblinPay server, for example
  `http://127.0.0.1:8080` when GoblinPay runs on the same host. No trailing
  slash.
- API Token: the GoblinPay create-invoice bearer token (`GP_API_TOKEN`).
- Webhook Secret: the shared HMAC secret (`GP_WEBHOOK_SECRET`).
- Matching mode: leave on Per-invoice identity (recommended) unless you have a
  reason to match by order reference or amount.
- Checkout experience: Redirect (recommended) or Embed the QR on the
  order-received page.
- Payment window: minutes before an unpaid order is cancelled (0 disables it).

Enable the method and save.

## 4. Register the webhook in GoblinPay

Point your GoblinPay server at this site so it can report payments. Set these on
the GoblinPay side:

- `GP_WEBHOOK_URL` = `https://YOUR-SITE/wp-json/goblinpay/v1/webhook`
- `GP_WEBHOOK_SECRET` = the same secret you entered in the gateway settings.
- `GP_API_TOKEN` = the same token you entered as the API Token.

GoblinPay signs each delivery with `X-GoblinPay-Signature: sha256=<hmac>` over
the raw body and sends an idempotency key in `X-GoblinPay-Delivery`. The plugin
verifies the signature, dedupes on the event id, and completes the matching
order.

The exact POST target the plugin exposes (the value to use for
`GP_WEBHOOK_URL`) is:

```
https://YOUR-SITE/wp-json/goblinpay/v1/webhook
```

Make sure the WordPress REST API is reachable from the GoblinPay host. If the
webhook is ever missed, the plugin also polls
`GET {GoblinPay URL}/invoice/{invoice_id}` (with the bearer token) as a
fallback.

## 5. Test

Place a test order, choose Grin (GRIN), and confirm:

- Redirect mode sends you to the GoblinPay `/pay/<token>` page.
- Embed mode shows the Goblin QR on the order-received page.
- Paying from a Goblin Wallet moves the order to processing or completed once
  GoblinPay delivers the `payment.received` webhook.

Turn on Debug logging in the gateway settings to trace requests and webhooks in
WooCommerce, then Status, then Logs, source `goblinpay`.

## Refund caveat

Refunds are not automated. GoblinPay is receive-only and never sends Grin, so
any refund is a manual Grin send performed by the merchant from a wallet under
their control.
