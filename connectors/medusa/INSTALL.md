# Installing GoblinPay for Medusa

This is a Medusa v2 payment-module provider. There are two ways to add it.

## 1. Add the provider to your Medusa app

### Option A: copy the source (simplest)

Copy this `medusa` directory into your Medusa app as a module, for example
`src/modules/goblinpay`, keeping the `src/` files (`index.ts`, `service.ts`,
`types.ts`). Medusa compiles it with the rest of your app.

### Option B: install as a package

Publish or vendor `medusa-payment-goblinpay` and add it to your app's
dependencies. Build it first with `npm run build` (emits `dist/`).

## 2. Register it in `medusa-config.ts`

Add GoblinPay to the payment module's `providers`. Use `id: "goblinpay"` so the
webhook route is predictable (see step 4):

```ts
module.exports = defineConfig({
  // ...
  modules: [
    {
      resolve: "@medusajs/medusa/payment",
      options: {
        providers: [
          {
            // Option A: the path to the copied module.
            resolve: "./src/modules/goblinpay",
            // Option B: the package name, "medusa-payment-goblinpay".
            id: "goblinpay",
            options: {
              baseUrl: process.env.GOBLINPAY_URL,
              apiToken: process.env.GOBLINPAY_API_TOKEN,
              webhookSecret: process.env.GOBLINPAY_WEBHOOK_SECRET,
              matchMode: "derived",
            },
          },
        ],
      },
    },
  ],
})
```

## 3. Set the environment

In your Medusa app's `.env`:

```
GOBLINPAY_URL=https://pay.example
GOBLINPAY_API_TOKEN=<the same value as GP_API_TOKEN on the server>
GOBLINPAY_WEBHOOK_SECRET=<the same value as GP_WEBHOOK_SECRET on the server>
```

Then enable the `goblinpay` provider in the region(s) that should offer Grin,
via the Medusa admin (Settings, then Regions, then Payment Providers).

## 4. Register the webhook in GoblinPay

Point your GoblinPay server at the Medusa payment webhook route. The route id is
`<provider id>_<identifier>`, both `goblinpay`, so set these on the GoblinPay
side:

- `GP_WEBHOOK_URL` = `https://YOUR-MEDUSA-HOST/hooks/payment/goblinpay_goblinpay`
- `GP_WEBHOOK_SECRET` = the same secret you set as `webhookSecret`.
- `GP_API_TOKEN` = the same token you set as `apiToken`.

GoblinPay signs each delivery with `X-GoblinPay-Signature: sha256=<hmac>` over
the raw body and sends an idempotency key in `X-GoblinPay-Delivery`. The provider
verifies the signature (constant-time) and flips the payment to captured.

Make sure the Medusa host is reachable from the GoblinPay host. If a webhook is
ever missed, Medusa's `getPaymentStatus` polls
`GET {baseUrl}/invoice/{invoice_id}` (with the bearer token) as a fallback.

## 5. Test

Place a test order, choose Grin (GoblinPay), and confirm:

- The storefront shows the GoblinPay QR / redirects to the `/pay/<token>` page
  (the checkout details are on the payment session's `data.goblinpay`).
- Paying from a Goblin Wallet moves the order's payment to captured once
  GoblinPay delivers the `payment.received` webhook.

## Refund caveat

Refunds are not automated. GoblinPay is receive-only and never sends Grin, so
any refund is a manual Grin send performed by the merchant from a wallet under
their control. `refundPayment` throws to make this explicit.
