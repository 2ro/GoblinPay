# Medusa quick start

Take Grin payments in a Medusa v2 store. You run the GoblinPay till on your own
server and add the GoblinPay payment provider to your Medusa app.

## 1. Install GoblinPay and run the wizard

On your server:

```bash
sudo ./deploy/install.sh     # installs, then offers the wizard
# or, if already installed:
sudo gp-server setup
```

You choose your wallet password (entered twice) and write down the 24-word seed
it shows once; the wizard generates the service tokens, makes your till wallet,
picks a healthy Grin node, asks how the till should restart (default unattended),
and writes the config. Note the three values it prints at the end: the **till
URL**, the **API Token** (`gp_live_…`), and the **Webhook Secret** (`whsec_…`).

> **One Medusa-specific step.** The wizard fills in a *WooCommerce* webhook URL
> by default. Medusa uses a different route, so after setup, edit
> `/etc/goblinpay.env` and change `GP_WEBHOOK_URL` to your Medusa route (see
> step 3), then `sudo systemctl restart gp-server`. Everything else the wizard
> generated (tokens, secret, wallet) is reused as-is.

Start the till:

```bash
sudo systemctl start gp-server
```

## 2. Add the provider to your Medusa app

Copy the `connectors/medusa` directory into your app (e.g.
`src/modules/goblinpay`), or install it as `medusa-payment-goblinpay`. Register
it in `medusa-config.ts` under the payment module's `providers` with
`id: "goblinpay"`, and set its options from the environment:

```ts
options: {
  baseUrl: process.env.GOBLINPAY_URL,          // your till URL
  apiToken: process.env.GOBLINPAY_API_TOKEN,   // the gp_live_… value
  webhookSecret: process.env.GOBLINPAY_WEBHOOK_SECRET, // the whsec_… value
  matchMode: "derived",
}
```

In your Medusa `.env`:

```
GOBLINPAY_URL=https://pay.myshop.com
GOBLINPAY_API_TOKEN=<the gp_live_… value from the wizard>
GOBLINPAY_WEBHOOK_SECRET=<the whsec_… value from the wizard>
```

Enable the `goblinpay` provider in the region(s) that should offer Grin
(Medusa admin → Settings → Regions → Payment Providers).

## 3. Point the till's webhook at Medusa

The Medusa payment webhook route id is `<provider id>_<identifier>`, both
`goblinpay`, so set on the GoblinPay server (`/etc/goblinpay.env`):

```
GP_WEBHOOK_URL=https://YOUR-MEDUSA-HOST/hooks/payment/goblinpay_goblinpay
```

Then `sudo systemctl restart gp-server`. The `GP_API_TOKEN` and
`GP_WEBHOOK_SECRET` the wizard generated must equal the `apiToken` and
`webhookSecret` you set in Medusa (they already do if you copied them across).

## 4. Test a payment

Place a test order and choose Grin (GoblinPay). The storefront shows the
GoblinPay QR or redirects to the `/pay/<token>` page. Pay from your
[Goblin wallet](https://goblin.st); the order's payment flips to captured once
GoblinPay delivers the webhook. If a delivery is ever missed, the provider falls
back to polling `GET {baseUrl}/invoice/{invoice_id}`.

## Notes

- **Refunds** are manual (receive-only): send Grin back from your wallet.
- For the full provider reference see `connectors/medusa/INSTALL.md`.
