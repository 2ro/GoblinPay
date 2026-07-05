# WooCommerce quick start

Take Grin payments on your WooCommerce store in four steps. You will run the
GoblinPay till on your own server, then paste three values into WooCommerce.

## 1. Install GoblinPay and run the wizard

On your server (a small Linux box is plenty):

```bash
# build + install the binary and the service unit, then it offers the wizard
sudo ./deploy/install.sh
# or, if GoblinPay is already installed:
sudo gp-server setup
```

The wizard asks a few questions (all with defaults) and does the rest: it makes
your till wallet, generates every secret, picks a healthy Grin node, and writes
the config. Two answers matter for WooCommerce:

- **Your till URL** - either a subdomain like `https://pay.myshop.com`, or a
  path on your existing shop domain like `https://myshop.com/pay` if you would
  rather not add a DNS record (put a reverse proxy in front either way; the
  wizard prints the exact snippet).
- **Your shop URL** - `https://myshop.com`. The wizard turns this into your
  webhook URL for you.

When it finishes it prints three values and a webhook URL. Keep that screen.
Then start the till:

```bash
sudo systemctl start gp-server
```

## 2. Install the plugin

Download `goblinpay-woocommerce.zip` (a GoblinPay release artifact; you can also
build it yourself with `deploy/package-woocommerce.sh`). In WordPress:

**Plugins → Add New → Upload Plugin →** choose the zip **→ Install → Activate.**

## 3. Paste the three values

**WooCommerce → Settings → Payments → GoblinPay (Grin) → Manage:**

| Field | Paste |
|---|---|
| GoblinPay URL | your till URL (e.g. `https://pay.myshop.com`) |
| API Token | the `gp_live_…` value from the wizard |
| Webhook Secret | the `whsec_…` value from the wizard |
| Matching mode | Per-invoice identity (recommended) |

Tick **Enable Grin payments via GoblinPay** and **Save changes**. The wizard
already pointed the till's webhook at your shop, so nothing else to wire.

## 4. Test a payment

Place a test order and choose the Grin method at checkout. You are shown a QR
(or redirected to the hosted checkout). Pay it from your
[Goblin wallet](https://goblin.st): scan, approve, done. The order moves to
**processing** once the payment confirms on chain (default 10 confirmations).

Watch **WooCommerce → Status → Logs** (source `goblinpay`) if you enabled debug
logging, or the till's own admin dashboard, to follow the payment.

## Notes

- **Refunds** are manual: GoblinPay is receive-only, so refund a customer by
  sending Grin back from your wallet.
- **Run the till hot but light:** it has its own seed, so keep only a small
  working balance on it and sweep to your main wallet regularly.
- For the full plugin reference see `connectors/woocommerce/INSTALL.md`.
