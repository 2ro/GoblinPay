/**
 * Options + wire types for the GoblinPay Medusa v2 payment provider.
 *
 * GoblinPay is a receive-only Grin payment server. This provider is a thin
 * client: it calls GoblinPay's REST API to create an invoice and reads back the
 * checkout details, then flips the Medusa payment on a signed webhook. All Grin
 * and Nostr work happens in GoblinPay; Medusa only speaks HTTP to it.
 */

/** Provider options, set per-provider in `medusa-config.ts`. */
export interface GoblinPayOptions {
  /** Base URL of your GoblinPay server, no trailing slash (e.g. https://pay.example). */
  baseUrl: string
  /** Bearer token for the create-invoice API (`GP_API_TOKEN` on the server). */
  apiToken: string
  /** Shared HMAC secret for webhook verification (`GP_WEBHOOK_SECRET`). */
  webhookSecret: string
  /**
   * How GoblinPay matches an incoming payment to this order. `derived`
   * (per-invoice identity, recommended) gives each order its own QR. Omit to
   * use the server default.
   */
  matchMode?: "memo" | "derived" | "amount"
  /** Optional invoice expiry in seconds from creation. */
  expirySecs?: number
}

/** The subset of GoblinPay's `/invoice` response this provider stores/uses. */
export interface GoblinPayInvoice {
  invoice_id: string
  token?: string
  pay_url: string
  nprofile?: string
  npub?: string
  qr_svg?: string
  amount?: string
  /** GoblinPay invoice lifecycle: `open` | `paid` | `expired`. */
  status: string
  order_ref?: string
}
