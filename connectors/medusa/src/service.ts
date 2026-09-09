/**
 * GoblinPay payment provider for Medusa v2 (tested against @medusajs 2.12).
 *
 * Modeled on connectors/woocommerce and on the reference
 * github.com/SGFGOV/medusa-payment-plugins (packages/medusa-plugin-btcpay).
 *
 * Flow: `initiatePayment` creates a GoblinPay invoice for the order and stashes
 * the checkout details (pay_url, nprofile, qr_svg) on the session so the
 * storefront can render or redirect. The customer pays from their Goblin Wallet;
 * GoblinPay receives it, returns the reply slatepack, watches the chain, and
 * POSTs a signed webhook. `getWebhookActionAndData` verifies the HMAC and, on
 * `payment.confirmed` ONLY (the paying kernel reached the required depth on
 * chain), flips the Medusa payment to captured. `payment.received` means the
 * funds are in hand off-chain but the payer may never broadcast the finalized
 * transaction, so it is not settlement and is acknowledged without acting, the
 * same rule the WooCommerce connector follows. Status polling
 * (`authorizePayment`, `getPaymentStatus`) is the webhook-miss fallback; it maps
 * an `expired` invoice to a canceled session, and `capturePayment` refuses one,
 * so an order that was never paid can never be marked captured. Every polled
 * invoice carries `confirmations` / `confirmations_required`, which stay on the
 * session data for the storefront to show a received payment maturing.
 *
 * Refunds are NOT automated: GoblinPay is receive-only (it never sends Grin), so
 * `refundPayment` throws. A refund is a manual, out-of-band Grin send by the
 * merchant. See README.md.
 */
import crypto from "node:crypto"

import {
  AbstractPaymentProvider,
  ContainerRegistrationKeys,
  MathBN,
  MedusaError,
  Modules,
  PaymentActions,
} from "@medusajs/framework/utils"
import type {
  AuthorizePaymentInput,
  AuthorizePaymentOutput,
  CancelPaymentInput,
  CancelPaymentOutput,
  CapturePaymentInput,
  CapturePaymentOutput,
  DeletePaymentInput,
  DeletePaymentOutput,
  GetPaymentStatusInput,
  GetPaymentStatusOutput,
  InitiatePaymentInput,
  InitiatePaymentOutput,
  IPaymentModuleService,
  Logger,
  PaymentSessionDTO,
  ProviderWebhookPayload,
  RefundPaymentInput,
  RefundPaymentOutput,
  RetrievePaymentInput,
  RetrievePaymentOutput,
  UpdatePaymentInput,
  UpdatePaymentOutput,
  WebhookActionResult,
} from "@medusajs/framework/types"

import type { GoblinPayInvoice, GoblinPayOptions } from "./types"

/**
 * How long a processed delivery id is remembered. GoblinPay retries a delivery
 * with exponential backoff for roughly five hours before abandoning it, so a
 * day is comfortably longer than any retry chain.
 */
const EVENT_TTL_MS = 24 * 60 * 60 * 1000

/** Hard cap on remembered delivery ids so the cache cannot grow without bound. */
const EVENT_CACHE_MAX = 1000

class GoblinPayProviderService extends AbstractPaymentProvider<GoblinPayOptions> {
  static identifier = "goblinpay"

  /**
   * Delivery ids (`event_id` / `X-GoblinPay-Delivery`) already settled by this
   * process, with the time they were recorded.
   *
   * Best effort by design: a Medusa payment provider has no shared store, and
   * the capture it guards is itself idempotent, so a miss after a restart or
   * across workers costs nothing. Entries expire and the map is capped.
   */
  private static readonly seenEvents_ = new Map<string, number>()

  /** Has this delivery id already been settled (and not yet expired)? */
  private static alreadySettled(eventId: string): boolean {
    const at = GoblinPayProviderService.seenEvents_.get(eventId)
    if (at === undefined) {
      return false
    }
    if (Date.now() - at > EVENT_TTL_MS) {
      GoblinPayProviderService.seenEvents_.delete(eventId)
      return false
    }
    return true
  }

  /** Record a delivery id, evicting expired then oldest entries at the cap. */
  private static rememberSettled(eventId: string): void {
    const seen = GoblinPayProviderService.seenEvents_
    const now = Date.now()
    for (const [id, at] of seen) {
      if (now - at > EVENT_TTL_MS) {
        seen.delete(id)
      }
    }
    while (seen.size >= EVENT_CACHE_MAX) {
      const oldest = seen.keys().next()
      if (oldest.done) {
        break
      }
      seen.delete(oldest.value)
    }
    seen.set(eventId, now)
  }

  protected readonly options_: GoblinPayOptions
  protected readonly logger_: Logger
  protected readonly paymentService_: IPaymentModuleService

  constructor(container: Record<string, unknown>, options: GoblinPayOptions) {
    super(container as never, options)
    this.options_ = options
    this.logger_ = container[ContainerRegistrationKeys.LOGGER] as Logger
    this.paymentService_ = container[Modules.PAYMENT] as IPaymentModuleService

    if (!options?.baseUrl || !options?.apiToken || !options?.webhookSecret) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "GoblinPay provider requires baseUrl, apiToken, and webhookSecret options"
      )
    }
  }

  private get base(): string {
    return this.options_.baseUrl.replace(/\/+$/, "")
  }

  /** Call the GoblinPay REST API with the bearer token. */
  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown
  ): Promise<T> {
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.options_.apiToken}`,
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    })
    const text = await res.text()
    const json = text ? JSON.parse(text) : {}
    if (!res.ok) {
      const err =
        (json && (json.error as string)) || `GoblinPay HTTP ${res.status}`
      throw new MedusaError(MedusaError.Types.UNEXPECTED_STATE, err)
    }
    return json as T
  }

  /**
   * Map a GoblinPay invoice status to a Medusa payment session status.
   *
   * The server's lifecycle is `open` | `paid` | `confirmed` | `expired`
   * (crates/gp-core/src/invoice.rs:40-57):
   *
   * - `open`      awaiting payment.
   * - `paid`      the slatepack was received and the reply handed back, but the
   *               payer may still never broadcast the finalized transaction, so
   *               this is NOT settlement: it stays `pending`.
   * - `confirmed` the paying kernel reached `GP_CONFIRMATIONS` on chain. This is
   *               the settlement signal, matching `payment.confirmed` and the
   *               WooCommerce connector.
   * - `expired`   the invoice lapsed unpaid.
   */
  private static mapStatus(
    status: string
  ): "captured" | "canceled" | "pending" {
    switch (status) {
      case "confirmed":
        return "captured"
      case "expired":
        return "canceled"
      // "open" and "paid" are both still in flight.
      default:
        return "pending"
    }
  }

  async initiatePayment(
    input: InitiatePaymentInput
  ): Promise<InitiatePaymentOutput> {
    const sessionId = input.context?.idempotency_key
    if (!sessionId) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "Idempotency key (payment session id) is required to initiate payment"
      )
    }

    // GoblinPay prices the fiat order into Grin via its own oracle. The order's
    // session id is the order_ref, so the signed webhook echoes it back to us.
    const invoice = await this.request<GoblinPayInvoice>("POST", "/invoice", {
      order_ref: sessionId,
      amount_fiat: input.amount.toString(),
      currency: input.currency_code,
      memo: `Medusa order ${sessionId}`,
      ...(this.options_.matchMode ? { match_mode: this.options_.matchMode } : {}),
      ...(this.options_.expirySecs ? { expiry_secs: this.options_.expirySecs } : {}),
    })

    return {
      id: sessionId,
      data: { ...input.data, goblinpay: invoice },
    }
  }

  /** Re-read the current invoice from GoblinPay using the stored invoice_id. */
  private async fetchInvoice(
    data: Record<string, unknown> | undefined
  ): Promise<GoblinPayInvoice> {
    const stored = (data?.goblinpay ?? {}) as GoblinPayInvoice
    if (!stored.invoice_id) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "No GoblinPay invoice_id on the payment session"
      )
    }
    return this.request<GoblinPayInvoice>(
      "GET",
      `/invoice/${encodeURIComponent(stored.invoice_id)}`
    )
  }

  async authorizePayment(
    input: AuthorizePaymentInput
  ): Promise<AuthorizePaymentOutput> {
    const invoice = await this.fetchInvoice(input.data)
    return {
      status: GoblinPayProviderService.mapStatus(invoice.status),
      data: { ...input.data, goblinpay: invoice },
    }
  }

  async getPaymentStatus(
    input: GetPaymentStatusInput
  ): Promise<GetPaymentStatusOutput> {
    const invoice = await this.fetchInvoice(input.data)
    return {
      status: GoblinPayProviderService.mapStatus(invoice.status),
      data: { ...input.data, goblinpay: invoice },
    }
  }

  async capturePayment(
    input: CapturePaymentInput
  ): Promise<CapturePaymentOutput> {
    // GoblinPay is receive-only: once the payment is received the funds are
    // already in the merchant wallet, so capture is a no-op acknowledgement.
    //
    // An EXPIRED invoice is the one case where that acknowledgement would be a
    // lie: nothing was ever received, and GoblinPay closed the invoice so
    // nothing can be. Refuse rather than mark an unpaid order captured. Only an
    // `open` invoice ever expires (gp-core/src/invoice.rs:459-462), so this can
    // never block a real payment.
    const stored = (input.data?.goblinpay ?? {}) as GoblinPayInvoice
    if (stored.status === "expired") {
      throw new MedusaError(
        MedusaError.Types.NOT_ALLOWED,
        "GoblinPay invoice expired without payment; it cannot be captured"
      )
    }
    // The stored copy can be stale, so confirm against the server. A GoblinPay
    // that is unreachable must not fail a capture whose money is already in
    // hand, so only a definite `expired` refuses.
    try {
      const invoice = await this.fetchInvoice(input.data)
      if (invoice.status === "expired") {
        throw new MedusaError(
          MedusaError.Types.NOT_ALLOWED,
          "GoblinPay invoice expired without payment; it cannot be captured"
        )
      }
      return { data: { ...input.data, goblinpay: invoice } }
    } catch (e) {
      if (e instanceof MedusaError && e.type === MedusaError.Types.NOT_ALLOWED) {
        throw e
      }
      this.logger_.warn(
        `GoblinPay: could not re-read the invoice before capture (${
          e instanceof Error ? e.message : String(e)
        }); acknowledging with the stored session data`
      )
      return { data: input.data ?? {} }
    }
  }

  async cancelPayment(
    input: CancelPaymentInput
  ): Promise<CancelPaymentOutput> {
    // Nothing to cancel server-side; an unpaid GoblinPay invoice simply expires.
    return { data: input.data ?? {} }
  }

  async deletePayment(
    input: DeletePaymentInput
  ): Promise<DeletePaymentOutput> {
    return { data: input.data ?? {} }
  }

  async refundPayment(
    _input: RefundPaymentInput
  ): Promise<RefundPaymentOutput> {
    // Receive-only: GoblinPay never sends Grin, so refunds cannot be automated.
    // A refund is a manual, out-of-band Grin send by the merchant.
    throw new MedusaError(
      MedusaError.Types.NOT_ALLOWED,
      "GoblinPay is receive-only; refunds must be issued manually by the merchant (out-of-band Grin send)."
    )
  }

  async retrievePayment(
    input: RetrievePaymentInput
  ): Promise<RetrievePaymentOutput> {
    const invoice = await this.fetchInvoice(input.data)
    return { data: { ...input.data, goblinpay: invoice } }
  }

  async updatePayment(
    input: UpdatePaymentInput
  ): Promise<UpdatePaymentOutput> {
    return { data: input.data ?? {} }
  }

  /**
   * Verify the HMAC-SHA256 over the EXACT raw body, constant-time. Mirrors the
   * WooCommerce connector and GoblinPay's webhook contract:
   *   X-GoblinPay-Signature: sha256=<hex(HMAC-SHA256(secret, raw_body))>
   */
  private verifySignature(payload: ProviderWebhookPayload["payload"]): boolean {
    const raw = payload.rawData
    if (!raw) {
      return false
    }
    const provided = (payload.headers?.["x-goblinpay-signature"] as string) ?? ""
    const expected =
      "sha256=" +
      crypto
        .createHmac("sha256", this.options_.webhookSecret)
        .update(raw as string | Buffer)
        .digest("hex")
    const a = Buffer.from(provided, "utf8")
    const b = Buffer.from(expected, "utf8")
    return a.length === b.length && crypto.timingSafeEqual(a, b)
  }

  async getWebhookActionAndData(
    payload: ProviderWebhookPayload["payload"]
  ): Promise<WebhookActionResult> {
    if (!this.verifySignature(payload)) {
      this.logger_.warn("goblinpay: webhook signature mismatch")
      return { action: PaymentActions.FAILED }
    }

    const data = (payload.data ?? {}) as {
      event_id?: string
      event_type?: string
      invoice_id?: string
      order_ref?: string
    }

    // Idempotency key: the body's event_id, else the delivery header that
    // carries the same value.
    const eventId =
      data.event_id ||
      ((payload.headers?.["x-goblinpay-delivery"] as string) ?? "")
    if (eventId && GoblinPayProviderService.alreadySettled(eventId)) {
      return { action: PaymentActions.NOT_SUPPORTED }
    }

    const sessionId = data.order_ref
    if (!sessionId) {
      return { action: PaymentActions.NOT_SUPPORTED }
    }

    // SETTLE ON payment.confirmed ONLY. payment.received means the funds are in
    // hand off-chain (the S2 went back) but the payer may never broadcast the
    // finalized transaction, so it is not fulfilment: acknowledge it and wait.
    // Same rule as the WooCommerce connector.
    if (data.event_type !== "payment.confirmed") {
      return { action: PaymentActions.NOT_SUPPORTED }
    }

    // One read serves both guards below: it binds the delivery to the invoice
    // this session created, and it supplies the amount to capture.
    const session = await this.settlingSession(sessionId)

    // Bind the webhook to the invoice we created for this session (defence in
    // depth behind the HMAC, mirroring the WooCommerce connector). A mismatch
    // is permanent, so acknowledge it rather than making GoblinPay retry.
    const known = (
      (session.data ?? {}) as { goblinpay?: Partial<GoblinPayInvoice> }
    ).goblinpay?.invoice_id
    if (known && data.invoice_id && known !== data.invoice_id) {
      this.logger_.warn(
        `goblinpay: invoice mismatch on session ${sessionId}: known ${known}, got ${data.invoice_id}`
      )
      return { action: PaymentActions.NOT_SUPPORTED }
    }

    // Capture the session's own (store-currency) amount, never an amount from
    // the webhook body. `amount` is a BigNumberValue, so it goes through MathBN
    // rather than Number(), which would silently produce NaN for the object form.
    const amount = MathBN.convert(session.amount).toNumber()
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new MedusaError(
        MedusaError.Types.UNEXPECTED_STATE,
        `GoblinPay webhook: payment session ${sessionId} has no usable amount; refusing to capture`
      )
    }

    // Record the delivery LAST, once everything above succeeded. Anything that
    // throws on the way here leaves the id unrecorded, so GoblinPay's retry can
    // still settle the payment.
    if (eventId) {
      GoblinPayProviderService.rememberSettled(eventId)
    }

    return {
      action: PaymentActions.SUCCESSFUL,
      data: { session_id: sessionId, amount },
    }
  }

  /**
   * The payment session a confirmed webhook is about to settle.
   *
   * FAIL CLOSED: a lookup failure throws instead of returning a default, so a
   * capture can never run on a guessed (or zero) amount. The delivery then
   * fails and GoblinPay retries it with backoff.
   */
  private async settlingSession(sessionId: string): Promise<PaymentSessionDTO> {
    try {
      return await this.paymentService_.retrievePaymentSession(sessionId)
    } catch (e) {
      this.logger_.error(
        `goblinpay: could not read session ${sessionId}: ${(e as Error).message}`
      )
      throw new MedusaError(
        MedusaError.Types.UNEXPECTED_STATE,
        `GoblinPay webhook: payment session ${sessionId} is unreadable; refusing to capture`
      )
    }
  }
}

export default GoblinPayProviderService
