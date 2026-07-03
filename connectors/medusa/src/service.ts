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
 * POSTs a signed webhook. `getWebhookActionAndData` verifies the HMAC and flips
 * the Medusa payment to captured. Status polling (`authorizePayment`,
 * `getPaymentStatus`) is the webhook-miss fallback.
 *
 * Refunds are NOT automated: GoblinPay is receive-only (it never sends Grin), so
 * `refundPayment` throws. A refund is a manual, out-of-band Grin send by the
 * merchant. See README.md.
 */
import crypto from "node:crypto"

import {
  AbstractPaymentProvider,
  ContainerRegistrationKeys,
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

class GoblinPayProviderService extends AbstractPaymentProvider<GoblinPayOptions> {
  static identifier = "goblinpay"

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

  /** Map a GoblinPay invoice status to a Medusa payment session status. */
  private static mapStatus(
    status: string
  ): "captured" | "canceled" | "pending" {
    switch (status) {
      case "paid":
        return "captured"
      case "expired":
        return "canceled"
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
    return { data: input.data ?? {} }
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
      event_type?: string
      order_ref?: string
    }
    const sessionId = data.order_ref
    if (!sessionId) {
      return { action: PaymentActions.NOT_SUPPORTED }
    }

    // payment.received (funds in hand, S2 returned) and payment.confirmed
    // (on-chain) both mean paid for a receive-only till: flip to captured. The
    // capture is idempotent, so a later confirmation after a received event is a
    // no-op. Capture the session's own (store-currency) amount.
    if (
      data.event_type === "payment.received" ||
      data.event_type === "payment.confirmed"
    ) {
      const amount = await this.sessionAmount(sessionId)
      return {
        action: PaymentActions.SUCCESSFUL,
        data: { session_id: sessionId, amount },
      }
    }

    return { action: PaymentActions.NOT_SUPPORTED }
  }

  /** The payment session's authorized amount, for the webhook capture. */
  private async sessionAmount(sessionId: string): Promise<number> {
    try {
      const session = await this.paymentService_.retrievePaymentSession(sessionId)
      return Number(session.amount)
    } catch (e) {
      this.logger_.warn(
        `goblinpay: could not read session ${sessionId} amount: ${
          (e as Error).message
        }`
      )
      return 0
    }
  }
}

export default GoblinPayProviderService
