//! The connector-facing invoice API (authenticated with `GP_API_TOKEN`):
//! create an invoice and read its checkout info. This is what a store
//! connector (WooCommerce, Medusa, generic REST) calls; it returns the hosted
//! `/pay/<token>` URL plus the nprofile + QR so the store can render or
//! redirect. All matching modes are supported per invoice.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use gp_core::config::{Config, MatchMode};
use gp_core::invoice::{self, AmountSpec, Invoice, NewInvoice};
use gp_core::rates::{Oracle, RateError};
use gp_core::store::{CreateInvoiceRequest, RestConnector, StoreConnector};
use gp_nostr::Keys;
use gp_wallet::GpWallet;
use log::error;
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::authorized;
use crate::checkout::{build_info, CheckoutInfo};
use crate::payments::ReceiptSigner;

/// Register the invoice API routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/invoice", web::post().to(create_invoice))
        .route("/invoice/{id}", web::get().to(get_invoice));
}

/// JSON body for `POST /invoice`.
#[derive(Deserialize)]
struct CreateInvoiceBody {
    /// The store's order reference (memo/subject match key).
    order_ref: Option<String>,
    /// Exact amount in nanogrin.
    amount_grin: Option<u64>,
    /// Or a fiat amount (decimal string) plus currency (Grin quote deferred).
    amount_fiat: Option<String>,
    currency: Option<String>,
    memo: Option<String>,
    /// Per-invoice matching mode override: `memo`, `derived`, or `amount`.
    match_mode: Option<String>,
    /// Expiry in seconds from now.
    expiry_secs: Option<i64>,
}

fn parse_mode(s: &str) -> Option<MatchMode> {
    match s {
        "memo" => Some(MatchMode::Memo),
        "derived" => Some(MatchMode::Derived),
        "amount" => Some(MatchMode::Amount),
        _ => None,
    }
}

/// JSON shape returned for a created/fetched invoice. `confirmations` is the
/// paying kernel's live depth (0 until it lands) and `confirmations_required`
/// is the house threshold (`GP_CONFIRMATIONS`); `status` advances
/// open -> paid -> confirmed (paid stays a real, backward-compatible state).
fn checkout_json(
    info: &CheckoutInfo,
    confirmations: i64,
    confirmations_required: i64,
) -> serde_json::Value {
    serde_json::json!({
        "invoice_id": info.invoice_id,
        "token": info.token,
        "pay_url": info.pay_url,
        "recipient_pubkey": info.recipient_pubkey,
        "npub": info.npub,
        "nprofile": info.nprofile,
        "qr_svg": info.qr_svg,
        "amount": info.amount_display,
        "status": info.status,
        "confirmations": confirmations,
        "confirmations_required": confirmations_required,
        "order_ref": info.order_ref,
        "memo": info.memo,
    })
}

/// POST /invoice (auth): create an invoice, return its checkout info.
async fn create_invoice(
    req: HttpRequest,
    body: web::Json<CreateInvoiceBody>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
    signer: web::Data<ReceiptSigner>,
    oracle: web::Data<Oracle>,
    wallet: web::Data<Option<GpWallet>>,
) -> impl Responder {
    if !authorized(&req, cfg.api_token.as_ref().map(|s| s.reveal())) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    // Invoice creation needs the server identity (to derive per-invoice keys
    // and to name the master recipient).
    let Some(keys) = signer.0.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error": "server identity not loaded (GP_INGEST=off)"}));
    };

    let body = body.into_inner();
    let amount = match (body.amount_grin, body.amount_fiat, body.currency) {
        (Some(nano), _, _) => AmountSpec::Grin(nano),
        (None, Some(amount), Some(currency)) => AmountSpec::Fiat { amount, currency },
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "provide amount_grin, or amount_fiat + currency"
            }))
        }
    };
    let match_mode = match body.match_mode.as_deref() {
        Some(m) => match parse_mode(m) {
            Some(mode) => Some(mode),
            None => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "match_mode must be memo, derived, or amount"
                }))
            }
        },
        None => None,
    };

    // Route the request through the store connector (uniform mapping).
    let connector = RestConnector::new(cfg.webhook_url.clone());
    let params: NewInvoice = connector.new_invoice(CreateInvoiceRequest {
        order_ref: body.order_ref,
        amount,
        memo: body.memo,
        match_mode,
        expiry_secs: body.expiry_secs,
    });

    // Milestone 7: a fiat invoice is priced into Grin by the oracle (DIRECT
    // HTTP, never Nym) and its quote locked for the expiry window, so its
    // expected_amount is filled and it matches by amount. A Grin invoice
    // bypasses the oracle entirely. Fail fast on an unpriceable invoice.
    let params = match price_if_fiat(oracle.get_ref(), params).await {
        Ok(params) => params,
        Err(resp) => return resp,
    };

    let master_sk = master_secret(keys);
    let master_hex = keys.public_key().to_hex();
    let inv = match invoice::create(
        pool.get_ref(),
        params,
        &master_sk,
        &master_hex,
        cfg.match_mode,
    )
    .await
    {
        Ok(inv) => inv,
        Err(e) => {
            error!("create invoice failed: {e}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "internal error"}));
        }
    };

    // grin1 rail (Phase 2): when armed and a wallet is loaded, an exact-amount
    // invoice also issues a native Grin invoice slate (the primary "pay with any
    // Grin wallet" path). The returning finalize is matched back by slate id.
    // The node round trip in issue_invoice blocks, so it runs off the workers.
    let inv = arm_grin1_rail(pool.get_ref(), cfg.get_ref(), wallet.get_ref(), inv).await;

    // The JSON connector API surfaces the Nostr checkout fields only; the
    // grin1 Slatepack option is presented on the hosted /pay page. A freshly
    // created invoice is `open`, so its confirmation depth is 0.
    let info = build_info(&inv, cfg.get_ref(), None, None, false);
    HttpResponse::Ok().json(checkout_json(&info, 0, cfg.confirmations_required))
}

/// GET /invoice/{id} (auth): the invoice's current checkout info + status.
async fn get_invoice(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !authorized(&req, cfg.api_token.as_ref().map(|s| s.reveal())) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}));
    }
    match invoice::get(pool.get_ref(), &path.into_inner()).await {
        Ok(Some(inv)) => {
            let confirmations = invoice::confirmations(pool.get_ref(), &inv.id)
                .await
                .unwrap_or(0);
            let info = build_info(&inv, cfg.get_ref(), None, None, false);
            HttpResponse::Ok().json(checkout_json(
                &info,
                confirmations,
                cfg.confirmations_required,
            ))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "not found"})),
        Err(e) => {
            error!("get invoice: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

/// Arm a freshly created invoice on the grin1 rail: issue a native Grin invoice
/// slate for its exact amount and store the slate id + armored slatepack. A
/// no-op (returns the invoice unchanged) when the rail is off, no wallet is
/// loaded, or the invoice has no positive exact amount (an unpriced fiat invoice
/// has nothing to invoice for). Best-effort: an issue/attach failure is logged
/// and the invoice still returns on its other rails, never failing the caller.
async fn arm_grin1_rail(
    pool: &SqlitePool,
    cfg: &Config,
    wallet: &Option<GpWallet>,
    inv: Invoice,
) -> Invoice {
    if !cfg.grin1_rail {
        return inv;
    }
    let (Some(wallet), Some(nano)) = (wallet.as_ref(), inv.expected_amount) else {
        return inv;
    };
    if nano <= 0 {
        return inv;
    }
    let nano = nano as u64;
    let w = wallet.clone();
    // issue_invoice reads the chain tip through the blocking grin node client;
    // keep it off the async workers.
    let issued = actix_web::rt::task::spawn_blocking(move || w.issue_invoice(nano)).await;
    match issued {
        Ok(Ok(issued)) => {
            if let Err(e) =
                invoice::attach_grin1(pool, &inv.id, &issued.slate_id, &issued.i1_armor).await
            {
                error!("grin1: attach failed for {}: {e}", inv.id);
                return inv;
            }
            // Refetch so the returned row carries the rail fields.
            invoice::get(pool, &inv.id).await.ok().flatten().unwrap_or(inv)
        }
        Ok(Err(e)) => {
            error!("grin1: issue_invoice failed for {}: {e}", inv.id);
            inv
        }
        Err(e) => {
            error!("grin1: issue_invoice task panicked for {}: {e}", inv.id);
            inv
        }
    }
}

/// Price a fiat invoice through the oracle, in place. A `Grin` or already
/// `FiatQuoted` amount passes through untouched. On a fiat amount the oracle is
/// consulted (DIRECT HTTP); on success the amount becomes `FiatQuoted` with the
/// locked nanogrin and the expiry is clamped to the quote-lock window so the
/// locked rate is never honoured past it. On failure a clear HTTP error is
/// returned (never a silently unpriced invoice).
async fn price_if_fiat(
    oracle: &Oracle,
    mut params: NewInvoice,
) -> Result<NewInvoice, HttpResponse> {
    let AmountSpec::Fiat { amount, currency } = &params.amount else {
        return Ok(params);
    };
    let (amount, currency) = (amount.clone(), currency.clone());
    match oracle.quote(&amount, &currency).await {
        Ok(quote) => {
            // The quote lock window (GP_QUOTE_TTL) caps the invoice expiry: a
            // shorter requested expiry is kept, anything longer (or unset) is
            // clamped so the rate is not honoured beyond its lock.
            let ttl = oracle.quote_ttl_secs();
            params.expiry_secs = Some(match params.expiry_secs {
                Some(secs) if secs > 0 && secs < ttl => secs,
                _ => ttl,
            });
            params.amount = AmountSpec::FiatQuoted {
                amount,
                currency,
                nanogrin: quote.nanogrin,
                rate: gp_core::rates::format_rate(quote.fiat_per_grin),
                source: quote.source.to_string(),
            };
            Ok(params)
        }
        Err(e) => Err(rate_error_response(&e)),
    }
}

/// Map an oracle failure to a clear HTTP error so create-invoice never returns
/// an unpriceable invoice: bad input is a 400, an unreachable source is a 502.
fn rate_error_response(err: &RateError) -> HttpResponse {
    match err {
        RateError::UnsupportedCurrency(_) | RateError::BadAmount(_) => {
            HttpResponse::BadRequest().json(serde_json::json!({"error": err.to_string()}))
        }
        RateError::SourceUnavailable(_) => {
            error!("create invoice: {err}");
            HttpResponse::BadGateway().json(serde_json::json!({"error": err.to_string()}))
        }
        RateError::Config(_) => {
            error!("create invoice: {err}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": err.to_string()}))
        }
    }
}

/// Master Nostr secret bytes (for per-invoice derivation).
fn master_secret(keys: &Keys) -> [u8; 32] {
    keys.secret_key().to_secret_bytes()
}
