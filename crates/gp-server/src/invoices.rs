//! The connector-facing invoice API (authenticated with `GP_API_TOKEN`):
//! create an invoice and read its checkout info. This is what a store
//! connector (WooCommerce, Medusa, generic REST) calls; it returns the hosted
//! `/pay/<token>` URL plus the nprofile + QR so the store can render or
//! redirect. All matching modes are supported per invoice.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use gp_core::config::{Config, MatchMode};
use gp_core::invoice::{self, AmountSpec, NewInvoice};
use gp_core::rates::{Oracle, RateError};
use gp_core::store::{CreateInvoiceRequest, RestConnector, StoreConnector};
use gp_nostr::Keys;
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

/// JSON shape returned for a created/fetched invoice.
fn checkout_json(info: &CheckoutInfo) -> serde_json::Value {
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
    let info = build_info(&inv, cfg.get_ref());
    HttpResponse::Ok().json(checkout_json(&info))
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
            let info = build_info(&inv, cfg.get_ref());
            HttpResponse::Ok().json(checkout_json(&info))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "not found"})),
        Err(e) => {
            error!("get invoice: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
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
