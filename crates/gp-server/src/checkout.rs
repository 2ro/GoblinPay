//! The hosted, zero-JS checkout: the `/pay/<token>` page (shared renderer for
//! embedded and hosted use), its live status, and the manual-slatepack
//! fallback.
//!
//! The page shows the amount, a server-generated QR SVG of the recipient
//! `nprofile`, the `nprofile`/`npub` strings, live status via a
//! `<meta http-equiv="refresh">` while open, and a `<textarea>` POST form to
//! paste an S1 slatepack when the automatic Nostr flow cannot be used. On
//! submit, the same offline `receive_tx` runs and the S2 reply renders back for
//! the payer to copy and finalize. No JavaScript anywhere.

use actix_web::{web, HttpResponse, Responder};
use askama::Template;
use gp_core::config::Config;
use gp_core::invoice::{self, Invoice, InvoiceStatus};
use gp_core::qr;
use gp_core::webhook::nanogrin_to_grin;
use gp_nostr::PublicKey;
use gp_wallet::GpWallet;
use log::error;
use serde::Deserialize;
use sqlx::SqlitePool;

/// Everything the checkout page (and the create-invoice API) present for one
/// invoice.
#[derive(Debug, Clone)]
pub struct CheckoutInfo {
    pub invoice_id: String,
    pub token: String,
    pub pay_url: String,
    pub recipient_pubkey: String,
    pub npub: String,
    pub nprofile: String,
    pub qr_svg: String,
    pub amount_display: String,
    pub status: String,
    pub memo: Option<String>,
    pub order_ref: Option<String>,
}

/// Build the presentation for an invoice: the nprofile, its QR, the pay URL,
/// and a human amount. Shared by the hosted page and the connector API so both
/// render identically.
pub fn build_info(inv: &Invoice, cfg: &Config) -> CheckoutInfo {
    let relays = gp_nostr::relays::resolve(&cfg.relays);
    let recipient_pubkey = inv.recipient_pubkey.clone().unwrap_or_default();
    let (npub, nprofile) = match PublicKey::from_hex(&recipient_pubkey) {
        Ok(pk) => (gp_nostr::npub_of(pk), gp_nostr::nprofile(pk, &relays)),
        Err(_) => (String::new(), String::new()),
    };
    let qr_svg = qr::svg(&nprofile, cfg.qr_logo_href()).unwrap_or_default();
    let amount_display = amount_display(inv);
    let token = inv.token.clone().unwrap_or_default();
    CheckoutInfo {
        invoice_id: inv.id.clone(),
        pay_url: format!("{}/pay/{}", cfg.public_url, token),
        token,
        recipient_pubkey,
        npub,
        nprofile,
        qr_svg,
        amount_display,
        status: inv.status.clone(),
        memo: inv.memo.clone(),
        order_ref: inv.order_ref.clone(),
    }
}

/// Human amount for display: a priced fiat invoice shows both the fiat charge
/// and its locked Grin quote, an exact-Grin invoice shows Grin, an unpriced
/// fiat invoice notes the quote is pending, and an open amount shows "any".
fn amount_display(inv: &Invoice) -> String {
    match (inv.expected_amount, &inv.fiat_amount, &inv.fiat_currency) {
        // Priced fiat quote: the fiat charge with its locked Grin equivalent.
        (Some(nano), Some(amount), Some(currency)) => {
            format!(
                "{amount} {currency} (~{} GRIN)",
                nanogrin_to_grin(nano as u64)
            )
        }
        // Exact Grin invoice.
        (Some(nano), _, _) => format!("{} GRIN", nanogrin_to_grin(nano as u64)),
        // Fiat invoice not yet priced (oracle disabled/deferred).
        (None, Some(amount), Some(currency)) => format!("{amount} {currency} (Grin quote pending)"),
        _ => "any amount".to_string(),
    }
}

/// The checkout page template.
#[derive(Template)]
#[template(path = "pay.html")]
struct PayPage {
    info: CheckoutInfo,
    is_open: bool,
    is_paid: bool,
    is_expired: bool,
    wallet_available: bool,
}

/// The manual-slatepack result template (S2 to copy back).
#[derive(Template)]
#[template(path = "pay_result.html")]
struct PayResultPage {
    token: String,
    ok: bool,
    message: String,
    s2_armor: String,
}

/// Register the checkout routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/pay/{token}", web::get().to(pay_page))
        .route("/pay/{token}/status", web::get().to(pay_status))
        .route("/pay/{token}/slatepack", web::post().to(manual_slatepack));
}

/// GET /pay/{token}: the hosted checkout page.
async fn pay_page(
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
    wallet: web::Data<Option<GpWallet>>,
) -> impl Responder {
    let token = path.into_inner();
    let inv = match invoice::get_by_token(pool.get_ref(), &token).await {
        Ok(Some(inv)) => inv,
        Ok(None) => return HttpResponse::NotFound().body("invoice not found"),
        Err(e) => {
            error!("pay: lookup failed: {e}");
            return HttpResponse::InternalServerError().body("internal error");
        }
    };
    let status = inv.status();
    let page = PayPage {
        info: build_info(&inv, cfg.get_ref()),
        is_open: status == InvoiceStatus::Open,
        is_paid: status == InvoiceStatus::Paid,
        is_expired: status == InvoiceStatus::Expired,
        wallet_available: wallet.get_ref().is_some(),
    };
    render(page)
}

/// GET /pay/{token}/status: status JSON for polling (public-by-token).
async fn pay_status(path: web::Path<String>, pool: web::Data<SqlitePool>) -> impl Responder {
    let token = path.into_inner();
    match invoice::get_by_token(pool.get_ref(), &token).await {
        Ok(Some(inv)) => HttpResponse::Ok().json(serde_json::json!({
            "invoice_id": inv.id,
            "status": inv.status,
            "expected_amount": inv.expected_amount,
            "paid_payment_id": inv.paid_payment_id,
        })),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "not found"})),
        Err(e) => {
            error!("pay status: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

/// Manual-slatepack form body.
#[derive(Deserialize)]
struct ManualForm {
    slatepack: String,
}

/// POST /pay/{token}/slatepack: offline receive of a pasted S1, rendering S2.
async fn manual_slatepack(
    path: web::Path<String>,
    form: web::Form<ManualForm>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
    wallet: web::Data<Option<GpWallet>>,
) -> impl Responder {
    let token = path.into_inner();
    let inv = match invoice::get_by_token(pool.get_ref(), &token).await {
        Ok(Some(inv)) => inv,
        Ok(None) => return HttpResponse::NotFound().body("invoice not found"),
        Err(e) => {
            error!("manual: lookup failed: {e}");
            return HttpResponse::InternalServerError().body("internal error");
        }
    };

    let Some(wallet) = wallet.get_ref().as_ref() else {
        return render(PayResultPage {
            token,
            ok: false,
            message: "Manual receive is unavailable on this instance (wallet not loaded).".into(),
            s2_armor: String::new(),
        });
    };

    // Offline receive_tx (no node), exactly the wallet path the Nostr flow
    // uses. Then persist + match + webhook via the shared helper, so a manual
    // payment lands in the ledger like any other.
    let s1 = form.slatepack.trim().to_string();
    let page = match wallet.receive_slatepack(&s1) {
        Ok(received) => {
            let webhook = match (cfg.webhook_url.clone(), cfg.webhook_secret.as_ref()) {
                (Some(url), Some(secret)) => Some((url, secret.reveal().to_string())),
                _ => None,
            };
            crate::record::persist_and_match(
                pool.get_ref(),
                &received,
                None,
                inv.recipient_pubkey.as_deref().unwrap_or_default(),
                inv.order_ref.as_deref(),
                cfg.match_mode,
                webhook.as_ref(),
            )
            .await;
            PayResultPage {
                token,
                ok: true,
                message: "Payment received. Copy the response slatepack below back into your \
                          wallet to finalize and post it to the chain."
                    .into(),
                s2_armor: received.s2_armor,
            }
        }
        Err(e) => PayResultPage {
            token,
            ok: false,
            message: format!("That slatepack could not be received: {e}"),
            s2_armor: String::new(),
        },
    };
    render(page)
}

/// Render an Askama template to an HTML response.
fn render<T: Template>(page: T) -> HttpResponse {
    match page.render() {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(e) => {
            error!("template render failed: {e}");
            HttpResponse::InternalServerError().body("template error")
        }
    }
}
