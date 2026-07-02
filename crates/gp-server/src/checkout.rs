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
    // The QR carries a pay-URI so a scanning wallet can auto-fill the amount
    // (and memo). The human-readable nprofile/npub strings on the page are
    // unchanged — only the QR payload gains the query. An invalid pubkey yields
    // an empty nprofile; keep that empty (no useless `nostr:` QR).
    let qr_payload = if nprofile.is_empty() {
        nprofile.clone()
    } else {
        pay_uri(&nprofile, inv)
    };
    let qr_svg = qr::svg(&qr_payload, cfg.qr_logo_href()).unwrap_or_default();
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

/// Build the QR pay-URI for an invoice: `nostr:<nprofile>`, plus `?amount=`
/// when the invoice has an exact expected amount, plus `&memo=` when it carries
/// a human memo. A scanning Goblin wallet auto-fills the amount (and note) from
/// this; open-amount invoices stay a bare `nostr:<nprofile>`.
///
/// The URI never carries the invoice token or any key — only the already-public
/// recipient nprofile, relay hints, the amount, and the human memo shown on the
/// page. `expected_amount` is a locked nanogrin quote (i64 in the DB, always
/// non-negative here); only strictly positive amounts are emitted.
fn pay_uri(nprofile: &str, inv: &Invoice) -> String {
    let mut uri = format!("nostr:{nprofile}");
    let mut sep = '?';
    if let Some(nano) = inv.expected_amount {
        if nano > 0 {
            uri.push(sep);
            uri.push_str("amount=");
            uri.push_str(&nanogrin_to_grin(nano as u64));
            sep = '&';
        }
    }
    if let Some(memo) = inv.memo.as_deref() {
        let memo = memo.trim();
        if !memo.is_empty() {
            uri.push(sep);
            uri.push_str("memo=");
            uri.push_str(&percent_encode(memo));
        }
    }
    uri
}

/// Minimal RFC-3986 percent-encoding for a query value: keep the unreserved set
/// (`A-Z a-z 0-9 - . _ ~`), percent-escape every other byte. Small and
/// dependency-free (gp-core has no percent-encoding crate).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal invoice fixture: only the fields the QR pay-URI reads matter.
    fn invoice(expected_amount: Option<i64>, memo: Option<&str>) -> Invoice {
        Invoice {
            id: "inv_1".into(),
            order_ref: None,
            expected_amount,
            expiry: None,
            status: "open".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            token: Some("secret-token-should-never-leak".into()),
            memo: memo.map(str::to_string),
            recipient_pubkey: Some("aa".repeat(32)),
            fiat_amount: None,
            fiat_currency: None,
            match_mode: None,
            paid_payment_id: None,
            paid_at: None,
            quote_rate: None,
            quote_source: None,
        }
    }

    #[test]
    fn amount_invoice_encodes_amount() {
        // 1.5 GRIN → nostr:<nprofile>?amount=1.5
        let inv = invoice(Some(1_500_000_000), None);
        assert_eq!(
            pay_uri("nprofile1abc", &inv),
            "nostr:nprofile1abc?amount=1.5"
        );
    }

    #[test]
    fn open_amount_invoice_stays_bare() {
        // Open amount (no expected_amount, no memo) → bare nostr:<nprofile>.
        let inv = invoice(None, None);
        assert_eq!(pay_uri("nprofile1abc", &inv), "nostr:nprofile1abc");
    }

    #[test]
    fn amount_and_memo_encoded() {
        let inv = invoice(Some(1_000_000_000), Some("Coffee & cake"));
        assert_eq!(
            pay_uri("nprofile1abc", &inv),
            "nostr:nprofile1abc?amount=1&memo=Coffee%20%26%20cake"
        );
    }

    #[test]
    fn memo_only_uses_question_mark() {
        // No amount but a memo → the memo is the first (and only) query param.
        let inv = invoice(None, Some("hi"));
        assert_eq!(pay_uri("nprofile1abc", &inv), "nostr:nprofile1abc?memo=hi");
    }

    #[test]
    fn zero_and_blank_are_treated_as_open() {
        assert_eq!(
            pay_uri("nprofile1abc", &invoice(Some(0), None)),
            "nostr:nprofile1abc"
        );
        // A whitespace-only memo is dropped.
        assert_eq!(
            pay_uri("nprofile1abc", &invoice(None, Some("   "))),
            "nostr:nprofile1abc"
        );
    }

    #[test]
    fn uri_never_leaks_token_or_key() {
        // The token and recipient private material must never appear in the QR.
        let inv = invoice(Some(2_000_000_000), Some("order 42"));
        let uri = pay_uri("nprofile1abc", &inv);
        assert!(!uri.contains("secret-token-should-never-leak"));
        assert!(!uri.contains("token"));
    }

    #[test]
    fn percent_encode_covers_reserved_and_unicode() {
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(percent_encode("a b&c=d"), "a%20b%26c%3Dd");
        // Multi-byte UTF-8 is percent-encoded byte-by-byte.
        assert_eq!(percent_encode("é"), "%C3%A9");
    }
}
