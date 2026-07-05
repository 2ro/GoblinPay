//! The hosted, zero-JS checkout: the `/pay/<token>` page (shared renderer for
//! embedded and hosted use), its live status, and the Slatepack receive flow.
//!
//! The page offers two first-class ways to pay: the Goblin/Nostr path (a QR
//! SVG of the recipient `nprofile` plus the `nprofile`/`npub` strings) and a
//! Slatepack (`grin1`) path for any Grin wallet (the wallet's stable index-0
//! Slatepack address, its QR, and a `<textarea>` POST form to paste the S1 the
//! payer's wallet produces). It also shows the amount and live status via a
//! `<meta http-equiv="refresh">` while open. On submit, the same offline
//! `receive_tx` runs and the S2 reply renders back for the payer to finalize
//! and broadcast. The Slatepack path only appears when a wallet is loaded. No
//! JavaScript anywhere.

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
    /// Path prefix the app is mounted under for building root-relative links in
    /// the hosted page (empty for a subdomain/root, e.g. `/pay` for a
    /// reverse-proxied path on the shop's existing domain). Derived from
    /// `GP_PUBLIC_URL` so path hosting needs zero new DNS records.
    pub base: String,
    pub pay_url: String,
    pub recipient_pubkey: String,
    pub npub: String,
    pub nprofile: String,
    pub qr_svg: String,
    /// The wallet's stable `grin1` Slatepack address, when a wallet is loaded
    /// AND the plain-send fallback is permitted for this invoice (the render
    /// gate: an amount collision with an earlier open grin1 invoice hides it).
    /// `None` (and no plain-send panel shown) otherwise.
    pub slatepack_address: Option<String>,
    /// QR SVG of the `grin1` Slatepack address (present with the address).
    pub slatepack_qr_svg: Option<String>,
    /// The armored I1 invoice slatepack (grin1 rail, native invoice flow): the
    /// PRIMARY "pay with any Grin wallet" method. `None` off the rail.
    pub invoice_slatepack: Option<String>,
    /// QR SVG of the armored I1 invoice slatepack (present with it).
    pub invoice_slatepack_qr_svg: Option<String>,
    pub amount_display: String,
    pub status: String,
    pub memo: Option<String>,
    pub order_ref: Option<String>,
}

/// Build the presentation for an invoice: the nprofile, its QR, the pay URL,
/// and a human amount. Shared by the hosted page and the connector API so both
/// render identically.
///
/// `slatepack_addr` is the wallet's stable `grin1` Slatepack address when a
/// wallet is loaded (the hosted page passes it so a payer can pay from any Grin
/// wallet without Nostr); pass `None` when no wallet is available or the
/// caller does not surface the Slatepack option (e.g. the JSON connector API),
/// in which case no Slatepack address or QR is produced.
pub fn build_info(
    inv: &Invoice,
    cfg: &Config,
    slatepack_addr: Option<&str>,
    invoice_slatepack: Option<&str>,
    plain_send_allowed: bool,
) -> CheckoutInfo {
    let relays = gp_nostr::relays::resolve(cfg.relay_mode, &cfg.bundled_relay_url, &cfg.relays);
    let recipient_pubkey = inv.recipient_pubkey.clone().unwrap_or_default();
    // The Nostr (Goblin Wallet) method is only surfaced when the operator has it
    // enabled (`GP_CHECKOUT_METHODS`). Disabled, the nprofile/npub/QR are left
    // empty and the template omits the whole section. This gates only the hosted
    // PAGE display; the connector API and ingest are unaffected.
    let (npub, nprofile) = if cfg.checkout_nostr {
        match PublicKey::from_hex(&recipient_pubkey) {
            Ok(pk) => (gp_nostr::npub_of(pk), gp_nostr::nprofile(pk, &relays)),
            Err(_) => (String::new(), String::new()),
        }
    } else {
        (String::new(), String::new())
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
    let qr_svg = qr::svg(&qr_payload, cfg.qr_logo()).unwrap_or_default();
    // The Slatepack (grin1) address is stable and reused across invoices; its
    // QR carries the bare address (a Grin wallet reads no amount from it, so
    // the page states the amount to send in text next to it). No address means
    // no wallet loaded: the page simply omits the Slatepack option.
    // The Slatepack method needs both operator opt-in (`GP_CHECKOUT_METHODS`)
    // and a loaded wallet: an enabled method that cannot work is simply hidden.
    // The whole "pay with any Grin wallet" rail is operator opt-in
    // (GP_GRIN1_RAIL, packaged default OFF): with the rail off the page shows
    // only the Goblin method, even for an invoice armed while it was on.
    // The plain-send fallback (an exact-amount receive to the stable grin1
    // address) additionally needs the slatepack method enabled, a wallet
    // address, AND the render gate (no amount collision with an earlier open
    // grin1 invoice; Phase 3, no jitter).
    let grin_rail_on = cfg.grin1_rail && cfg.checkout_slatepack;
    let (slatepack_address, slatepack_qr_svg) = match slatepack_addr {
        Some(addr) if grin_rail_on && plain_send_allowed && !addr.is_empty() => {
            let qr = qr::svg(addr, cfg.qr_logo()).unwrap_or_default();
            (Some(addr.to_string()), Some(qr))
        }
        _ => (None, None),
    };
    // The native invoice slatepack (I1) is the primary Grin-wallet method; it is
    // shown whenever the invoice is armed on the grin1 rail (and the rail is
    // still on). Its QR carries the armored slatepack text verbatim.
    let (invoice_slatepack, invoice_slatepack_qr_svg) = match invoice_slatepack {
        Some(armor) if grin_rail_on && !armor.is_empty() => {
            let qr = qr::svg(armor, cfg.qr_logo()).unwrap_or_default();
            (Some(armor.to_string()), Some(qr))
        }
        _ => (None, None),
    };
    let amount_display = amount_display(inv);
    let token = inv.token.clone().unwrap_or_default();
    CheckoutInfo {
        invoice_id: inv.id.clone(),
        base: gp_core::setup::base_path(&cfg.public_url),
        pay_url: format!("{}/pay/{}", cfg.public_url, token),
        token,
        recipient_pubkey,
        npub,
        nprofile,
        qr_svg,
        slatepack_address,
        slatepack_qr_svg,
        invoice_slatepack,
        invoice_slatepack_qr_svg,
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

/// The checkout page template. `is_paid` is the "received, confirming on chain"
/// state (funds in hand, below the confirmation threshold); `is_confirmed` is
/// the final settled state at/above the threshold. `confirmations` /
/// `confirmations_required` drive the "n of N" progress shown while confirming.
#[derive(Template)]
#[template(path = "pay.html")]
struct PayPage {
    info: CheckoutInfo,
    is_open: bool,
    is_paid: bool,
    is_confirmed: bool,
    is_expired: bool,
    confirmations: i64,
    confirmations_required: i64,
}

/// The manual-slatepack result template (S2 to copy back).
#[derive(Template)]
#[template(path = "pay_result.html")]
struct PayResultPage {
    /// Mount path prefix for root-relative links (see `CheckoutInfo::base`).
    base: String,
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
    let confirmations = invoice::confirmations(pool.get_ref(), &inv.id)
        .await
        .unwrap_or(0);
    // Surface the wallet's stable grin1 Slatepack address (same wallet handle
    // the manual receive uses). No wallet loaded, or the address cannot be
    // derived, means no Slatepack option is shown.
    let slatepack_addr = wallet
        .get_ref()
        .as_ref()
        .and_then(|w| w.slatepack_address().ok());
    // Render gate for the plain-send fallback panel (Phase 3): an amount
    // collision with an earlier open grin1 invoice hides this one's panel.
    let plain_send_allowed = invoice::plain_send_allowed(pool.get_ref(), &inv)
        .await
        .unwrap_or(false);
    let page = PayPage {
        info: build_info(
            &inv,
            cfg.get_ref(),
            slatepack_addr.as_deref(),
            inv.slatepack.as_deref(),
            plain_send_allowed,
        ),
        is_open: status == InvoiceStatus::Open,
        is_paid: status == InvoiceStatus::Paid,
        is_confirmed: status == InvoiceStatus::Confirmed,
        is_expired: status == InvoiceStatus::Expired,
        confirmations,
        confirmations_required: cfg.confirmations_required,
    };
    render(page)
}

/// GET /pay/{token}/status: status JSON for polling (public-by-token).
/// `status` advances open -> paid -> confirmed (paid remains a real,
/// backward-compatible state); `confirmations` is the paying kernel's live
/// depth and `confirmations_required` is the house threshold.
async fn pay_status(
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    let token = path.into_inner();
    match invoice::get_by_token(pool.get_ref(), &token).await {
        Ok(Some(inv)) => {
            let confirmations = invoice::confirmations(pool.get_ref(), &inv.id)
                .await
                .unwrap_or(0);
            HttpResponse::Ok().json(serde_json::json!({
                "invoice_id": inv.id,
                "status": inv.status,
                "expected_amount": inv.expected_amount,
                "paid_payment_id": inv.paid_payment_id,
                "confirmations": confirmations,
                "confirmations_required": cfg.confirmations_required,
            }))
        }
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

/// Where a pasted slatepack goes (GRIM-parity manual fallback: every rail is
/// completable by copy-paste when the automatic Tor path fails).
#[derive(Debug, PartialEq, Eq)]
enum PasteRoute {
    /// A plain-send S1: the existing offline receive path.
    ReceiveS1,
    /// The invoice response (I2) for THIS invoice, arriving by browser
    /// instead of onion: finalize + post + settle by slate id.
    FinalizeI2,
    /// Neither: a clean, human-readable rejection.
    Reject(String),
}

/// Route a decoded paste. Pure so the decision is unit-testable: `state` is
/// the compact slate-state name ("S1"/"I2"/...), `slate_id` the pasted slate's
/// id, `inv` the invoice whose pay page received the paste.
fn route_paste(state: &str, slate_id: &str, inv: &Invoice) -> PasteRoute {
    match state {
        "S1" => PasteRoute::ReceiveS1,
        "I2" => {
            if inv.status() != InvoiceStatus::Open {
                // Already settled (possibly by the Tor return of this same
                // slate racing the paste): nothing to do, never settle twice.
                return PasteRoute::Reject(
                    "This invoice has already been paid or is no longer open; \
                     nothing more to submit."
                        .into(),
                );
            }
            if inv.is_grin1() && inv.slate_id.as_deref() == Some(slate_id) {
                PasteRoute::FinalizeI2
            } else {
                PasteRoute::Reject(
                    "That looks like an invoice response, but it does not belong to \
                     this invoice. Check you pasted the response for the invoice on \
                     this page."
                        .into(),
                )
            }
        }
        other => PasteRoute::Reject(format!(
            "That slatepack is in state {other}; expected a payment (S1) or an \
             invoice response (I2)."
        )),
    }
}

/// POST /pay/{token}/slatepack: the dual-purpose paste form. A plain-send S1
/// runs the offline receive and renders the S2 to copy back; an invoice
/// response (I2) matching this invoice's slate id is finalized + posted here
/// (the manual fallback for a payer wallet that cannot reach the onion).
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

    // The path prefix the app is mounted under (empty for a subdomain/root,
    // `/pay` for path hosting), so the result page's links stay correct under a
    // reverse-proxied path.
    let base = gp_core::setup::base_path(&cfg.public_url);

    let Some(wallet) = wallet.get_ref().as_ref() else {
        return render(PayResultPage {
            base,
            token,
            ok: false,
            message: "Manual receive is unavailable on this instance (wallet not loaded).".into(),
            s2_armor: String::new(),
        });
    };

    let armor = form.slatepack.trim().to_string();
    let route = match wallet.slatepack_kind(&armor) {
        Ok((slate_id, state)) => route_paste(&state, &slate_id, &inv),
        Err(e) => PasteRoute::Reject(format!("That slatepack could not be read: {e}")),
    };

    // Compute the outcome (ok, message, S2-to-copy) once, then render a single
    // PayResultPage; this keeps the money-path branches focused on the receive/
    // finalize logic rather than repeating the page shell.
    let (ok, message, s2_armor): (bool, String, String) = match route {
        PasteRoute::Reject(message) => (false, message, String::new()),
        PasteRoute::ReceiveS1 => {
            // Offline receive_tx (no node), exactly the wallet path the Nostr
            // flow uses; persist + match + webhook via the shared helper.
            match wallet.receive_slatepack(&armor) {
                Ok(received) => {
                    let webhook = crate::foreign::webhook_pair(cfg.get_ref());
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
                    (
                        true,
                        "Payment received. Copy the response slatepack below back \
                         into your wallet to finalize and post it to the chain."
                            .into(),
                        received.s2_armor,
                    )
                }
                Err(e) => (
                    false,
                    format!("That slatepack could not be received: {e}"),
                    String::new(),
                ),
            }
        }
        PasteRoute::FinalizeI2 => {
            // Same payload the onion endpoint would get, arriving by browser:
            // finalize from our stored context, post the tx (blocking node
            // I/O, so off the async workers), then settle by slate id. The
            // settle is idempotent (payment id + open->paid transition) and a
            // replayed finalize fails cleanly in the wallet (context already
            // deleted), so racing the Tor return cannot double-settle or
            // double-post.
            let w = wallet.clone();
            let a = armor.clone();
            let finalized =
                actix_web::rt::task::spawn_blocking(move || w.finalize_invoice_slatepack(&a))
                    .await;
            match finalized {
                Ok(Ok(finalized)) => {
                    let webhook = crate::foreign::webhook_pair(cfg.get_ref());
                    crate::foreign::settle_finalized(pool.get_ref(), &finalized, webhook.as_ref())
                        .await;
                    (
                        true,
                        "Invoice response received: the payment has been finalized \
                         and posted to the chain. Nothing more to paste; this page \
                         will show confirmations as they arrive."
                            .into(),
                        String::new(),
                    )
                }
                Ok(Err(e)) => (
                    false,
                    format!("That invoice response could not be finalized: {e}"),
                    String::new(),
                ),
                Err(e) => {
                    error!("manual finalize task panicked: {e}");
                    (
                        false,
                        "Internal error while finalizing; please try again.".into(),
                        String::new(),
                    )
                }
            }
        }
    };
    render(PayResultPage {
        base,
        token,
        ok,
        message,
        s2_armor,
    })
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
            confirmed_at: None,
            rail: None,
            slate_id: None,
            slatepack: None,
        }
    }

    /// An open grin1-rail invoice fixture with an issued slate id.
    fn grin1_invoice(slate_id: &str) -> Invoice {
        let mut inv = invoice(Some(1_000_000_000), None);
        inv.rail = Some("grin1".into());
        inv.slate_id = Some(slate_id.to_string());
        inv.slatepack = Some("BEGINSLATEPACK.i1.ENDSLATEPACK.".into());
        inv
    }

    #[test]
    fn paste_router_sends_each_rail_to_its_path() {
        let inv = grin1_invoice("slate-abc");
        // A plain-send S1 always goes to the existing receive path.
        assert_eq!(route_paste("S1", "any-id", &inv), PasteRoute::ReceiveS1);
        // The invoice response with the matching slate id finalizes.
        assert_eq!(route_paste("I2", "slate-abc", &inv), PasteRoute::FinalizeI2);
        // An I2 for a DIFFERENT slate is rejected with a human message.
        match route_paste("I2", "slate-other", &inv) {
            PasteRoute::Reject(m) => assert!(m.contains("does not belong"), "{m}"),
            other => panic!("expected reject, got {other:?}"),
        }
        // An I2 pasted on a non-grin1 invoice is rejected.
        let plain = invoice(Some(1), None);
        match route_paste("I2", "slate-abc", &plain) {
            PasteRoute::Reject(m) => assert!(m.contains("does not belong"), "{m}"),
            other => panic!("expected reject, got {other:?}"),
        }
        // Any other slate state is rejected, naming the state.
        match route_paste("S2", "any-id", &inv) {
            PasteRoute::Reject(m) => assert!(m.contains("state S2"), "{m}"),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn paste_router_never_settles_a_non_open_invoice_twice() {
        // The double-settle guard: once the Tor return (or a first paste) has
        // flipped the invoice paid, a racing paste of the SAME slate is
        // rejected before any wallet call, so it cannot double-settle or
        // double-post. (The deeper backstops are settle_finalized's
        // open->paid idempotency and the wallet deleting the context on the
        // first finalize.)
        for status in ["paid", "confirmed", "expired"] {
            let mut inv = grin1_invoice("slate-abc");
            inv.status = status.into();
            match route_paste("I2", "slate-abc", &inv) {
                PasteRoute::Reject(m) => {
                    assert!(m.contains("already been paid"), "{status}: {m}")
                }
                other => panic!("{status}: expected reject, got {other:?}"),
            }
        }
    }

    /// A config with the grin1 rail armed (it is OFF by default, owner ruling).
    fn grin1_cfg() -> Config {
        Config {
            grin1_rail: true,
            ..Config::default()
        }
    }

    #[test]
    fn build_info_surfaces_slatepack_address_when_wallet_loaded() {
        // A loaded wallet passes its grin1 address: build_info exposes it plus
        // a QR for it, so the hosted page can show the Slatepack option.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = grin1_cfg();
        // Plain-send permitted (render gate allowed): the address surfaces.
        let info = build_info(&inv, &cfg, Some("grin1qtestaddress"), None, true);
        assert_eq!(info.slatepack_address.as_deref(), Some("grin1qtestaddress"));
        let qr = info.slatepack_qr_svg.expect("slatepack QR present");
        assert!(qr.contains("<svg"), "grin1 QR is an SVG");
    }

    #[test]
    fn grin1_rail_off_strips_all_grin_ui_and_switcher() {
        // Owner requirement: with GP_GRIN1_RAIL off (the packaged default),
        // the page shows ONLY "Pay with Goblin" — no switcher, no grin1 UI —
        // even when a wallet address and an armed invoice slatepack exist.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = Config::default(); // grin1_rail defaults OFF
        assert!(!cfg.grin1_rail, "packaged default must be off");
        let info = build_info(
            &inv,
            &cfg,
            Some("grin1qtestaddress"),
            Some("BEGINSLATEPACK.inv.ENDSLATEPACK."),
            true,
        );
        assert!(info.slatepack_address.is_none(), "no plain-send when off");
        assert!(info.slatepack_qr_svg.is_none());
        assert!(info.invoice_slatepack.is_none(), "no invoice pack when off");
        assert!(info.invoice_slatepack_qr_svg.is_none());
        assert!(!info.nprofile.is_empty(), "Goblin method still present");

        let page = PayPage {
            info,
            is_open: true,
            is_paid: false,
            is_confirmed: false,
            is_expired: false,
            confirmations: 0,
            confirmations_required: 10,
        };
        let html = page.render().unwrap();
        assert!(!html.contains("rail-tab"), "no switcher when rail off");
        assert!(!html.contains("rail-radio"), "no switcher radios either");
        assert!(!html.contains("id=\"panel-grin\""), "no grin panel");
        assert!(!html.contains("grin1qtestaddress"), "no grin1 address");
        assert!(!html.contains("BEGINSLATEPACK"), "no invoice slatepack");
        assert!(html.contains("id=\"panel-goblin\""), "Goblin panel present");
        assert!(
            html.contains("Nostr</p>"),
            "footer reads like the pre-rail page (no 'and Tor')"
        );
    }

    #[test]
    fn grin1_rail_on_shows_switcher_with_goblin_default_selected() {
        // Owner requirement: rail enabled => the two-rail switcher renders and
        // the Goblin tab is the default-selected one.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = grin1_cfg();
        let info = build_info(
            &inv,
            &cfg,
            Some("grin1qtestaddress"),
            Some("BEGINSLATEPACK.inv.ENDSLATEPACK."),
            true,
        );
        let page = PayPage {
            info,
            is_open: true,
            is_paid: false,
            is_confirmed: false,
            is_expired: false,
            confirmations: 0,
            confirmations_required: 10,
        };
        let html = page.render().unwrap();
        assert!(
            html.contains(r#"id="rail-goblin" checked"#),
            "Goblin rail is the default-selected tab"
        );
        assert!(
            !html.contains(r#"id="rail-grin" checked"#),
            "Grin rail is the alternative, not preselected"
        );
        assert!(html.contains("Pay with Goblin"), "Goblin tab label");
        assert!(html.contains("Pay with any Grin wallet"), "Grin tab label");
        assert!(html.contains("id=\"panel-goblin\""));
        assert!(html.contains("id=\"panel-grin\""));
    }

    #[test]
    fn render_gate_hides_plain_send_address_but_keeps_invoice_slatepack() {
        // The gate denies the plain-send address (amount collision), but the
        // primary invoice slatepack still renders.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = grin1_cfg();
        let info = build_info(
            &inv,
            &cfg,
            Some("grin1qtestaddress"),
            Some("BEGINSLATEPACK.inv.ENDSLATEPACK."),
            false,
        );
        assert!(info.slatepack_address.is_none(), "plain-send gated off");
        assert!(info.slatepack_qr_svg.is_none());
        assert_eq!(
            info.invoice_slatepack.as_deref(),
            Some("BEGINSLATEPACK.inv.ENDSLATEPACK.")
        );
        assert!(info
            .invoice_slatepack_qr_svg
            .as_deref()
            .unwrap()
            .contains("<svg"));
    }

    #[test]
    fn build_info_omits_slatepack_when_no_wallet() {
        // No wallet (None) or a blank address: no Slatepack address or QR, so
        // the page simply does not show the Slatepack option.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = grin1_cfg();
        let info = build_info(&inv, &cfg, None, None, true);
        assert!(info.slatepack_address.is_none());
        assert!(info.slatepack_qr_svg.is_none());
        let blank = build_info(&inv, &cfg, Some(""), None, true);
        assert!(blank.slatepack_address.is_none());
        assert!(blank.slatepack_qr_svg.is_none());
    }

    #[test]
    fn checkout_nostr_disabled_hides_nostr_section() {
        // GP_CHECKOUT_METHODS=slatepack: the Nostr method is off, so build_info
        // leaves the nprofile/npub empty and the page omits the Nostr section
        // while still showing the Slatepack one.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = Config {
            checkout_nostr: false,
            checkout_slatepack: true,
            grin1_rail: true,
            ..Config::default()
        };
        let info = build_info(&inv, &cfg, Some("grin1qtestaddress"), None, true);
        assert!(info.nprofile.is_empty(), "nprofile empty when nostr off");
        assert!(info.npub.is_empty(), "npub empty when nostr off");
        assert_eq!(info.slatepack_address.as_deref(), Some("grin1qtestaddress"));

        let page = PayPage {
            info,
            is_open: true,
            is_paid: false,
            is_confirmed: false,
            is_expired: false,
            confirmations: 0,
            confirmations_required: 10,
        };
        let html = page.render().unwrap();
        // The Goblin rail (nprofile) is absent; the Grin rail is present.
        assert!(
            !html.contains("id=\"rail-goblin\""),
            "Goblin rail absent when checkout_nostr=false"
        );
        assert!(
            html.contains("id=\"panel-grin\""),
            "Grin rail present"
        );
        assert!(html.contains("Send to address"), "plain-send panel present");
    }

    #[test]
    fn checkout_slatepack_disabled_hides_slatepack_section() {
        // GP_CHECKOUT_METHODS=nostr: the Slatepack method is off, so even with a
        // wallet address available, build_info drops it and the page omits the
        // Slatepack section while still showing the Nostr one.
        let inv = invoice(Some(1_500_000_000), None);
        let cfg = Config {
            checkout_nostr: true,
            checkout_slatepack: false,
            grin1_rail: true,
            ..Config::default()
        };
        let info = build_info(
            &inv,
            &cfg,
            Some("grin1qtestaddress"),
            Some("BEGINSLATEPACK.inv.ENDSLATEPACK."),
            true,
        );
        assert!(
            info.slatepack_address.is_none(),
            "plain-send dropped when method off"
        );
        assert!(info.slatepack_qr_svg.is_none());
        assert!(
            info.invoice_slatepack.is_none(),
            "invoice slatepack dropped when method off"
        );
        assert!(!info.nprofile.is_empty(), "nprofile present when nostr on");

        let page = PayPage {
            info,
            is_open: true,
            is_paid: false,
            is_confirmed: false,
            is_expired: false,
            confirmations: 0,
            confirmations_required: 10,
        };
        let html = page.render().unwrap();
        assert!(html.contains("id=\"panel-goblin\""), "Goblin rail present");
        assert!(
            !html.contains("id=\"panel-grin\""),
            "Grin rail absent when checkout_slatepack=false"
        );
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
