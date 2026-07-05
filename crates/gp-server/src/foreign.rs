//! The Grin Foreign API v2 (`POST /v2/foreign`), served on loopback for the
//! onion service to proxy (`onion:80 -> 127.0.0.1:<GP_GRIN1_FOREIGN_PORT>`).
//! This is the receiving surface of the grin1 rail: stock Grin senders speak
//! JSON-RPC 2.0 here exactly as they would to any grin-wallet listener.
//!
//! Methods:
//!   check_version  -> the Foreign API version + supported slate versions
//!   receive_tx     -> sender-initiated receive (S1 -> S2), recorded + matched
//!                     to an open invoice by AMOUNT (the plain-send fallback).
//!   finalize_tx    -> the native invoice-flow return leg: complete our issued
//!                     invoice from the payer's I2, POST it, and settle the
//!                     matching invoice by slate id (flip it `paid`).
//!
//! The wire shapes mirror grin-wallet's `foreign_rpc` (positional params, a
//! `VersionedSlate` in and out), so no custom client is needed. The heavy
//! wallet calls run off the async workers (`spawn_blocking`); node contact
//! (finalize posts the tx) goes DIRECT over HTTP.

use actix_web::{web, HttpResponse, Responder};
use gp_core::config::{Config, MatchMode};
use gp_core::invoice;
use gp_core::webhook::{enqueue, WebhookPayload};
use gp_wallet::{FinalizedInvoice, GpWallet, VersionedSlate};
use log::{error, warn};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::SqlitePool;

/// A JSON-RPC 2.0 request envelope (positional params, as grin-wallet uses).
#[derive(Deserialize)]
struct RpcRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Register the Foreign API route (mounted on the loopback foreign server).
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/v2/foreign", web::post().to(handle));
}

/// How often the grin1 expiry sweep runs. A cancel only matters before a late
/// I2 arrives, and finalize also rechecks the invoice status, so a slow sweep is
/// plenty.
const EXPIRY_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Spawn the grin1 expiry sweep: periodically expire due grin1 invoices and
/// `cancel_tx` their stored wallet contexts, so a late payer I2 for an expired
/// invoice fails cleanly instead of settling. `cancel` contacts the node and
/// blocks, so it runs off the async workers.
pub fn spawn_expiry_cancel(pool: SqlitePool, wallet: GpWallet) {
    actix_web::rt::spawn(async move {
        log::info!("grin1: expiry-cancel sweep every {EXPIRY_SWEEP_INTERVAL:?}");
        loop {
            actix_web::rt::time::sleep(EXPIRY_SWEEP_INTERVAL).await;
            let due = match invoice::due_grin1_slates(&pool).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("grin1 expiry sweep: {e}");
                    continue;
                }
            };
            for (inv_id, slate_id) in due {
                let w = wallet.clone();
                let sid = slate_id.clone();
                // Cancel first; only expire the invoice once its context is gone,
                // so a node hiccup leaves it open and the next pass retries.
                let res = actix_web::rt::task::spawn_blocking(move || w.cancel(&sid)).await;
                match res {
                    Ok(Ok(())) => {
                        if let Err(e) = invoice::mark_expired(&pool, &inv_id).await {
                            warn!("grin1: mark_expired {inv_id} failed: {e}");
                        } else {
                            log::info!("grin1: cancelled expired invoice slate {slate_id}");
                        }
                    }
                    Ok(Err(e)) => warn!("grin1: cancel {slate_id} failed (retries next pass): {e}"),
                    Err(e) => warn!("grin1: cancel task panicked for {slate_id}: {e}"),
                }
            }
        }
    });
}

/// A JSON-RPC success envelope.
fn ok(id: Value, result: Value) -> HttpResponse {
    HttpResponse::Ok().json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

/// A JSON-RPC error envelope (code -32603 internal / -32602 bad params).
fn err(id: Value, code: i64, message: impl Into<String>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "jsonrpc": "2.0", "id": id,
        "error": {"code": code, "message": message.into()},
    }))
}

/// The single POST handler dispatching the Foreign API methods.
async fn handle(
    body: web::Json<RpcRequest>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
    wallet: web::Data<Option<GpWallet>>,
) -> impl Responder {
    let RpcRequest { id, method, params } = body.into_inner();

    // check_version needs no wallet.
    if method == "check_version" {
        return ok(id, serde_json::to_value(gp_wallet::check_version()).unwrap());
    }

    let Some(wallet) = wallet.get_ref().as_ref() else {
        return err(id, -32603, "wallet not loaded");
    };

    match method.as_str() {
        "receive_tx" => receive_tx(id, params, pool.get_ref(), cfg.get_ref(), wallet).await,
        "finalize_tx" => finalize_tx(id, params, pool.get_ref(), cfg.get_ref(), wallet).await,
        other => err(id, -32601, format!("method `{other}` not found")),
    }
}

/// Parse the slate at positional param index 0.
fn slate_param(params: &Value) -> Result<VersionedSlate, String> {
    let slate = params
        .get(0)
        .ok_or_else(|| "missing slate parameter".to_string())?;
    serde_json::from_value(slate.clone()).map_err(|e| format!("bad slate: {e}"))
}

/// receive_tx: offline receive + record + amount-match, returning the S2 slate.
async fn receive_tx(
    id: Value,
    params: Value,
    pool: &SqlitePool,
    cfg: &Config,
    wallet: &GpWallet,
) -> HttpResponse {
    let in_slate = match slate_param(&params) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, e),
    };
    let w = wallet.clone();
    let received = actix_web::rt::task::spawn_blocking(move || w.receive_slate(in_slate)).await;
    let (out_slate, received) = match received {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return err(id, -32603, format!("receive failed: {e}")),
        Err(e) => return err(id, -32603, format!("receive task panicked: {e}")),
    };

    // Record + match by AMOUNT (the plain-send / sender-initiated mapping), then
    // hand back the S2. The money is already in hand, so a persist/match error
    // never fails the reply.
    let webhook = webhook_pair(cfg);
    crate::record::persist_and_match(
        pool,
        &received,
        None,
        "",
        None,
        MatchMode::Amount,
        webhook.as_ref(),
    )
    .await;

    ok(id, serde_json::to_value(out_slate).unwrap())
}

/// finalize_tx: complete + post our issued invoice from the payer's I2, then
/// settle the matching invoice (flip it `paid`). Returns the final slate.
async fn finalize_tx(
    id: Value,
    params: Value,
    pool: &SqlitePool,
    cfg: &Config,
    wallet: &GpWallet,
) -> HttpResponse {
    let in_slate = match slate_param(&params) {
        Ok(s) => s,
        Err(e) => return err(id, -32602, e),
    };
    let w = wallet.clone();
    let finalized = actix_web::rt::task::spawn_blocking(move || w.finalize_slate(in_slate)).await;
    let (out_slate, finalized) = match finalized {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return err(id, -32603, format!("finalize failed: {e}")),
        Err(e) => return err(id, -32603, format!("finalize task panicked: {e}")),
    };

    let webhook = webhook_pair(cfg);
    settle_finalized(pool, &finalized, webhook.as_ref()).await;
    ok(id, serde_json::to_value(out_slate).unwrap())
}

/// The (url, secret) webhook pair when one is configured.
pub(crate) fn webhook_pair(cfg: &Config) -> Option<(String, String)> {
    match (cfg.webhook_url.clone(), cfg.webhook_secret.as_ref()) {
        (Some(url), Some(secret)) => Some((url, secret.reveal().to_string())),
        _ => None,
    }
}

/// Settle a finalized invoice-flow payment: find the invoice we issued this
/// slate for, record the payment, and flip the invoice `paid`. The confirmation
/// poll then carries it to `confirmed`. Best-effort (the tx is already posted):
/// every error is logged and swallowed.
///
/// The ledger amount is the invoice's own expected amount, never the slate's:
/// an invoice-flow I2 carries a zeroed amount (the payer zeroes it), so the
/// slate is not a trustworthy amount source here.
pub(crate) async fn settle_finalized(
    pool: &SqlitePool,
    finalized: &FinalizedInvoice,
    webhook: Option<&(String, String)>,
) {
    let inv = match invoice::get_by_slate_id(pool, &finalized.slate_id).await {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            warn!(
                "foreign finalize: no invoice for slate {}",
                finalized.slate_id
            );
            return;
        }
        Err(e) => {
            error!("foreign finalize: invoice lookup for {}: {e}", finalized.slate_id);
            return;
        }
    };
    let amount = inv.expected_amount.unwrap_or(finalized.amount as i64).max(0) as u64;

    // Record the payment (id = slate id, its own unguessable bearer), linked to
    // the invoice, with the kernel excess for the confirmation poll.
    if let Err(e) = sqlx::query(
        "INSERT INTO payment \
             (id, amount, payer, slate_id, kernel, recipient, status, invoice_id, created_at) \
         VALUES (?1, ?2, NULL, ?1, ?3, '', 'received', ?4, \
             strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    )
    .bind(&finalized.slate_id)
    .bind(amount as i64)
    .bind(&finalized.kernel_excess)
    .bind(&inv.id)
    .execute(pool)
    .await
    {
        // A duplicate id (same finalize replayed) is expected; log others.
        warn!("foreign finalize: payment insert for {}: {e}", finalized.slate_id);
    }

    match invoice::mark_paid(pool, &inv.id, &finalized.slate_id).await {
        Ok(true) => {}
        Ok(false) => return, // already paid/settled: no re-notify.
        Err(e) => {
            error!("foreign finalize: mark_paid for {}: {e}", inv.id);
            return;
        }
    }

    if let Some((url, _secret)) = webhook {
        let payload = WebhookPayload::received(
            finalized.slate_id.clone(),
            amount,
            None,
            Some(inv.id.clone()),
            inv.order_ref.clone(),
            None,
        );
        if let Err(e) = enqueue(pool, url, &payload).await {
            warn!("foreign finalize: webhook enqueue for {}: {e}", finalized.slate_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_core::invoice::{AmountSpec, NewInvoice};

    async fn pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        gp_core::db::MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    async fn grin1_invoice(pool: &SqlitePool, nano: u64, slate_id: &str) -> String {
        let inv = invoice::create(
            pool,
            NewInvoice {
                order_ref: Some("order-9".into()),
                amount: AmountSpec::Grin(nano),
                memo: None,
                match_mode: Some(MatchMode::Amount),
                expiry_secs: None,
            },
            &[5u8; 32],
            "cc".repeat(32).as_str(),
            MatchMode::Amount,
        )
        .await
        .unwrap();
        invoice::attach_grin1(pool, &inv.id, slate_id, "BEGINSLATEPACK.i1.ENDSLATEPACK.")
            .await
            .unwrap();
        inv.id
    }

    #[tokio::test]
    async fn settle_flips_invoice_paid_and_records_payment_with_invoice_amount() {
        let pool = pool().await;
        let inv_id = grin1_invoice(&pool, 4_200_000_000, "slate-fin-1").await;

        // The finalized slate reports amount 0 (invoice-flow I2), so settlement
        // must take the amount from the invoice, not the slate.
        let finalized = FinalizedInvoice {
            slate_id: "slate-fin-1".into(),
            amount: 0,
            kernel_excess: "09".repeat(33),
        };
        settle_finalized(&pool, &finalized, None).await;

        let inv = invoice::get(&pool, &inv_id).await.unwrap().unwrap();
        assert_eq!(inv.status(), gp_core::invoice::InvoiceStatus::Paid);
        assert_eq!(inv.paid_payment_id.as_deref(), Some("slate-fin-1"));

        let (amount, kernel, status): (i64, String, String) = sqlx::query_as(
            "SELECT amount, kernel, status FROM payment WHERE slate_id = 'slate-fin-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(amount, 4_200_000_000, "ledger amount from the invoice");
        assert_eq!(kernel, "09".repeat(33));
        assert_eq!(status, "received");
    }

    #[tokio::test]
    async fn settle_is_idempotent_on_replay() {
        let pool = pool().await;
        let inv_id = grin1_invoice(&pool, 1_000_000_000, "slate-fin-2").await;
        let finalized = FinalizedInvoice {
            slate_id: "slate-fin-2".into(),
            amount: 0,
            kernel_excess: "0a".repeat(33),
        };
        settle_finalized(&pool, &finalized, None).await;
        settle_finalized(&pool, &finalized, None).await; // replay

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment WHERE slate_id = 'slate-fin-2'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "no duplicate payment row");
        let inv = invoice::get(&pool, &inv_id).await.unwrap().unwrap();
        assert_eq!(inv.status(), gp_core::invoice::InvoiceStatus::Paid);
    }

    #[actix_web::test]
    async fn check_version_speaks_jsonrpc_without_a_wallet() {
        use actix_web::{test, App};
        let pool = pool().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(Config::default()))
                .app_data(web::Data::new(None::<GpWallet>))
                .configure(configure),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/v2/foreign")
            .set_json(json!({"jsonrpc":"2.0","id":1,"method":"check_version","params":[]}))
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["id"], 1);
        assert_eq!(body["result"]["foreign_api_version"], 2);
        assert!(body["result"]["supported_slate_versions"].is_array());
    }

    #[actix_web::test]
    async fn unknown_method_returns_jsonrpc_error() {
        use actix_web::{test, App};
        let pool = pool().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool))
                .app_data(web::Data::new(Config::default()))
                .app_data(web::Data::new(None::<GpWallet>))
                .configure(configure),
        )
        .await;
        // With no wallet, a wallet-requiring method reports the missing wallet.
        let req = test::TestRequest::post()
            .uri("/v2/foreign")
            .set_json(json!({"jsonrpc":"2.0","id":7,"method":"receive_tx","params":[]}))
            .to_request();
        let body: Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["id"], 7);
        assert!(body["error"]["message"].as_str().unwrap().contains("wallet not loaded"));
    }

    #[tokio::test]
    async fn settle_unknown_slate_is_a_noop() {
        let pool = pool().await;
        let finalized = FinalizedInvoice {
            slate_id: "no-such-slate".into(),
            amount: 500,
            kernel_excess: "0b".repeat(33),
        };
        settle_finalized(&pool, &finalized, None).await;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
