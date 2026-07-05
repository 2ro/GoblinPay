//! Payment read surface (M4): the confirmation poll that advances received
//! payments to `confirmed` when their kernel lands, plus two public-by-token
//! read endpoints:
//!
//!   GET /payment/{id}          -> payment status JSON
//!   GET /payment/{id}/receipt  -> the server-signed, verifiable receipt
//!
//! Both are keyed by the payment id (the Grin slate UUID), which is an
//! unguessable bearer token, so no separate auth is needed for these reads
//! (admin/write endpoints arrive with later milestones). The receipt is
//! self-authenticating (BIP-340 Schnorr over the server identity key), so it
//! is safe to expose.

use std::time::Duration;

use actix_web::{web, HttpResponse, Responder};
use gp_core::config::Config;
use gp_core::invoice;
use gp_core::webhook::{enqueue, WebhookPayload};
use gp_nostr::receipt::{sign_receipt, Receipt, RECEIPT_VERSION};
use gp_nostr::Keys;
use log::{debug, error, info, warn};
use sqlx::SqlitePool;

/// How often the confirmation poll runs. Node reads are direct and cheap, so a
/// simple fixed interval is enough; a payment confirms within one interval of
/// its kernel landing.
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The receipt signer: the server identity keys, or `None` when ingest (and
/// thus the identity) is disabled. Shared into the HTTP app as app data.
#[derive(Clone)]
pub struct ReceiptSigner(pub Option<Keys>);

/// Register the M4 read routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/payment/{id}", web::get().to(payment_status))
        .route("/payment/{id}/receipt", web::get().to(payment_receipt));
}

/// Confirmation-depth policy plus the optional webhook sink, carried into the
/// poll. `required` is `GP_CONFIRMATIONS` (default 10, house standard);
/// `webhook_url` is the store endpoint a `payment.confirmed` event is enqueued
/// to when an invoice crosses the threshold (its HMAC secret is applied by the
/// dispatcher at send time, so only the URL is needed here).
#[derive(Clone)]
pub struct ConfirmPolicy {
    pub required: i64,
    pub webhook_url: Option<String>,
}

impl ConfirmPolicy {
    /// Read the confirmation policy from the resolved config.
    pub fn from_config(cfg: &Config) -> ConfirmPolicy {
        ConfirmPolicy {
            required: cfg.confirmations_required,
            webhook_url: cfg.webhook_url.clone(),
        }
    }
}

/// Spawn the confirmation poll on the current (Actix/tokio) runtime. It scans
/// payments that carry a kernel excess and are not yet at the required depth,
/// doing one DIRECT `get_kernel` per payment (off the async workers via
/// `spawn_blocking`, because the grin node client blocks). Each pass records
/// the payment's current confirmation depth; when the kernel first lands the
/// row advances to `confirmed` with its height + timestamp, and once the depth
/// reaches `policy.required` the paying invoice advances `paid` -> `confirmed`
/// and a `payment.confirmed` webhook is enqueued.
pub fn spawn_confirm_poll(pool: SqlitePool, node_url: String, policy: ConfirmPolicy) {
    actix_web::rt::spawn(async move {
        info!(
            "confirm: polling pending payments every {CONFIRM_POLL_INTERVAL:?} via {node_url} \
             (final at {} confirmations)",
            policy.required
        );
        loop {
            actix_web::rt::time::sleep(CONFIRM_POLL_INTERVAL).await;
            if let Err(e) = confirm_pending(&pool, &node_url, &policy).await {
                warn!("confirm: poll pass failed: {e}");
            }
        }
    });
}

/// One poll pass. Returns Err only on a DB error reading the work list; a
/// single payment's node read failing is logged and retried next pass (never
/// drops confirmation tracking).
async fn confirm_pending(
    pool: &SqlitePool,
    node_url: &str,
    policy: &ConfirmPolicy,
) -> Result<(), sqlx::Error> {
    // Poll every kernel-bearing payment that has not yet reached the required
    // depth (confirmations defaults to 0, so still-pending received/replied
    // payments are included). A payment that reaches the threshold drops out,
    // so the poll is self-terminating per payment.
    let pending: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT slate_id, kernel, invoice_id FROM payment \
         WHERE kernel IS NOT NULL AND confirmations < ?1",
    )
    .bind(policy.required)
    .fetch_all(pool)
    .await?;

    if pending.is_empty() {
        return Ok(());
    }
    debug!("confirm: checking {} pending payment(s)", pending.len());

    for (slate_id, kernel_excess, invoice_id) in pending {
        let node = node_url.to_string();
        let excess = kernel_excess.clone();
        // The grin node client blocks (its own runtime); keep it off the async
        // workers.
        let result =
            actix_web::rt::task::spawn_blocking(move || gp_wallet::confirm_status(&node, &excess))
                .await;

        match result {
            Ok(Ok(status)) if status.confirmed => {
                let confirmations = status.confirmations.unwrap_or(0);
                let height = status.height.map(|h| h as i64);
                // Record the current depth and (first time) the confirmed
                // marker. `confirmed_at` is set once via COALESCE so a later
                // pass does not keep rewriting it.
                if let Err(e) = sqlx::query(
                    "UPDATE payment SET status = 'confirmed', confirmed_height = ?1, \
                     confirmed_at = COALESCE(confirmed_at, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')), \
                     confirmations = ?2 WHERE slate_id = ?3",
                )
                .bind(height)
                .bind(confirmations as i64)
                .bind(&slate_id)
                .execute(pool)
                .await
                {
                    error!("confirm: failed to update {slate_id}: {e}");
                    continue;
                }
                info!(
                    "confirm: payment {slate_id} at {confirmations}/{} confirmations (height {:?})",
                    policy.required, status.height
                );

                // Threshold reached: advance the paying invoice and notify.
                if confirmations as i64 >= policy.required {
                    if let Some(inv_id) = invoice_id.as_deref() {
                        finalize_invoice(pool, policy, &slate_id, inv_id, height, confirmations)
                            .await;
                    }
                }
            }
            // Not yet on chain: leave pending, retry next pass.
            Ok(Ok(_status)) => {}
            Ok(Err(e)) => warn!("confirm: node read failed for {slate_id}: {e}"),
            Err(e) => warn!("confirm: confirm task panicked for {slate_id}: {e}"),
        }
    }
    Ok(())
}

/// Advance a paid invoice to `confirmed` and, on that (idempotent) transition,
/// enqueue a `payment.confirmed` webhook. Only the transition fires the event,
/// so a repeated threshold crossing never re-notifies. All side effects are
/// best-effort: the money is already final on chain, so a DB/webhook hiccup is
/// logged and swallowed.
async fn finalize_invoice(
    pool: &SqlitePool,
    policy: &ConfirmPolicy,
    slate_id: &str,
    invoice_id: &str,
    confirmed_height: Option<i64>,
    confirmations: u64,
) {
    let transitioned = match invoice::mark_confirmed(pool, invoice_id).await {
        Ok(t) => t,
        Err(e) => {
            error!("confirm: mark_confirmed failed for invoice {invoice_id}: {e}");
            return;
        }
    };
    if !transitioned {
        return; // already confirmed (or not paid): nothing to notify.
    }
    info!("confirm: invoice {invoice_id} confirmed ({confirmations} confirmations)");

    let Some(url) = policy.webhook_url.as_deref() else {
        return; // no webhook configured.
    };

    // Gather the payload fields from the payment + its invoice.
    #[allow(clippy::type_complexity)]
    let row: Option<(i64, Option<String>, Option<String>, Option<String>)> = match sqlx::query_as(
        "SELECT p.amount, p.payer, p.user_id, i.ref \
         FROM payment p LEFT JOIN invoice i ON i.id = p.invoice_id \
         WHERE p.slate_id = ?1",
    )
    .bind(slate_id)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            warn!("confirm: could not load {slate_id} for webhook: {e}");
            return;
        }
    };
    let Some((amount, payer, user_id, order_ref)) = row else {
        return;
    };

    let payload = WebhookPayload::confirmed(
        slate_id.to_string(),
        amount as u64,
        payer,
        Some(invoice_id.to_string()),
        order_ref,
        user_id,
        confirmed_height.map(|h| h as u64),
        confirmations,
    );
    if let Err(e) = enqueue(pool, url, &payload).await {
        warn!("confirm: webhook enqueue failed for {slate_id}: {e}");
    }
}

/// GET /payment/{id}: status JSON (pure DB read; public-by-token).
async fn payment_status(
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    let id = path.into_inner();
    #[allow(clippy::type_complexity)] // a flat sqlx row tuple, destructured just below
    let row: Option<(
        i64,
        Option<String>,
        String,
        Option<i64>,
        Option<String>,
        String,
        i64,
    )> = match sqlx::query_as(
        "SELECT amount, payer, status, confirmed_height, confirmed_at, created_at, confirmations \
             FROM payment WHERE slate_id = ?1",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(row) => row,
        Err(e) => {
            error!("status: query failed for {id}: {e}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "internal error"}));
        }
    };

    match row {
        Some((
            amount,
            payer,
            status,
            confirmed_height,
            confirmed_at,
            created_at,
            confirmations,
        )) => HttpResponse::Ok().json(serde_json::json!({
            "payment_id": id,
            "amount": amount,
            "payer": payer,
            "status": status,
            "confirmed_height": confirmed_height,
            "confirmed_at": confirmed_at,
            "created_at": created_at,
            "confirmations": confirmations,
            "confirmations_required": cfg.confirmations_required,
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "payment not found"})),
    }
}

/// GET /payment/{id}/receipt: the server-signed, verifiable receipt.
async fn payment_receipt(
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    signer: web::Data<ReceiptSigner>,
) -> impl Responder {
    let id = path.into_inner();

    let Some(keys) = signer.0.as_ref() else {
        return HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "receipt signing unavailable (server identity not loaded)"
        }));
    };

    #[allow(clippy::type_complexity)] // a flat sqlx row tuple, destructured just below
    let row: Option<(i64, Option<String>, Option<String>, Option<i64>)> = match sqlx::query_as(
        "SELECT amount, kernel, proof, confirmed_height FROM payment WHERE slate_id = ?1",
    )
    .bind(&id)
    .fetch_optional(pool.get_ref())
    .await
    {
        Ok(row) => row,
        Err(e) => {
            error!("receipt: query failed for {id}: {e}");
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "internal error"}));
        }
    };

    let Some((amount, kernel, proof, confirmed_height)) = row else {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "payment not found"}));
    };
    let Some(kernel_excess) = kernel else {
        // No kernel recorded means the payment predates M4 or was not received
        // through the wallet path; a receipt has nothing to anchor.
        return HttpResponse::Conflict()
            .json(serde_json::json!({"error": "payment has no kernel excess recorded"}));
    };

    let receipt = Receipt {
        version: RECEIPT_VERSION,
        payment_id: id,
        amount: amount as u64,
        kernel_excess,
        confirmed_height: confirmed_height.map(|h| h as u64),
        confirmations: None,
        proof: proof.and_then(|p| serde_json::from_str(&p).ok()),
        issued_at: now_iso8601(),
        server_pubkey: String::new(), // filled by sign_receipt
    };

    match sign_receipt(keys, receipt) {
        Ok(signed) => HttpResponse::Ok().json(signed),
        Err(e) => {
            error!("receipt: signing failed: {e}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "receipt signing failed"}))
        }
    }
}

/// ISO-8601 UTC timestamp (seconds), no extra dependency.
fn now_iso8601() -> String {
    // Delegate the calendar math to SQLite-free logic is overkill here; use the
    // same seconds-since-epoch the rest of the crate uses and format via a tiny
    // civil-time conversion.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_utc(secs)
}

/// Format a Unix timestamp (seconds) as `YYYY-MM-DDTHH:MM:SSZ` (UTC), using the
/// civil-from-days algorithm (Howard Hinnant), so no date-time dependency is
/// pulled in for one timestamp.
fn format_unix_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_core::config::MatchMode;
    use gp_core::invoice::{self, AmountSpec, InvoiceStatus, NewInvoice};

    #[test]
    fn formats_known_epochs() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        // The Unix billennium.
        assert_eq!(format_unix_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // A widely-cited round timestamp.
        assert_eq!(format_unix_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    async fn pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        gp_core::db::MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    /// Insert a kernel-bearing payment row (as ingest would) and set its
    /// current confirmation depth + linked invoice.
    async fn insert_payment(pool: &SqlitePool, slate: &str, confs: i64, invoice_id: Option<&str>) {
        sqlx::query(
            "INSERT INTO payment (id, amount, payer, slate_id, kernel, status, confirmations, \
             invoice_id, created_at) \
             VALUES (?1, 2000000000, 'payerhex', ?1, 'deadbeef', 'received', ?2, ?3, \
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
        )
        .bind(slate)
        .bind(confs)
        .bind(invoice_id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn paid_invoice(pool: &SqlitePool, slate: &str) -> String {
        let inv = invoice::create(
            pool,
            NewInvoice {
                order_ref: Some("order-1".into()),
                amount: AmountSpec::Grin(2_000_000_000),
                memo: None,
                match_mode: Some(MatchMode::Memo),
                expiry_secs: None,
            },
            &[7u8; 32],
            "bb".repeat(32).as_str(),
            MatchMode::Memo,
        )
        .await
        .unwrap();
        invoice::mark_paid(pool, &inv.id, slate).await.unwrap();
        inv.id
    }

    /// The poll work-list is self-terminating at the threshold: a payment at or
    /// above `required` confirmations is excluded, one below is included.
    #[tokio::test]
    async fn pending_query_excludes_payments_at_threshold() {
        let pool = pool().await;
        insert_payment(&pool, "below", 3, None).await;
        insert_payment(&pool, "at", 10, None).await;
        let pending: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT slate_id, kernel, invoice_id FROM payment \
             WHERE kernel IS NOT NULL AND confirmations < ?1",
        )
        .bind(10i64)
        .fetch_all(&pool)
        .await
        .unwrap();
        let ids: Vec<&str> = pending.iter().map(|(s, _, _)| s.as_str()).collect();
        assert_eq!(ids, vec!["below"], "only the below-threshold payment polls");
    }

    /// At the threshold, a paid invoice advances to `confirmed` exactly once and
    /// a single `payment.confirmed` webhook is enqueued (idempotent on replay).
    #[tokio::test]
    async fn finalize_confirms_invoice_and_enqueues_confirmed_webhook_once() {
        let pool = pool().await;
        let inv_id = paid_invoice(&pool, "slate-1").await;
        insert_payment(&pool, "slate-1", 10, Some(&inv_id)).await;

        let policy = ConfirmPolicy {
            required: 10,
            webhook_url: Some("https://store.example/hook".into()),
        };
        finalize_invoice(&pool, &policy, "slate-1", &inv_id, Some(3_900_123), 10).await;

        // The invoice reached the terminal state.
        let inv = invoice::get(&pool, &inv_id).await.unwrap().unwrap();
        assert_eq!(inv.status(), InvoiceStatus::Confirmed);
        assert!(inv.confirmed_at.is_some());

        // Exactly one payment.confirmed webhook is queued, carrying the depth.
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT event_type, body FROM webhook_delivery")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "payment.confirmed");
        assert!(rows[0].1.contains("\"confirmations\":10"));
        assert!(rows[0].1.contains("\"confirmed_height\":3900123"));

        // A replay does not re-confirm or re-enqueue.
        finalize_invoice(&pool, &policy, "slate-1", &inv_id, Some(3_900_123), 11).await;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_delivery")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "confirmed webhook fires only on the transition");
    }

    /// With no webhook configured, the transition still happens (no enqueue).
    #[tokio::test]
    async fn finalize_confirms_without_a_webhook_configured() {
        let pool = pool().await;
        let inv_id = paid_invoice(&pool, "slate-2").await;
        insert_payment(&pool, "slate-2", 10, Some(&inv_id)).await;

        let policy = ConfirmPolicy {
            required: 10,
            webhook_url: None,
        };
        finalize_invoice(&pool, &policy, "slate-2", &inv_id, None, 10).await;

        let inv = invoice::get(&pool, &inv_id).await.unwrap().unwrap();
        assert_eq!(inv.status(), InvoiceStatus::Confirmed);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_delivery")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
