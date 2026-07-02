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

/// Spawn the confirmation poll on the current (Actix/tokio) runtime. It scans
/// not-yet-confirmed payments that carry a kernel excess and does one DIRECT
/// `get_kernel` per payment (off the async workers via `spawn_blocking`,
/// because the grin node client blocks). When the kernel is on chain the row
/// advances to `confirmed` with its height + timestamp.
pub fn spawn_confirm_poll(pool: SqlitePool, node_url: String) {
    actix_web::rt::spawn(async move {
        info!("confirm: polling pending payments every {CONFIRM_POLL_INTERVAL:?} via {node_url}");
        loop {
            actix_web::rt::time::sleep(CONFIRM_POLL_INTERVAL).await;
            if let Err(e) = confirm_pending(&pool, &node_url).await {
                warn!("confirm: poll pass failed: {e}");
            }
        }
    });
}

/// One poll pass. Returns Err only on a DB error reading the work list; a
/// single payment's node read failing is logged and retried next pass (never
/// drops confirmation tracking).
async fn confirm_pending(pool: &SqlitePool, node_url: &str) -> Result<(), sqlx::Error> {
    let pending: Vec<(String, String)> = sqlx::query_as(
        "SELECT slate_id, kernel FROM payment \
         WHERE status IN ('received', 'replied') AND kernel IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;

    if pending.is_empty() {
        return Ok(());
    }
    debug!("confirm: checking {} pending payment(s)", pending.len());

    for (slate_id, kernel_excess) in pending {
        let node = node_url.to_string();
        let excess = kernel_excess.clone();
        // The grin node client blocks (its own runtime); keep it off the async
        // workers.
        let result =
            actix_web::rt::task::spawn_blocking(move || gp_wallet::confirm_status(&node, &excess))
                .await;

        match result {
            Ok(Ok(status)) if status.confirmed => {
                let height = status.height.map(|h| h as i64);
                if let Err(e) = sqlx::query(
                    "UPDATE payment SET status = 'confirmed', confirmed_height = ?1, \
                     confirmed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE slate_id = ?2",
                )
                .bind(height)
                .bind(&slate_id)
                .execute(pool)
                .await
                {
                    error!("confirm: failed to mark {slate_id} confirmed: {e}");
                } else {
                    info!(
                        "confirm: payment {slate_id} confirmed at height {:?}",
                        status.height
                    );
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

/// GET /payment/{id}: status JSON (pure DB read; public-by-token).
async fn payment_status(path: web::Path<String>, pool: web::Data<SqlitePool>) -> impl Responder {
    let id = path.into_inner();
    #[allow(clippy::type_complexity)] // a flat sqlx row tuple, destructured just below
    let row: Option<(
        i64,
        Option<String>,
        String,
        Option<i64>,
        Option<String>,
        String,
    )> = match sqlx::query_as(
        "SELECT amount, payer, status, confirmed_height, confirmed_at, created_at \
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
        Some((amount, payer, status, confirmed_height, confirmed_at, created_at)) => {
            HttpResponse::Ok().json(serde_json::json!({
                "payment_id": id,
                "amount": amount,
                "payer": payer,
                "status": status,
                "confirmed_height": confirmed_height,
                "confirmed_at": confirmed_at,
                "created_at": created_at,
            }))
        }
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

    #[test]
    fn formats_known_epochs() {
        assert_eq!(format_unix_utc(0), "1970-01-01T00:00:00Z");
        // The Unix billennium.
        assert_eq!(format_unix_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // A widely-cited round timestamp.
        assert_eq!(format_unix_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
