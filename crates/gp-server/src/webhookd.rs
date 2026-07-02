//! The webhook delivery worker (milestone 6): drains the persisted
//! `webhook_delivery` queue, POSTs each due payload with its HMAC signature,
//! and marks it delivered or reschedules it with backoff. Runs on the Actix
//! runtime for the process lifetime.
//!
//! Idempotency is the receiver's job (dedupe on the `X-GoblinPay-Delivery`
//! event id); the worker guarantees at-least-once with bounded retries.

use std::time::Duration;

use gp_core::webhook::{self, sign, DELIVERY_HEADER, SIGNATURE_HEADER};
use log::{info, warn};
use sqlx::SqlitePool;

/// How often the queue is drained.
const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Max deliveries attempted per pass.
const BATCH: i64 = 20;
/// Per-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Spawn the webhook dispatcher. `secret` is the HMAC key (`GP_WEBHOOK_SECRET`).
pub fn spawn(pool: SqlitePool, secret: String) {
    actix_web::rt::spawn(async move {
        let client = match reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build() {
            Ok(c) => c,
            Err(e) => {
                warn!("webhook: HTTP client build failed, dispatcher disabled: {e}");
                return;
            }
        };
        info!("webhook: dispatcher started (every {POLL_INTERVAL:?})");
        loop {
            if let Err(e) = drain(&pool, &client, &secret).await {
                warn!("webhook: drain pass failed: {e}");
            }
            actix_web::rt::time::sleep(POLL_INTERVAL).await;
        }
    });
}

/// One drain pass: deliver every due webhook once.
async fn drain(
    pool: &SqlitePool,
    client: &reqwest::Client,
    secret: &str,
) -> Result<(), sqlx::Error> {
    for delivery in webhook::due(pool, BATCH).await? {
        let signature = sign(secret, delivery.body.as_bytes());
        let result = client
            .post(&delivery.url)
            .header("content-type", "application/json")
            .header(SIGNATURE_HEADER, signature)
            .header(DELIVERY_HEADER, &delivery.id)
            .body(delivery.body.clone())
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                webhook::mark_delivered(pool, &delivery.id).await?;
                info!(
                    "webhook: delivered {} to {} (HTTP {})",
                    &delivery.id[..8.min(delivery.id.len())],
                    host_of(&delivery.url),
                    resp.status().as_u16()
                );
            }
            Ok(resp) => {
                let msg = format!("HTTP {}", resp.status().as_u16());
                webhook::mark_failed(pool, &delivery.id, &msg).await?;
            }
            Err(e) => {
                webhook::mark_failed(pool, &delivery.id, &e.to_string()).await?;
            }
        }
    }
    Ok(())
}

/// Host of a URL for logging (host-only privacy, never the full path).
fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("?")
        .to_string()
}
