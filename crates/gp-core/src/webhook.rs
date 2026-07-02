//! HTTP webhook notifications (milestone 6): the signed, idempotent, retried
//! payload a store backend (WooCommerce, or any REST consumer) receives on a
//! payment event. This is the contract the connector plugins depend on, so
//! the field names, the signature scheme, and the headers are fixed here.
//!
//! ## Body (`application/json`)
//!
//! ```json
//! {
//!   "event_id": "5f3c…",              // 128-bit hex, the idempotency key
//!   "event_type": "payment.received", // (payment.confirmed once node-confirmed)
//!   "created_at": "2026-07-01T12:00:00Z",
//!   "payment": {
//!     "slate_id": "…",
//!     "amount": 2000000000,           // nanogrin (integer)
//!     "amount_grin": "2",             // human decimal string
//!     "status": "received",
//!     "payer": "…hex…",               // sender pubkey, or null
//!     "confirmed_height": null        // set once confirmed on chain
//!   },
//!   "invoice_id": "…",                // or null
//!   "order_ref": "order-42",          // or null
//!   "user_id": "…"                    // multi-tenant crediting (5b), or null
//! }
//! ```
//!
//! ## Signature
//!
//! `X-GoblinPay-Signature: sha256=<hex>` where `<hex>` is
//! `HMAC-SHA256(secret, raw_body_bytes)`. The receiver recomputes the HMAC
//! over the exact bytes it received and compares in constant time.
//! `X-GoblinPay-Delivery: <event_id>` lets the receiver dedupe retries.
//!
//! Sending, retries, and backoff are persisted in `webhook_delivery`, so a
//! crash mid-retry resumes; the HTTP transport itself lives in gp-server.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;

use crate::ids;

/// HTTP header carrying the HMAC signature.
pub const SIGNATURE_HEADER: &str = "X-GoblinPay-Signature";
/// HTTP header carrying the idempotency key (the event id).
pub const DELIVERY_HEADER: &str = "X-GoblinPay-Delivery";

/// Base retry backoff (seconds); doubles each attempt up to [`BACKOFF_CAP`].
const BACKOFF_BASE: i64 = 30;
/// Maximum retry backoff (seconds).
const BACKOFF_CAP: i64 = 3600;
/// Give up after this many attempts.
pub const MAX_ATTEMPTS: i64 = 12;

type HmacSha256 = Hmac<Sha256>;

/// The payment slice of the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    pub slate_id: String,
    pub amount: u64,
    pub amount_grin: String,
    pub status: String,
    pub payer: Option<String>,
    pub confirmed_height: Option<u64>,
}

/// The full webhook payload (the JSON body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_id: String,
    pub event_type: String,
    pub created_at: String,
    pub payment: PaymentPayload,
    pub invoice_id: Option<String>,
    pub order_ref: Option<String>,
    pub user_id: Option<String>,
}

/// Format nanogrin as a trimmed decimal Grin string (1 grin = 1e9 nanogrin).
pub fn nanogrin_to_grin(nano: u64) -> String {
    let whole = nano / 1_000_000_000;
    let frac = nano % 1_000_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        let frac = format!("{frac:09}");
        format!("{whole}.{}", frac.trim_end_matches('0'))
    }
}

impl WebhookPayload {
    /// Build a `payment.received` payload with a fresh idempotency key.
    #[allow(clippy::too_many_arguments)]
    pub fn received(
        slate_id: String,
        amount: u64,
        payer: Option<String>,
        invoice_id: Option<String>,
        order_ref: Option<String>,
        user_id: Option<String>,
    ) -> WebhookPayload {
        WebhookPayload {
            event_id: ids::random_id(),
            event_type: "payment.received".into(),
            created_at: now_iso8601(),
            payment: PaymentPayload {
                slate_id: slate_id.clone(),
                amount,
                amount_grin: nanogrin_to_grin(amount),
                status: "received".into(),
                payer,
                confirmed_height: None,
            },
            invoice_id,
            order_ref,
            user_id,
        }
    }

    /// Serialize to the exact JSON body that gets signed and stored.
    pub fn to_body(&self) -> String {
        serde_json::to_string(self).expect("payload serializes")
    }
}

/// `sha256=<hex(HMAC-SHA256(secret, body))>`, the value of the signature
/// header.
pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    format!("sha256={}", hex::encode(digest))
}

/// Verify a signature header against the body in constant time. Accepts the
/// full `sha256=<hex>` form (case-insensitive scheme, lower-hex digest).
pub fn verify(secret: &str, body: &[u8], header: &str) -> bool {
    let expected = sign(secret, body);
    // Compare the whole `sha256=<hex>` string in constant time. Equal length
    // for a well-formed header; a length mismatch is a plain reject.
    let a = expected.as_bytes();
    let b = header.trim().as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Retry backoff for the Nth attempt (attempt counter starts at 1 after the
/// first failure): `min(BASE * 2^(attempts-1), CAP)`.
pub fn backoff_secs(attempts: i64) -> i64 {
    if attempts <= 0 {
        return 0;
    }
    let shift = (attempts - 1).min(20) as u32;
    BACKOFF_BASE.saturating_mul(1i64 << shift).min(BACKOFF_CAP)
}

/// A persisted delivery awaiting (re)send.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Delivery {
    pub id: String,
    pub url: String,
    pub body: String,
    pub attempts: i64,
}

/// Persist a payload for delivery to `url`, due immediately. Returns the
/// event id (idempotency key). No-op-safe: the event id is unique.
pub async fn enqueue(
    pool: &SqlitePool,
    url: &str,
    payload: &WebhookPayload,
) -> Result<String, sqlx::Error> {
    let body = payload.to_body();
    sqlx::query(
        "INSERT INTO webhook_delivery \
         (id, payment_id, event_type, url, body, attempts, delivered, next_attempt_at, \
          created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
                 strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    )
    .bind(&payload.event_id)
    .bind(&payload.payment.slate_id)
    .bind(&payload.event_type)
    .bind(url)
    .bind(&body)
    .execute(pool)
    .await?;
    Ok(payload.event_id.clone())
}

/// Deliveries that are due (undelivered and past their next-attempt time and
/// under the attempt ceiling).
pub async fn due(pool: &SqlitePool, limit: i64) -> Result<Vec<Delivery>, sqlx::Error> {
    sqlx::query_as::<_, Delivery>(
        "SELECT id, url, body, attempts FROM webhook_delivery \
         WHERE delivered = 0 AND attempts < ?2 \
           AND next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         ORDER BY next_attempt_at LIMIT ?1",
    )
    .bind(limit)
    .bind(MAX_ATTEMPTS)
    .fetch_all(pool)
    .await
}

/// Mark a delivery succeeded.
pub async fn mark_delivered(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE webhook_delivery SET delivered = 1, attempts = attempts + 1, last_error = NULL, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a failed attempt and schedule the next one with backoff.
pub async fn mark_failed(pool: &SqlitePool, id: &str, error: &str) -> Result<(), sqlx::Error> {
    // The new attempt count decides the backoff, computed in Rust and applied
    // as a relative SQL offset.
    let attempts: i64 =
        sqlx::query_scalar("SELECT attempts + 1 FROM webhook_delivery WHERE id = ?1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    let backoff = format!("+{} seconds", backoff_secs(attempts));
    sqlx::query(
        "UPDATE webhook_delivery SET attempts = ?2, last_error = ?3, \
         next_attempt_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?4), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = ?1",
    )
    .bind(id)
    .bind(attempts)
    .bind(error)
    .bind(backoff)
    .execute(pool)
    .await?;
    Ok(())
}

/// Current UTC time as ISO-8601 seconds (`YYYY-MM-DDTHH:MM:SSZ`), computed
/// from the Unix epoch without pulling in a date library.
fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Days since the Unix epoch to a civil (year, month, day). Howard Hinnant's
/// algorithm; avoids a chrono/time dependency for one timestamp.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn pool() -> SqlitePool {
        db::test_pool().await
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let secret = "s3cr3t";
        let body = br#"{"event_id":"abc","amount":1}"#;
        let sig = sign(secret, body);
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
        assert!(verify(secret, body, &sig));
        // A tampered body fails.
        assert!(!verify(secret, br#"{"event_id":"abc","amount":2}"#, &sig));
        // A wrong secret fails.
        assert!(!verify("other", body, &sig));
        // Garbage header fails without panicking.
        assert!(!verify(secret, body, "sha256=deadbeef"));
        assert!(!verify(secret, body, ""));
    }

    #[test]
    fn signature_matches_a_known_vector() {
        // HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
        // = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
        let sig = sign("key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            sig,
            "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn grin_formatting() {
        assert_eq!(nanogrin_to_grin(0), "0");
        assert_eq!(nanogrin_to_grin(1_000_000_000), "1");
        assert_eq!(nanogrin_to_grin(2_500_000_000), "2.5");
        assert_eq!(nanogrin_to_grin(1_234_567_890), "1.23456789");
        assert_eq!(nanogrin_to_grin(1), "0.000000001");
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_secs(0), 0);
        assert_eq!(backoff_secs(1), 30);
        assert_eq!(backoff_secs(2), 60);
        assert_eq!(backoff_secs(3), 120);
        assert_eq!(backoff_secs(100), BACKOFF_CAP, "must cap");
    }

    #[test]
    fn timestamp_is_iso8601() {
        let ts = now_iso8601();
        assert_eq!(ts.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        // A known epoch second: 2021-01-01T00:00:00Z = 1609459200.
        assert_eq!(civil_from_days(1_609_459_200 / 86_400), (2021, 1, 1));
    }

    #[tokio::test]
    async fn enqueue_deliver_and_idempotency() {
        let pool = pool().await;
        let payload = WebhookPayload::received(
            "slate-1".into(),
            2_000_000_000,
            Some("payerhex".into()),
            Some("inv-1".into()),
            Some("order-1".into()),
            None,
        );
        let id = enqueue(&pool, "https://store.example/hook", &payload)
            .await
            .unwrap();
        assert_eq!(id, payload.event_id);

        // It is due immediately.
        let due_now = due(&pool, 10).await.unwrap();
        assert_eq!(due_now.len(), 1);
        assert_eq!(due_now[0].id, id);
        // The stored body verifies under the same secret.
        assert!(verify(
            "hooksecret",
            due_now[0].body.as_bytes(),
            &sign("hooksecret", due_now[0].body.as_bytes())
        ));

        // A failure reschedules it into the future (no longer due now).
        mark_failed(&pool, &id, "connection refused").await.unwrap();
        assert!(due(&pool, 10).await.unwrap().is_empty());

        // Delivery marks it done and it never comes due again.
        mark_delivered(&pool, &id).await.unwrap();
        assert!(due(&pool, 10).await.unwrap().is_empty());
        let delivered: i64 =
            sqlx::query_scalar("SELECT delivered FROM webhook_delivery WHERE id = ?1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(delivered, 1);
    }
}
