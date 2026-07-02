//! Persisting a received payment and running the matching + webhook side
//! effects, shared by the Nostr ingest adapter and the manual-slatepack
//! handler so both take exactly the same path (record -> match -> notify).

use gp_core::config::MatchMode;
use gp_core::invoice;
use gp_core::matching::{match_payment, IncomingPayment, MatchResult};
use gp_core::webhook::{enqueue, WebhookPayload};
use gp_wallet::Received;
use log::{error, warn};
use sqlx::SqlitePool;

/// Insert the payment row, resolve it to an invoice/user, and enqueue the
/// webhook if one is configured. Returns what it matched. Never fails the
/// caller: the money is already in hand, so persistence/matching/webhook
/// errors are logged and swallowed.
pub async fn persist_and_match(
    pool: &SqlitePool,
    received: &Received,
    payer_hex: Option<&str>,
    recipient_hex: &str,
    memo: Option<&str>,
    default_mode: MatchMode,
    webhook: Option<&(String, String)>,
) -> MatchResult {
    let inserted = sqlx::query(
        "INSERT INTO payment \
             (id, amount, payer, slate_id, kernel, proof, s2_armor, recipient, status, \
              created_at) \
         VALUES (?1, ?2, ?3, ?1, ?4, ?5, ?6, ?7, 'received', \
             strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
    )
    .bind(&received.slate_id)
    .bind(received.amount as i64)
    .bind(payer_hex)
    .bind(&received.kernel_excess)
    .bind(&received.proof)
    .bind(&received.s2_armor)
    .bind(recipient_hex)
    .execute(pool)
    .await;
    if let Err(e) = inserted {
        // A duplicate id (same slate received twice) is expected on a retry;
        // anything else is logged. Either way, keep going so the reply/S2 is
        // still handed back.
        error!("payment record insert for {}: {e}", received.slate_id);
    }

    let matched = match match_payment(
        pool,
        default_mode,
        &IncomingPayment {
            slate_id: &received.slate_id,
            amount: received.amount,
            recipient_hex,
            memo,
        },
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            warn!("matching failed for {}: {e}", received.slate_id);
            MatchResult::default()
        }
    };

    if let Some((url, _secret)) = webhook {
        let order_ref = match matched.invoice_id.as_deref() {
            Some(id) => invoice::get(pool, id)
                .await
                .ok()
                .flatten()
                .and_then(|inv| inv.order_ref),
            None => None,
        };
        let payload = WebhookPayload::received(
            received.slate_id.clone(),
            received.amount,
            payer_hex.map(|p| p.to_string()),
            matched.invoice_id.clone(),
            order_ref,
            matched.user_id.clone(),
        );
        if let Err(e) = enqueue(pool, url, &payload).await {
            warn!("webhook enqueue failed for {}: {e}", received.slate_id);
        }
    }

    matched
}
