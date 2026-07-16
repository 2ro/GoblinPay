//! Persisting a received payment and running the matching + webhook side
//! effects, shared by the Nostr ingest adapter and the manual-slatepack
//! handler so both take exactly the same path (record -> match -> notify).

use gp_core::config::MatchMode;
use gp_core::invoice;
use gp_core::matching::{match_payment, AmountMismatch, IncomingPayment, MatchResult};
use gp_core::webhook::{enqueue, WebhookPayload};
use gp_wallet::Received;
use log::{error, warn};
use sqlx::SqlitePool;

/// The result of [`persist_and_match`].
#[derive(Debug, Clone)]
pub enum PersistOutcome {
    /// The payment was recorded and resolved (possibly to nothing).
    Matched(MatchResult),
    /// The received amount does not equal the matched invoice's expected
    /// amount, so the payment was REJECTED: no payment row is persisted, the
    /// invoice is left open, and no webhook is enqueued. Carries the exact
    /// figures (nanogrin) so the caller can tell the payer what to send.
    Rejected(AmountMismatch),
}

/// Insert the payment row, resolve it to an invoice/user, and enqueue the
/// webhook if one is configured. Returns what it matched. A correct payment
/// never fails the caller: the money is already in hand, so persistence/
/// matching/webhook errors are logged and swallowed.
///
/// The one hard stop is the amount-binding guard: if the payment resolves to an
/// invoice whose exact expected amount it does not pay, the just-inserted
/// payment row is removed and [`PersistOutcome::Rejected`] is returned — the
/// invoice never flips paid on an under- or overpayment.
pub async fn persist_and_match(
    pool: &SqlitePool,
    received: &Received,
    payer_hex: Option<&str>,
    recipient_hex: &str,
    memo: Option<&str>,
    default_mode: MatchMode,
    webhook: Option<&(String, String)>,
) -> PersistOutcome {
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

    // Amount-binding rejection: the slate resolved to an invoice but pays the
    // wrong amount. Undo the record (nothing is persisted for a rejected
    // payment) and return the mismatch without notifying the store.
    if let Some(mismatch) = matched.amount_mismatch {
        if let Err(e) = sqlx::query("DELETE FROM payment WHERE id = ?1")
            .bind(&received.slate_id)
            .execute(pool)
            .await
        {
            warn!("payment record delete for {}: {e}", received.slate_id);
        }
        warn!(
            "rejected {}: pays {} nanogrin, invoice expects {} nanogrin",
            received.slate_id, mismatch.received, mismatch.expected
        );
        return PersistOutcome::Rejected(mismatch);
    }

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

    PersistOutcome::Matched(matched)
}
