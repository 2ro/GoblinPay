//! Persisting a received payment and running the matching + webhook side
//! effects, shared by the Nostr ingest adapter and the manual-slatepack
//! handler so both take exactly the same path (record -> match -> notify).

use gp_core::config::MatchMode;
use gp_core::invoice;
use gp_core::matching::{match_payment, AmountMismatch, IncomingPayment, MatchResult};
use gp_core::webhook::{enqueue, WebhookPayload};
use gp_wallet::{GpWallet, Received};
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

/// Cancel the I1 a grin1 invoice issued, once that invoice has been paid some
/// OTHER way (a plain-send S1 to the stable address, a Nostr payment, a manual
/// paste). Call it from every [`persist_and_match`] caller, right after the
/// payment settled.
///
/// The I1 the till handed the payer carries a live wallet context. Left alone
/// after the invoice settles it keeps the reserved inputs locked and stays
/// finalizable, so a late I2 for the same order can still be completed and
/// posted. Cancelling it as soon as the invoice flips closes both.
///
/// Best effort by design: `cancel_tx` contacts the node, so a hiccup is logged
/// and the periodic drain in [`crate::foreign::spawn_expiry_cancel`] retries it.
/// Nothing here can fail the payment; the money is already in hand.
pub async fn cancel_stale_grin1(
    pool: &SqlitePool,
    matched: &MatchResult,
    paying_slate_id: &str,
    wallet: &GpWallet,
) {
    // Only the payment that actually flipped the invoice does the cancelling: a
    // replay resolves the same invoice_id but transitioned nothing.
    if !matched.newly_paid {
        return;
    }
    let Some(invoice_id) = matched.invoice_id.as_deref() else {
        return;
    };
    let w = wallet.clone();
    cancel_stale_grin1_with(
        pool,
        invoice_id,
        paying_slate_id,
        move |slate_id| async move { wallet_cancel(w, slate_id).await },
    )
    .await;
}

/// Run one wallet `cancel_tx` off the async workers (it contacts the node and
/// blocks), flattening the join + wallet errors into one message.
pub(crate) async fn wallet_cancel(wallet: GpWallet, slate_id: String) -> Result<(), String> {
    match actix_web::rt::task::spawn_blocking(move || wallet.cancel(&slate_id)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => Err(format!("cancel task panicked: {e}")),
    }
}

/// The bookkeeping half of [`cancel_stale_grin1`], with the wallet call passed
/// in so the decision (which slate, and when to stamp it) is testable without a
/// node. Returns the slate id it cancelled, if any.
///
/// `paying_slate_id` is never cancelled: on the grin1 happy path the invoice is
/// settled BY its own I1, and cancelling that would unlock the outputs of a
/// transaction the till has already posted.
pub(crate) async fn cancel_stale_grin1_with<F, Fut>(
    pool: &SqlitePool,
    invoice_id: &str,
    paying_slate_id: &str,
    cancel: F,
) -> Option<String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let inv = match invoice::get(pool, invoice_id).await {
        Ok(Some(inv)) => inv,
        Ok(None) => return None,
        Err(e) => {
            warn!("grin1: stale-I1 lookup for {invoice_id}: {e}");
            return None;
        }
    };
    if !inv.is_grin1() {
        return None;
    }
    let slate_id = inv.slate_id?;
    if slate_id == paying_slate_id {
        return None; // the slate that just paid: never cancel it.
    }
    match invoice::slate_cancelled(pool, invoice_id).await {
        Ok(true) => return None, // already cancelled; nothing to retry.
        Ok(false) => {}
        Err(e) => {
            warn!("grin1: stale-I1 state for {invoice_id}: {e}");
            return None;
        }
    }
    match cancel(slate_id.clone()).await {
        Ok(()) => {
            if let Err(e) = invoice::mark_slate_cancelled(pool, invoice_id).await {
                warn!("grin1: stamping the cancelled I1 of {invoice_id} failed: {e}");
            }
            log::info!("grin1: cancelled the stale I1 {slate_id} of paid invoice {invoice_id}");
            Some(slate_id)
        }
        Err(e) => {
            // The sweep drains due_grin1_cancels every pass, so this retries.
            warn!("grin1: cancelling the stale I1 {slate_id} of {invoice_id} failed: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_core::invoice::{AmountSpec, NewInvoice};
    use std::cell::RefCell;

    async fn pool() -> SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        gp_core::db::MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    /// A grin1-rail invoice armed with an issued I1 slate id.
    async fn grin1_invoice(pool: &SqlitePool, nano: u64, slate_id: &str) -> String {
        let inv = invoice::create(
            pool,
            NewInvoice {
                order_ref: Some("order-stale".into()),
                amount: AmountSpec::Grin(nano),
                memo: None,
                match_mode: Some(MatchMode::Amount),
                expiry_secs: None,
            },
            &[7u8; 32],
            "dd".repeat(32).as_str(),
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
    async fn a_payment_by_another_route_cancels_the_issued_i1() {
        let pool = pool().await;
        let inv_id = grin1_invoice(&pool, 1_000_000_000, "slate-i1").await;
        // Settled by a plain-send / Nostr payment, NOT by the issued I1.
        assert!(invoice::mark_paid(&pool, &inv_id, "slate-elsewhere")
            .await
            .unwrap());

        let seen = RefCell::new(Vec::new());
        let cancelled = cancel_stale_grin1_with(&pool, &inv_id, "slate-elsewhere", |sid| {
            seen.borrow_mut().push(sid);
            async { Ok(()) }
        })
        .await;

        assert_eq!(cancelled.as_deref(), Some("slate-i1"));
        assert_eq!(seen.into_inner(), vec!["slate-i1".to_string()]);
        assert!(invoice::slate_cancelled(&pool, &inv_id).await.unwrap());
        // Drained: the sweep has nothing left to retry.
        assert!(invoice::due_grin1_cancels(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_slate_that_paid_is_never_cancelled() {
        // The grin1 happy path: the payer returned the I2 for our own I1, so
        // settle_finalized posted that transaction. Cancelling it would unlock
        // the outputs of a tx already on its way into a block. The wallet must
        // not even be asked.
        let pool = pool().await;
        let inv_id = grin1_invoice(&pool, 1_000_000_000, "slate-i1").await;
        assert!(invoice::mark_paid(&pool, &inv_id, "slate-i1")
            .await
            .unwrap());

        let seen = RefCell::new(Vec::new());
        let cancelled = cancel_stale_grin1_with(&pool, &inv_id, "slate-i1", |sid| {
            seen.borrow_mut().push(sid);
            async { Ok(()) }
        })
        .await;

        assert_eq!(cancelled, None);
        assert!(seen.into_inner().is_empty(), "the wallet was not called");
        assert!(!invoice::slate_cancelled(&pool, &inv_id).await.unwrap());
        assert!(
            invoice::due_grin1_cancels(&pool).await.unwrap().is_empty(),
            "and the sweep will not pick it up either"
        );
    }

    #[tokio::test]
    async fn a_failed_cancel_is_left_for_the_sweep() {
        let pool = pool().await;
        let inv_id = grin1_invoice(&pool, 1_000_000_000, "slate-i1").await;
        invoice::mark_paid(&pool, &inv_id, "slate-elsewhere")
            .await
            .unwrap();

        let cancelled = cancel_stale_grin1_with(&pool, &inv_id, "slate-elsewhere", |_| async {
            Err("Can't contact running Grin node. Not Cancelling.".into())
        })
        .await;

        assert_eq!(cancelled, None);
        assert!(
            !invoice::slate_cancelled(&pool, &inv_id).await.unwrap(),
            "never stamped on a failure"
        );
        assert_eq!(
            invoice::due_grin1_cancels(&pool).await.unwrap(),
            vec![(inv_id, "slate-i1".to_string())],
            "the sweep retries it"
        );
    }

    #[tokio::test]
    async fn an_already_cancelled_or_off_rail_invoice_is_a_noop() {
        let pool = pool().await;

        // Already stamped: no second wallet call.
        let armed = grin1_invoice(&pool, 1_000_000_000, "slate-i1").await;
        invoice::mark_paid(&pool, &armed, "slate-elsewhere")
            .await
            .unwrap();
        invoice::mark_slate_cancelled(&pool, &armed).await.unwrap();
        let seen = RefCell::new(0u32);
        assert_eq!(
            cancel_stale_grin1_with(&pool, &armed, "slate-elsewhere", |_| {
                *seen.borrow_mut() += 1;
                async { Ok(()) }
            })
            .await,
            None
        );

        // Off the grin1 rail: nothing was ever issued.
        let plain = invoice::create(
            &pool,
            NewInvoice {
                order_ref: None,
                amount: AmountSpec::Grin(5),
                memo: None,
                match_mode: Some(MatchMode::Amount),
                expiry_secs: None,
            },
            &[7u8; 32],
            "dd".repeat(32).as_str(),
            MatchMode::Amount,
        )
        .await
        .unwrap();
        invoice::mark_paid(&pool, &plain.id, "slate-elsewhere")
            .await
            .unwrap();
        assert_eq!(
            cancel_stale_grin1_with(&pool, &plain.id, "slate-elsewhere", |_| {
                *seen.borrow_mut() += 1;
                async { Ok(()) }
            })
            .await,
            None
        );

        // An invoice that does not exist at all.
        assert_eq!(
            cancel_stale_grin1_with(&pool, "no-such-invoice", "slate-elsewhere", |_| {
                *seen.borrow_mut() += 1;
                async { Ok(()) }
            })
            .await,
            None
        );
        assert_eq!(seen.into_inner(), 0, "the wallet was never called");
    }
}
