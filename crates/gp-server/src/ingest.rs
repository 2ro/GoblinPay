//! The secure handoff between the Nostr transport and the Grin wallet:
//! gp-nostr's [`SlatepackReceiver`] implemented over [`gp_wallet::GpWallet`]
//! plus the SQLite payment table. Only armored slatepack strings cross the
//! boundary, exactly like Goblin hands a gift-wrapped slatepack to its wallet.
//!
//! On top of the milestone-3 receive + reply, this adapter runs the
//! milestone-5 matching layer (link the payment to an invoice and/or tenant
//! user) and enqueues the milestone-6 webhook, via the shared
//! [`crate::record::persist_and_match`] so a manual-slatepack payment takes the
//! identical path.

use gp_core::config::MatchMode;
use gp_nostr::{
    IncomingContext, ReceiveError, ReceivedPayment, SlatepackReceiver, UnrepliedPayment,
};
use gp_wallet::{GpWallet, WalletError};
use log::warn;
use sqlx::SqlitePool;

use crate::record::{persist_and_match, PersistOutcome};

/// Wallet + database receiver for incoming S1 slatepacks.
pub struct WalletReceiver {
    wallet: GpWallet,
    pool: SqlitePool,
    /// Global default matching mode (per-invoice overrides win over this).
    default_mode: MatchMode,
    /// Webhook endpoint + HMAC secret, when notifications are configured.
    webhook: Option<(String, String)>,
}

impl WalletReceiver {
    /// A receiver with the default matching mode and no webhook (the
    /// milestone-3 E2E path).
    pub fn new(wallet: GpWallet, pool: SqlitePool) -> WalletReceiver {
        WalletReceiver {
            wallet,
            pool,
            default_mode: MatchMode::Memo,
            webhook: None,
        }
    }

    /// A receiver with the matching default and (optional) webhook wired.
    pub fn with_matching(
        wallet: GpWallet,
        pool: SqlitePool,
        default_mode: MatchMode,
        webhook_url: Option<String>,
        webhook_secret: Option<String>,
    ) -> WalletReceiver {
        let webhook = match (webhook_url, webhook_secret) {
            (Some(url), Some(secret)) => Some((url, secret)),
            _ => None,
        };
        WalletReceiver {
            wallet,
            pool,
            default_mode,
            webhook,
        }
    }

    /// Handle an S1 that grin-wallet refuses because it has already received
    /// this slate.
    ///
    /// Usually that is a plain replay of a wrap whose reply went missing, and
    /// the wrap is dropped: the payment row already holds the S2, and the
    /// unreplied sweep re-sends it. But the same error also covers the case
    /// where the FIRST receive succeeded in the wallet and then failed to
    /// record. Treating that as a replay dropped the wrap for good, and since
    /// no row existed the unreplied sweep had nothing to re-send either: the
    /// payer was stranded with locked inputs and no S2, permanently.
    ///
    /// So the ledger decides. With no row, the earlier receive left an orphan:
    /// an output and a tx-log entry the payer was never told about (the S2 is
    /// only released after the row is written). Its slate context is not kept
    /// by grin-wallet, so the S2 cannot be rebuilt; the receive is instead
    /// released with `cancel_tx` and run again on the same S1, which yields a
    /// fresh, valid S2. Cancelling is safe exactly because no reply ever went
    /// out, and grin refuses to cancel a confirmed transaction anyway.
    ///
    /// Every failure here returns [`ReceiveError::Failed`], so the wrap is
    /// retried rather than dropped. A wrap is only ever dropped on positive
    /// evidence that the payment is already on the ledger.
    async fn recover_duplicate(&self, s1_armor: &str) -> Result<gp_wallet::Received, ReceiveError> {
        // Read the slate id back off the S1 (no wallet state is touched).
        let slate_id = match self.wallet.slatepack_kind(s1_armor) {
            Ok((slate_id, _state)) => slate_id,
            Err(e) => {
                warn!("duplicate receive: cannot read the slatepack back: {e}");
                return Err(ReceiveError::Failed(format!("cannot read slatepack: {e}")));
            }
        };
        match duplicate_action(&self.pool, &slate_id).await {
            DuplicateAction::Drop => Err(ReceiveError::Duplicate),
            DuplicateAction::Retry(e) => {
                warn!("duplicate receive {slate_id}: ledger unreadable ({e}); will retry");
                Err(ReceiveError::Failed(format!("ledger unreadable: {e}")))
            }
            DuplicateAction::Recover => {
                warn!("duplicate receive {slate_id} has no payment row: redoing the receive");
                if let Err(e) =
                    crate::record::wallet_cancel(self.wallet.clone(), slate_id.clone()).await
                {
                    warn!(
                        "duplicate receive {slate_id}: cannot release the orphan ({e}); will retry"
                    );
                    return Err(ReceiveError::Failed(format!(
                        "cannot release the orphaned receive: {e}"
                    )));
                }
                self.wallet.receive_slatepack(s1_armor).map_err(|e| {
                    warn!("duplicate receive {slate_id}: redo failed ({e}); will retry");
                    ReceiveError::Failed(format!("receive redo failed: {e}"))
                })
            }
        }
    }
}

/// The text grin-wallet's duplicate-receive guard puts in its error message
/// (`Error::TransactionAlreadyReceived`, "Transaction <uuid> has already been
/// received"). gp-wallet flattens grin-wallet errors to strings by design, so
/// this is the only handle on that case; the pinning test below asserts the real
/// upstream variant still renders it.
const ALREADY_RECEIVED: &str = "already been received";

/// Classify a wallet receive failure for the transport.
///
/// A slatepack the wallet refuses is permanently bad (drop the wrap); a slate
/// grin has already received is a replay, decided against the ledger by
/// [`duplicate_action`] before any wrap is dropped; every other failure is
/// transient, so the wrap stays unmarked and the next catch-up retries it.
/// Split out so the classification is testable without a wallet.
fn map_receive_error(e: WalletError) -> ReceiveError {
    match e {
        WalletError::Slatepack(m) => ReceiveError::Rejected(m),
        WalletError::Wallet(m) if m.contains(ALREADY_RECEIVED) => ReceiveError::Duplicate,
        other => ReceiveError::Failed(other.to_string()),
    }
}

/// What a duplicate receive means, decided from the ledger alone.
#[derive(Debug, PartialEq, Eq)]
enum DuplicateAction {
    /// A payment row exists, so the first receive ran to completion and its S2
    /// is on file. A true replay: drop the wrap.
    Drop,
    /// No payment row. The first receive left an output and a tx-log entry in
    /// the wallet but nothing on the ledger, which means no S2 was ever handed
    /// back (the reply is only released once the row is written). Redo it.
    Recover,
    /// The ledger could not be consulted. Retry later: a wrap is never dropped
    /// on a guess, because dropping it is the one irreversible choice here.
    Retry(String),
}

/// Decide what to do about a slate grin-wallet refuses as already received.
///
/// The whole question is whether the earlier receive produced a payment row. It
/// is a pure ledger read, so every branch is testable without a wallet.
async fn duplicate_action(pool: &SqlitePool, slate_id: &str) -> DuplicateAction {
    match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM payment WHERE slate_id = ?1")
        .bind(slate_id)
        .fetch_one(pool)
        .await
    {
        Ok(0) => DuplicateAction::Recover,
        Ok(_) => DuplicateAction::Drop,
        Err(e) => DuplicateAction::Retry(e.to_string()),
    }
}

impl SlatepackReceiver for WalletReceiver {
    async fn receive(
        &self,
        s1_armor: &str,
        ctx: &IncomingContext<'_>,
    ) -> Result<ReceivedPayment, ReceiveError> {
        // The wallet enforces everything slate-level: parse, S1-only,
        // receive_tx (offline), S2 armor. `receive_slatepack` blocks for a
        // few milliseconds; the ingest loop is this runtime's only consumer,
        // so a direct call is fine (Goblin does the same).
        let received = match self.wallet.receive_slatepack(s1_armor) {
            Ok(received) => received,
            Err(e) => match map_receive_error(e) {
                ReceiveError::Duplicate => self.recover_duplicate(s1_armor).await?,
                other => return Err(other),
            },
        };

        // Persist, match (all three modes), and enqueue the webhook. Side
        // effects only: the reply is what completes the payment, so a matching
        // or webhook hiccup never fails the receive.
        //
        // The amount-binding guard is the exception: a slate that resolves to an
        // invoice but pays the wrong amount is rejected here, BEFORE the S2 reply
        // is handed back, so the transport never returns the reply the payer's
        // wallet needs to broadcast — the underpayment cannot complete.
        match persist_and_match(
            &self.pool,
            &received,
            Some(ctx.payer_hex),
            ctx.recipient_hex,
            ctx.memo,
            self.default_mode,
            self.webhook.as_ref(),
        )
        .await
        {
            // The payment could not be recorded at all. Return a TRANSIENT
            // failure: gp-nostr leaves the wrap unmarked and no S2 goes back, so
            // the payer cannot broadcast a transaction this till has no ledger
            // entry for.
            Err(e) => {
                warn!("ingest could not record {}: {e}", received.slate_id);
                return Err(ReceiveError::Failed(format!("payment not recorded: {e}")));
            }
            Ok(PersistOutcome::Matched(matched)) => {
                // This payment settled a grin1 invoice by a route other than
                // its issued I1: cancel that stale invoice slate.
                crate::record::cancel_stale_grin1(
                    &self.pool,
                    &matched,
                    &received.slate_id,
                    &self.wallet,
                )
                .await;
            }
            Ok(PersistOutcome::Rejected(mismatch)) => {
                warn!(
                    "ingest rejected {}: pays {} nanogrin, invoice expects {} nanogrin",
                    received.slate_id, mismatch.received, mismatch.expected
                );
                return Err(ReceiveError::Rejected(format!(
                    "payment pays {} nanogrin but the invoice expects exactly {} nanogrin",
                    mismatch.received, mismatch.expected
                )));
            }
        }

        Ok(ReceivedPayment {
            slate_id: received.slate_id,
            amount: received.amount,
            s2_armor: received.s2_armor,
        })
    }

    async fn mark_replied(&self, slate_id: &str) {
        if let Err(e) = sqlx::query("UPDATE payment SET status = 'replied' WHERE slate_id = ?1")
            .bind(slate_id)
            .execute(&self.pool)
            .await
        {
            warn!("payment status update failed for {slate_id}: {e}");
        }
    }

    async fn unreplied(&self) -> Vec<UnrepliedPayment> {
        let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT slate_id, payer, s2_armor, recipient FROM payment \
             WHERE status = 'received' AND s2_armor IS NOT NULL AND payer IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            warn!("unreplied payment query failed: {e}");
            vec![]
        });
        rows.into_iter()
            .map(
                |(slate_id, payer_hex, s2_armor, recipient)| UnrepliedPayment {
                    slate_id,
                    payer_hex,
                    s2_armor,
                    recipient_hex: recipient.unwrap_or_default(),
                },
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_receive_error_text_is_pinned_to_grin_wallet() {
        // gp-wallet flattens grin-wallet errors to strings, so the duplicate
        // guard reads TEXT. Build the REAL upstream error the wallet raises when
        // a slate is received twice (libwallet/src/api_impl/foreign.rs:92 raises
        // Error::TransactionAlreadyReceived) and assert the phrase we match on
        // is still in it. A grin-wallet bump that reworded it fails HERE, loudly,
        // instead of silently reclassifying every replayed slate as a transient
        // failure: gp-nostr would then leave the wrap unmarked and retry it
        // forever, and the ingest log would fill with false alarms.
        let slate = "0199a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a5b";
        let upstream = grin_wallet_libwallet::Error::TransactionAlreadyReceived(slate.into());
        let rendered = upstream.to_string();
        assert!(
            rendered.contains(ALREADY_RECEIVED),
            "grin-wallet reworded its duplicate-receive error: {rendered}"
        );

        // And that message, as gp-wallet surfaces it, classifies as a duplicate.
        assert!(matches!(
            map_receive_error(WalletError::Wallet(rendered)),
            ReceiveError::Duplicate
        ));
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

    async fn insert_payment(pool: &SqlitePool, slate_id: &str) {
        sqlx::query(
            "INSERT INTO payment (id, amount, slate_id, s2_armor, status, created_at) \
             VALUES (?1, 10, ?1, 'BEGINSLATEPACK.s2.ENDSLATEPACK.', 'received', \
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
        )
        .bind(slate_id)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_duplicate_is_only_dropped_when_the_ledger_proves_it() {
        let pool = pool().await;

        // No row: the first receive recorded nothing, so no S2 can ever have
        // reached the payer. Redo it rather than drop the wrap.
        assert_eq!(
            duplicate_action(&pool, "slate-orphan").await,
            DuplicateAction::Recover
        );

        // A row exists: the first receive completed and its S2 is on file, so
        // this really is a replay.
        insert_payment(&pool, "slate-recorded").await;
        assert_eq!(
            duplicate_action(&pool, "slate-recorded").await,
            DuplicateAction::Drop
        );

        // The ledger itself is unreadable: never guess. Dropping the wrap is
        // the one irreversible choice, so retry instead.
        sqlx::query("DROP TABLE payment")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            matches!(
                duplicate_action(&pool, "slate-recorded").await,
                DuplicateAction::Retry(_)
            ),
            "an unreadable ledger must never drop a wrap"
        );
    }

    #[test]
    fn other_wallet_failures_keep_their_own_class() {
        // A bad slatepack is permanently rejected...
        assert!(matches!(
            map_receive_error(WalletError::Slatepack("not an S1".into())),
            ReceiveError::Rejected(m) if m == "not an S1"
        ));
        // ...while anything else is transient, so the wrap is retried rather
        // than dropped. An incoming payment is never lost to a hiccup.
        assert!(matches!(
            map_receive_error(WalletError::Wallet("Client Callback Error".into())),
            ReceiveError::Failed(_)
        ));
        assert!(matches!(
            map_receive_error(WalletError::Config("no node URL".into())),
            ReceiveError::Failed(_)
        ));
    }
}
