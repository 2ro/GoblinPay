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

use crate::record::persist_and_match;

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
        let received = self
            .wallet
            .receive_slatepack(s1_armor)
            .map_err(|e| match e {
                WalletError::Slatepack(m) => ReceiveError::Rejected(m),
                // gp-wallet errors are strings by design; grin's own
                // duplicate-receive guard surfaces through this message.
                WalletError::Wallet(m) if m.contains("already been received") => {
                    ReceiveError::Duplicate
                }
                other => ReceiveError::Failed(other.to_string()),
            })?;

        // Persist, match (all three modes), and enqueue the webhook. Side
        // effects only: the reply is what completes the payment, so a matching
        // or webhook hiccup never fails the receive.
        persist_and_match(
            &self.pool,
            &received,
            Some(ctx.payer_hex),
            ctx.recipient_hex,
            ctx.memo,
            self.default_mode,
            self.webhook.as_ref(),
        )
        .await;

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
