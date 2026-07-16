//! The shared matching layer: map one received payment to an open invoice
//! (advancing its status) and to a tenant user (for crediting), composing all
//! three matching modes.
//!
//! An incoming payment carries the identity it was received on (the master key
//! or a per-invoice / per-user derived child), the amount, and an optional
//! memo (the payer's `subject` tag). Resolution tries, in order:
//!
//! 1. **Derived identity** (mode 2) — the recipient pubkey uniquely names a
//!    per-invoice child, an O(1) indexed lookup. Recommended for stores.
//! 2. **Memo / reference** (mode 1) — the memo equals the invoice's order ref.
//! 3. **Amount** (mode 3) — the exact expected amount, among unexpired open
//!    invoices, oldest first.
//!
//! Each candidate is scoped to invoices whose *effective* mode is that mode
//! (the per-invoice override, else the global default), so an amount-mode
//! invoice is never matched by a same-amount derived-mode invoice and vice
//! versa. User crediting (5b) is resolved independently from the endpub the
//! payment landed on and composes with any invoice match.
//!
//! This runs after the wallet has recorded the payment; it is a pure database
//! operation over synthetic inputs, so every mode is unit-testable without a
//! relay or a wallet.

use sqlx::SqlitePool;

use crate::config::MatchMode;
use crate::{endpub, invoice};

/// One received payment presented to the matcher. `slate_id` is also the
/// payment row id.
#[derive(Debug, Clone)]
pub struct IncomingPayment<'a> {
    pub slate_id: &'a str,
    pub amount: u64,
    /// The server identity that received it (master or a derived child),
    /// x-only hex.
    pub recipient_hex: &'a str,
    /// The payer's sanitized memo (subject tag), if any.
    pub memo: Option<&'a str>,
}

/// A resolved invoice whose expected amount did not equal the received amount:
/// the payment is REJECTED (never marked paid, never linked). Carries the exact
/// figures (nanogrin) so the caller can tell the payer precisely what to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmountMismatch {
    /// The invoice's locked expected amount, in nanogrin.
    pub expected: u64,
    /// The amount the pasted/received slate actually pays, in nanogrin.
    pub received: u64,
}

/// What the payment resolved to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchResult {
    /// The invoice it satisfied, if any.
    pub invoice_id: Option<String>,
    /// The tenant user it credits, if the endpub belongs to one.
    pub user_id: Option<String>,
    /// Set when a candidate invoice was resolved by identity/memo but its
    /// expected amount does not equal the received amount. The payment is then
    /// rejected: `invoice_id`/`user_id` are cleared and nothing is marked paid.
    pub amount_mismatch: Option<AmountMismatch>,
}

/// Resolve `incoming` against the open invoices and endpubs, mark a matched
/// invoice paid, and link the payment row to the invoice + user. Returns what
/// it matched.
pub async fn match_payment(
    pool: &SqlitePool,
    default_mode: MatchMode,
    incoming: &IncomingPayment<'_>,
) -> Result<MatchResult, sqlx::Error> {
    let default = mode_str(default_mode);

    // 5b: which tenant user does this endpub credit? Independent of invoices.
    let user_id = endpub::user_for_pubkey(pool, incoming.recipient_hex)
        .await?
        .map(|(user, _epoch)| user);

    // Invoice resolution, first hit wins across the three scoped modes.
    let invoice_id = resolve_derived(pool, default, incoming.recipient_hex).await?;
    let invoice_id = match invoice_id {
        Some(id) => Some(id),
        None => match incoming.memo {
            Some(memo) => resolve_memo(pool, default, memo).await?,
            None => None,
        },
    };
    let invoice_id = match invoice_id {
        Some(id) => Some(id),
        None => resolve_amount(pool, default, incoming.amount).await?,
    };

    // Amount binding (money-path guard): a resolved invoice that carries an
    // exact expected amount must be paid in full — no under-, no overpayment.
    // Amount-mode already resolved on the exact amount, but derived/memo mode
    // matched on identity/reference alone and did NOT check the amount, which is
    // the underpayment hole. An open-amount invoice (`expected_amount` NULL)
    // binds nothing and accepts any amount. On a mismatch the payment is
    // rejected outright: nothing is marked paid, nothing is linked, and the
    // caller (manual paste / Nostr ingest) is told the exact expected figure.
    if let Some(id) = &invoice_id {
        let expected: Option<i64> =
            sqlx::query_scalar("SELECT expected_amount FROM invoice WHERE id = ?1")
                .bind(id)
                .fetch_one(pool)
                .await?;
        if let Some(expected) = expected {
            let expected = expected.max(0) as u64;
            if incoming.amount != expected {
                return Ok(MatchResult {
                    invoice_id: None,
                    user_id: None,
                    amount_mismatch: Some(AmountMismatch {
                        expected,
                        received: incoming.amount,
                    }),
                });
            }
        }
    }

    if let Some(id) = &invoice_id {
        invoice::mark_paid(pool, id, incoming.slate_id).await?;
    }

    // Link the payment row to whatever it resolved to (both optional).
    sqlx::query("UPDATE payment SET invoice_id = ?2, user_id = ?3 WHERE id = ?1")
        .bind(incoming.slate_id)
        .bind(&invoice_id)
        .bind(&user_id)
        .execute(pool)
        .await?;

    Ok(MatchResult {
        invoice_id,
        user_id,
        amount_mismatch: None,
    })
}

fn mode_str(mode: MatchMode) -> &'static str {
    match mode {
        MatchMode::Memo => "memo",
        MatchMode::Derived => "derived",
        MatchMode::Amount => "amount",
    }
}

async fn resolve_derived(
    pool: &SqlitePool,
    default: &str,
    recipient_hex: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM invoice \
         WHERE recipient_pubkey = ?1 AND status = 'open' \
           AND COALESCE(match_mode, ?2) = 'derived' \
         ORDER BY created_at LIMIT 1",
    )
    .bind(recipient_hex)
    .bind(default)
    .fetch_optional(pool)
    .await
}

async fn resolve_memo(
    pool: &SqlitePool,
    default: &str,
    memo: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM invoice \
         WHERE ref = ?1 AND status = 'open' \
           AND COALESCE(match_mode, ?2) = 'memo' \
         ORDER BY created_at LIMIT 1",
    )
    .bind(memo)
    .bind(default)
    .fetch_optional(pool)
    .await
}

async fn resolve_amount(
    pool: &SqlitePool,
    default: &str,
    amount: u64,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM invoice \
         WHERE expected_amount = ?1 AND status = 'open' \
           AND COALESCE(match_mode, ?2) = 'amount' \
           AND (expiry IS NULL OR expiry > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')) \
         ORDER BY created_at LIMIT 1",
    )
    .bind(amount as i64)
    .bind(default)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::invoice::{AmountSpec, NewInvoice};

    async fn pool() -> SqlitePool {
        db::test_pool().await
    }

    const MASTER: [u8; 32] = [11u8; 32];
    const MASTER_PUB: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// Insert a payment row the way the ingest adapter does, so matching has a
    /// row to link.
    async fn insert_payment(pool: &SqlitePool, slate_id: &str, amount: u64, recipient: &str) {
        sqlx::query(
            "INSERT INTO payment (id, amount, payer, slate_id, recipient, status, created_at) \
             VALUES (?1, ?2, 'payerhex', ?1, ?3, 'received', \
                     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))",
        )
        .bind(slate_id)
        .bind(amount as i64)
        .bind(recipient)
        .execute(pool)
        .await
        .unwrap();
    }

    fn new(amount: AmountSpec, order_ref: Option<&str>, mode: Option<MatchMode>) -> NewInvoice {
        NewInvoice {
            order_ref: order_ref.map(|s| s.to_string()),
            amount,
            memo: None,
            match_mode: mode,
            expiry_secs: None,
        }
    }

    #[tokio::test]
    async fn memo_mode_matches_by_order_ref() {
        let pool = pool().await;
        let inv = invoice::create(
            &pool,
            new(
                AmountSpec::Grin(100),
                Some("order-42"),
                Some(MatchMode::Memo),
            ),
            &MASTER,
            MASTER_PUB,
            MatchMode::Memo,
        )
        .await
        .unwrap();
        insert_payment(&pool, "slate-a", 100, MASTER_PUB).await;

        let result = match_payment(
            &pool,
            MatchMode::Memo,
            &IncomingPayment {
                slate_id: "slate-a",
                amount: 100,
                recipient_hex: MASTER_PUB,
                memo: Some("order-42"),
            },
        )
        .await
        .unwrap();

        assert_eq!(result.invoice_id.as_deref(), Some(inv.id.as_str()));
        assert_eq!(
            invoice::get(&pool, &inv.id)
                .await
                .unwrap()
                .unwrap()
                .status(),
            invoice::InvoiceStatus::Paid
        );
        // The payment row is linked back.
        let linked: Option<String> =
            sqlx::query_scalar("SELECT invoice_id FROM payment WHERE id = 'slate-a'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(linked.as_deref(), Some(inv.id.as_str()));
    }

    #[tokio::test]
    async fn derived_mode_matches_by_recipient_identity() {
        let pool = pool().await;
        let inv = invoice::create(
            &pool,
            new(AmountSpec::Grin(100), None, Some(MatchMode::Derived)),
            &MASTER,
            MASTER_PUB,
            MatchMode::Memo,
        )
        .await
        .unwrap();
        let recipient = inv.recipient_pubkey.clone().unwrap();
        // The derived identity is unambiguous, and the amount matches the
        // invoice exactly (the amount-binding guard now REQUIRES this).
        insert_payment(&pool, "slate-b", 100, &recipient).await;

        let result = match_payment(
            &pool,
            MatchMode::Memo,
            &IncomingPayment {
                slate_id: "slate-b",
                amount: 100,
                recipient_hex: &recipient,
                memo: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.invoice_id.as_deref(), Some(inv.id.as_str()));
        assert!(result.amount_mismatch.is_none());
    }

    #[tokio::test]
    async fn derived_mode_rejects_underpayment_and_overpayment() {
        // The underpayment hole: a derived-identity match must not flip the
        // invoice paid unless the amount equals the invoice exactly. Both an
        // underpayment and an overpayment are rejected, the invoice stays open,
        // and the caller learns the exact expected figure.
        for pay in [50u64, 150u64] {
            let pool = pool().await;
            let inv = invoice::create(
                &pool,
                new(AmountSpec::Grin(100), None, Some(MatchMode::Derived)),
                &MASTER,
                MASTER_PUB,
                MatchMode::Memo,
            )
            .await
            .unwrap();
            let recipient = inv.recipient_pubkey.clone().unwrap();
            insert_payment(&pool, "slate-mis", pay, &recipient).await;

            let result = match_payment(
                &pool,
                MatchMode::Memo,
                &IncomingPayment {
                    slate_id: "slate-mis",
                    amount: pay,
                    recipient_hex: &recipient,
                    memo: None,
                },
            )
            .await
            .unwrap();

            // Not matched, not credited, and the exact mismatch is reported.
            assert_eq!(result.invoice_id, None, "pay {pay}: not matched");
            assert_eq!(
                result.amount_mismatch,
                Some(AmountMismatch {
                    expected: 100,
                    received: pay
                }),
                "pay {pay}"
            );
            // The invoice is untouched (still open) and the payment row is not
            // linked to it.
            assert_eq!(
                invoice::get(&pool, &inv.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status(),
                invoice::InvoiceStatus::Open,
                "pay {pay}: invoice stays open"
            );
            let linked: Option<String> =
                sqlx::query_scalar("SELECT invoice_id FROM payment WHERE id = 'slate-mis'")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(linked, None, "pay {pay}: payment not linked");
        }
    }

    #[tokio::test]
    async fn amount_mode_matches_exact_amount_oldest_first() {
        let pool = pool().await;
        let first = invoice::create(
            &pool,
            new(
                AmountSpec::Grin(2_000_000_000),
                None,
                Some(MatchMode::Amount),
            ),
            &MASTER,
            MASTER_PUB,
            MatchMode::Amount,
        )
        .await
        .unwrap();
        // A second same-amount invoice; the oldest open one wins.
        let _second = invoice::create(
            &pool,
            new(
                AmountSpec::Grin(2_000_000_000),
                None,
                Some(MatchMode::Amount),
            ),
            &MASTER,
            MASTER_PUB,
            MatchMode::Amount,
        )
        .await
        .unwrap();
        insert_payment(&pool, "slate-c", 2_000_000_000, MASTER_PUB).await;

        let result = match_payment(
            &pool,
            MatchMode::Amount,
            &IncomingPayment {
                slate_id: "slate-c",
                amount: 2_000_000_000,
                recipient_hex: MASTER_PUB,
                memo: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.invoice_id.as_deref(), Some(first.id.as_str()));
    }

    #[tokio::test]
    async fn mode_scoping_prevents_cross_mode_amount_collision() {
        let pool = pool().await;
        // A derived-mode invoice with the same amount must NOT be matched by an
        // amount-only payment on the master identity.
        let _derived = invoice::create(
            &pool,
            new(AmountSpec::Grin(500), None, Some(MatchMode::Derived)),
            &MASTER,
            MASTER_PUB,
            MatchMode::Amount,
        )
        .await
        .unwrap();
        insert_payment(&pool, "slate-d", 500, MASTER_PUB).await;

        let result = match_payment(
            &pool,
            MatchMode::Amount,
            &IncomingPayment {
                slate_id: "slate-d",
                amount: 500,
                recipient_hex: MASTER_PUB,
                memo: None,
            },
        )
        .await
        .unwrap();
        // No amount-mode invoice exists, so nothing matches.
        assert_eq!(result.invoice_id, None);
    }

    #[tokio::test]
    async fn credits_a_user_via_the_endpub_and_composes_with_invoices() {
        let pool = pool().await;
        let (_user, ep) = endpub::create_user(&pool, &MASTER, Some("alice".into()), None)
            .await
            .unwrap();
        insert_payment(&pool, "slate-e", 7, &ep.pubkey).await;

        let result = match_payment(
            &pool,
            MatchMode::Memo,
            &IncomingPayment {
                slate_id: "slate-e",
                amount: 7,
                recipient_hex: &ep.pubkey,
                memo: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.user_id.as_deref(), Some("alice"));
        assert_eq!(result.invoice_id, None);

        // The payment is credited to the user (balance reflects it).
        let balances = endpub::list_with_balances(&pool).await.unwrap();
        assert_eq!(balances[0].user_id, "alice");
        assert_eq!(balances[0].balance, 7);
    }

    #[tokio::test]
    async fn fiat_quoted_invoice_matches_a_synthetic_payment_of_the_quoted_amount() {
        use crate::rates::Oracle;

        let pool = pool().await;
        // Inject a fixed rate (no network): 0.02 USD/GRIN, so 10.00 USD is
        // 500 GRIN = 500_000_000_000 nanogrin.
        let oracle = Oracle::fixed(&["usd"], 0.02, 900);
        let quote = oracle.quote("10.00", "USD").await.unwrap();
        assert_eq!(quote.nanogrin, 500_000_000_000);

        // Create the fiat invoice priced by the oracle, amount-matched.
        let inv = invoice::create(
            &pool,
            NewInvoice {
                order_ref: None,
                amount: AmountSpec::FiatQuoted {
                    amount: "10.00".into(),
                    currency: "USD".into(),
                    nanogrin: quote.nanogrin,
                    rate: crate::rates::format_rate(quote.fiat_per_grin),
                    source: quote.source.to_string(),
                },
                memo: None,
                match_mode: Some(MatchMode::Amount),
                expiry_secs: Some(900),
            },
            &MASTER,
            MASTER_PUB,
            MatchMode::Amount,
        )
        .await
        .unwrap();
        // The gap M5 left is filled: expected_amount is the locked nanogrin, and
        // the quote (rate + source) is stored.
        assert_eq!(inv.expected_amount, Some(500_000_000_000));
        assert_eq!(inv.fiat_amount.as_deref(), Some("10.00"));
        assert_eq!(inv.fiat_currency.as_deref(), Some("USD"));
        assert_eq!(inv.quote_rate.as_deref(), Some("0.02"));
        assert_eq!(inv.quote_source.as_deref(), Some("coingecko"));

        // A payment of exactly the quoted amount matches by amount.
        insert_payment(&pool, "slate-fiat", 500_000_000_000, MASTER_PUB).await;
        let result = match_payment(
            &pool,
            MatchMode::Amount,
            &IncomingPayment {
                slate_id: "slate-fiat",
                amount: 500_000_000_000,
                recipient_hex: MASTER_PUB,
                memo: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.invoice_id.as_deref(), Some(inv.id.as_str()));
    }

    #[tokio::test]
    async fn expired_fiat_quote_is_not_matched_and_forces_a_requote() {
        let pool = pool().await;
        // A fiat quote whose lock window already elapsed (expiry in the past).
        let inv = invoice::create(
            &pool,
            NewInvoice {
                order_ref: None,
                amount: AmountSpec::FiatQuoted {
                    amount: "10.00".into(),
                    currency: "usd".into(),
                    nanogrin: 500_000_000_000,
                    rate: "0.02".into(),
                    source: "coingecko".into(),
                },
                memo: None,
                match_mode: Some(MatchMode::Amount),
                expiry_secs: Some(-1),
            },
            &MASTER,
            MASTER_PUB,
            MatchMode::Amount,
        )
        .await
        .unwrap();
        insert_payment(&pool, "slate-late", 500_000_000_000, MASTER_PUB).await;
        let result = match_payment(
            &pool,
            MatchMode::Amount,
            &IncomingPayment {
                slate_id: "slate-late",
                amount: 500_000_000_000,
                recipient_hex: MASTER_PUB,
                memo: None,
            },
        )
        .await
        .unwrap();
        // The stale-locked quote does not match; the checkout must re-quote.
        assert_eq!(result.invoice_id, None);
        assert_eq!(
            invoice::get(&pool, &inv.id)
                .await
                .unwrap()
                .unwrap()
                .status(),
            invoice::InvoiceStatus::Expired
        );
    }

    #[tokio::test]
    async fn unmatched_payment_returns_empty() {
        let pool = pool().await;
        insert_payment(&pool, "slate-f", 1, MASTER_PUB).await;
        let result = match_payment(
            &pool,
            MatchMode::Memo,
            &IncomingPayment {
                slate_id: "slate-f",
                amount: 1,
                recipient_hex: MASTER_PUB,
                memo: Some("no-such-order"),
            },
        )
        .await
        .unwrap();
        assert_eq!(result, MatchResult::default());
    }
}
