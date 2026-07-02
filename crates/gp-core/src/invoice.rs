//! Invoices: the optional order-matching layer over received payments.
//!
//! An invoice pins an expected payment (an amount, or a fiat quote to be
//! filled by the conversion milestone) to an order reference and mints an
//! unguessable checkout token for the hosted `/pay/<token>` page. Its
//! recipient identity is either the server's master Nostr key (for memo and
//! amount matching) or a per-invoice derived child (matching mode 2); only the
//! public key is stored, the child secret is recomputed on demand.
//!
//! Lifecycle: `open` -> `paid` (a received payment matched it) or `expired`
//! (its expiry passed while still open). Expiry is evaluated lazily on read
//! and by a periodic sweep, never by a background per-invoice timer.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::config::MatchMode;
use crate::{derive, ids};

/// Invoice lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvoiceStatus {
    /// Awaiting a matching payment.
    Open,
    /// A received payment matched this invoice.
    Paid,
    /// Expiry passed before a payment matched.
    Expired,
}

impl InvoiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            InvoiceStatus::Open => "open",
            InvoiceStatus::Paid => "paid",
            InvoiceStatus::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> InvoiceStatus {
        match s {
            "paid" => InvoiceStatus::Paid,
            "expired" => InvoiceStatus::Expired,
            _ => InvoiceStatus::Open,
        }
    }
}

/// How to state an invoice amount at creation: an exact Grin amount, a raw
/// fiat amount plus currency (unpriced), or a fiat amount already priced into
/// Grin by the conversion oracle (milestone 7).
///
/// The connector/API sends `Grin` or `Fiat`; the server resolves a `Fiat`
/// through the oracle into a `FiatQuoted` (with the locked nanogrin) before
/// persisting, so a fiat invoice's `expected_amount` is filled and it matches
/// by amount. A bare `Fiat` that reaches persistence stays unpriced
/// (`expected_amount` NULL), matchable only by memo or a derived identity.
#[derive(Debug, Clone)]
pub enum AmountSpec {
    /// Exact amount in nanogrin.
    Grin(u64),
    /// Fiat amount (decimal string) in the given ISO currency code, not yet
    /// priced (the pre-oracle state; expected_amount stays NULL).
    Fiat { amount: String, currency: String },
    /// A fiat amount priced into Grin by the oracle: the locked quote.
    FiatQuoted {
        /// The original fiat amount (decimal string), echoed for display.
        amount: String,
        /// The ISO currency code.
        currency: String,
        /// The locked Grin amount in nanogrin (becomes `expected_amount`).
        nanogrin: u64,
        /// The rate used, fiat per GRIN (decimal string, for the receipt).
        rate: String,
        /// The oracle source the rate came from (e.g. `coingecko`).
        source: String,
    },
}

/// Parameters for [`create`].
#[derive(Debug, Clone)]
pub struct NewInvoice {
    /// The store's order reference (also the memo/subject match key).
    pub order_ref: Option<String>,
    /// The amount, exact Grin or a fiat quote.
    pub amount: AmountSpec,
    /// A human memo shown on the checkout page.
    pub memo: Option<String>,
    /// Per-invoice matching-mode override; `None` uses the global default.
    pub match_mode: Option<MatchMode>,
    /// Expiry, seconds from now; `None` means no expiry.
    pub expiry_secs: Option<i64>,
}

/// A persisted invoice row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Invoice {
    pub id: String,
    #[sqlx(rename = "ref")]
    pub order_ref: Option<String>,
    pub expected_amount: Option<i64>,
    pub expiry: Option<String>,
    pub status: String,
    pub created_at: String,
    pub token: Option<String>,
    pub memo: Option<String>,
    pub recipient_pubkey: Option<String>,
    pub fiat_amount: Option<String>,
    pub fiat_currency: Option<String>,
    pub match_mode: Option<String>,
    pub paid_payment_id: Option<String>,
    pub paid_at: Option<String>,
    /// The locked rate (fiat per GRIN) a fiat quote was priced at, else NULL.
    pub quote_rate: Option<String>,
    /// The oracle source the quote came from (e.g. `coingecko`), else NULL.
    pub quote_source: Option<String>,
}

impl Invoice {
    /// The effective matching mode: the per-invoice override, else the global
    /// default supplied by the caller.
    pub fn effective_mode(&self, default: MatchMode) -> MatchMode {
        match self.match_mode.as_deref() {
            Some("memo") => MatchMode::Memo,
            Some("derived") => MatchMode::Derived,
            Some("amount") => MatchMode::Amount,
            _ => default,
        }
    }

    /// The status as a typed enum.
    pub fn status(&self) -> InvoiceStatus {
        InvoiceStatus::parse(&self.status)
    }
}

fn mode_str(mode: MatchMode) -> &'static str {
    match mode {
        MatchMode::Memo => "memo",
        MatchMode::Derived => "derived",
        MatchMode::Amount => "amount",
    }
}

/// Create an invoice: mint an id + checkout token, resolve the recipient
/// identity (a per-invoice derived child in `derived` mode, else the server
/// master key), persist it `open`, and return the row.
///
/// `master_sk` is the server Nostr secret (used only to derive the child
/// public key; the secret is never stored). `master_pubkey_hex` is the
/// server's own x-only key, used as the recipient for memo/amount invoices.
pub async fn create(
    pool: &SqlitePool,
    params: NewInvoice,
    master_sk: &[u8; 32],
    master_pubkey_hex: &str,
    default_mode: MatchMode,
) -> Result<Invoice, sqlx::Error> {
    let id = ids::random_id();
    let token = ids::checkout_token();
    let effective = params.match_mode.unwrap_or(default_mode);

    // Derived mode gets a unique per-invoice child key; everything else
    // receives on the server's own identity and matches by memo or amount.
    let recipient_pubkey = if effective == MatchMode::Derived {
        derive::invoice_pubkey_hex(master_sk, &id)
    } else {
        master_pubkey_hex.to_string()
    };

    let (expected_amount, fiat_amount, fiat_currency, quote_rate, quote_source) =
        match &params.amount {
            AmountSpec::Grin(nano) => (Some(*nano as i64), None, None, None, None),
            AmountSpec::Fiat { amount, currency } => (
                None,
                Some(amount.clone()),
                Some(currency.clone()),
                None,
                None,
            ),
            AmountSpec::FiatQuoted {
                amount,
                currency,
                nanogrin,
                rate,
                source,
            } => (
                Some(*nanogrin as i64),
                Some(amount.clone()),
                Some(currency.clone()),
                Some(rate.clone()),
                Some(source.clone()),
            ),
        };

    // Store the per-invoice override only when it differs from a bare default,
    // so an invoice created under one global default keeps behaving as created
    // even if the operator later changes GP_MATCH_MODE.
    let stored_mode = params.match_mode.map(mode_str);

    sqlx::query(
        "INSERT INTO invoice \
         (id, ref, expected_amount, expiry, status, created_at, token, memo, \
          recipient_pubkey, fiat_amount, fiat_currency, match_mode, \
          quote_rate, quote_source) \
         VALUES (?1, ?2, ?3, \
                 CASE WHEN ?4 IS NULL THEN NULL \
                      ELSE strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?4) END, \
                 'open', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), \
                 ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )
    .bind(&id)
    .bind(&params.order_ref)
    .bind(expected_amount)
    .bind(params.expiry_secs.map(|s| format!("{s:+} seconds")))
    .bind(&token)
    .bind(&params.memo)
    .bind(&recipient_pubkey)
    .bind(&fiat_amount)
    .bind(&fiat_currency)
    .bind(stored_mode)
    .bind(&quote_rate)
    .bind(&quote_source)
    .execute(pool)
    .await?;

    get(pool, &id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

const COLUMNS: &str = "id, ref, expected_amount, expiry, status, created_at, token, memo, \
     recipient_pubkey, fiat_amount, fiat_currency, match_mode, paid_payment_id, paid_at, \
     quote_rate, quote_source";

/// Fetch an invoice by id, marking it expired first if its expiry has passed.
pub async fn get(pool: &SqlitePool, id: &str) -> Result<Option<Invoice>, sqlx::Error> {
    expire_if_due_id(pool, id).await?;
    let sql = format!("SELECT {COLUMNS} FROM invoice WHERE id = ?1");
    sqlx::query_as::<_, Invoice>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Fetch an invoice by its checkout token (the `/pay/<token>` bearer),
/// marking it expired first if due.
pub async fn get_by_token(pool: &SqlitePool, token: &str) -> Result<Option<Invoice>, sqlx::Error> {
    // Expire lazily so the hosted page reflects the true status on load.
    sqlx::query(
        "UPDATE invoice SET status = 'expired' \
         WHERE token = ?1 AND status = 'open' \
           AND expiry IS NOT NULL AND expiry <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
    )
    .bind(token)
    .execute(pool)
    .await?;
    let sql = format!("SELECT {COLUMNS} FROM invoice WHERE token = ?1");
    sqlx::query_as::<_, Invoice>(&sql)
        .bind(token)
        .fetch_optional(pool)
        .await
}

/// The most recent invoices, newest first (admin listing).
pub async fn list(pool: &SqlitePool, limit: i64) -> Result<Vec<Invoice>, sqlx::Error> {
    expire_due(pool).await?;
    let sql = format!("SELECT {COLUMNS} FROM invoice ORDER BY created_at DESC LIMIT ?1");
    sqlx::query_as::<_, Invoice>(&sql)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Mark an invoice paid, linking the payment that satisfied it. Idempotent:
/// only an `open` invoice transitions, so a replayed match is a no-op.
pub async fn mark_paid(
    pool: &SqlitePool,
    invoice_id: &str,
    payment_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoice SET status = 'paid', paid_payment_id = ?2, \
         paid_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
         WHERE id = ?1 AND status = 'open'",
    )
    .bind(invoice_id)
    .bind(payment_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Sweep: mark every open invoice whose expiry has passed as expired.
pub async fn expire_due(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE invoice SET status = 'expired' \
         WHERE status = 'open' AND expiry IS NOT NULL \
           AND expiry <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

async fn expire_if_due_id(pool: &SqlitePool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE invoice SET status = 'expired' \
         WHERE id = ?1 AND status = 'open' \
           AND expiry IS NOT NULL AND expiry <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    async fn pool() -> SqlitePool {
        // In-memory database, migrated: fast and isolated per test.
        db::test_pool().await
    }

    const MASTER: [u8; 32] = [3u8; 32];
    const MASTER_PUB: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn grin(nano: u64) -> NewInvoice {
        NewInvoice {
            order_ref: Some("order-7".into()),
            amount: AmountSpec::Grin(nano),
            memo: Some("Coffee".into()),
            match_mode: None,
            expiry_secs: None,
        }
    }

    #[tokio::test]
    async fn create_get_and_token_roundtrip() {
        let pool = pool().await;
        let inv = create(
            &pool,
            grin(1_500_000_000),
            &MASTER,
            MASTER_PUB,
            MatchMode::Memo,
        )
        .await
        .unwrap();
        assert_eq!(inv.status(), InvoiceStatus::Open);
        assert_eq!(inv.expected_amount, Some(1_500_000_000));
        assert_eq!(inv.order_ref.as_deref(), Some("order-7"));
        let token = inv.token.clone().unwrap();
        assert_eq!(token.len(), 43);

        let by_id = get(&pool, &inv.id).await.unwrap().unwrap();
        assert_eq!(by_id.id, inv.id);
        let by_token = get_by_token(&pool, &token).await.unwrap().unwrap();
        assert_eq!(by_token.id, inv.id);
        // Memo-mode invoices receive on the master identity.
        assert_eq!(by_token.recipient_pubkey.as_deref(), Some(MASTER_PUB));
    }

    #[tokio::test]
    async fn derived_mode_gets_a_unique_child_recipient() {
        let pool = pool().await;
        let mut p = grin(1);
        p.match_mode = Some(MatchMode::Derived);
        let inv = create(&pool, p, &MASTER, MASTER_PUB, MatchMode::Memo)
            .await
            .unwrap();
        let recipient = inv.recipient_pubkey.clone().unwrap();
        assert_ne!(recipient, MASTER_PUB, "derived mode must not reuse master");
        // Stateless: recomputing from the invoice id yields the same key.
        assert_eq!(recipient, derive::invoice_pubkey_hex(&MASTER, &inv.id));
        assert_eq!(inv.effective_mode(MatchMode::Memo), MatchMode::Derived);
    }

    #[tokio::test]
    async fn fiat_invoice_has_no_expected_grin_amount_yet() {
        let pool = pool().await;
        let p = NewInvoice {
            order_ref: None,
            amount: AmountSpec::Fiat {
                amount: "19.99".into(),
                currency: "USD".into(),
            },
            memo: None,
            match_mode: None,
            expiry_secs: None,
        };
        let inv = create(&pool, p, &MASTER, MASTER_PUB, MatchMode::Amount)
            .await
            .unwrap();
        assert_eq!(inv.expected_amount, None);
        assert_eq!(inv.fiat_amount.as_deref(), Some("19.99"));
        assert_eq!(inv.fiat_currency.as_deref(), Some("USD"));
    }

    #[tokio::test]
    async fn expiry_is_evaluated_lazily() {
        let pool = pool().await;
        let mut p = grin(1);
        p.expiry_secs = Some(-1); // already in the past
        let inv = create(&pool, p, &MASTER, MASTER_PUB, MatchMode::Memo)
            .await
            .unwrap();
        // Fetching it flips open -> expired.
        let fetched = get(&pool, &inv.id).await.unwrap().unwrap();
        assert_eq!(fetched.status(), InvoiceStatus::Expired);
    }

    #[tokio::test]
    async fn mark_paid_is_idempotent() {
        let pool = pool().await;
        let inv = create(&pool, grin(10), &MASTER, MASTER_PUB, MatchMode::Memo)
            .await
            .unwrap();
        assert!(mark_paid(&pool, &inv.id, "pay-1").await.unwrap());
        // Second call does not transition again (already paid).
        assert!(!mark_paid(&pool, &inv.id, "pay-2").await.unwrap());
        let fetched = get(&pool, &inv.id).await.unwrap().unwrap();
        assert_eq!(fetched.status(), InvoiceStatus::Paid);
        assert_eq!(fetched.paid_payment_id.as_deref(), Some("pay-1"));
    }
}
