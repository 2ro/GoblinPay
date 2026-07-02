//! Conversion rates: the optional, configurable price oracle.
//!
//! A store priced in fiat (cryptodrip.com prices in USD) sends GoblinPay a
//! `{fiat amount, currency}` at checkout. This module quotes the equivalent
//! Grin amount, locks it for an expiry window, and hands back the nanogrin the
//! invoice's `expected_amount` is set to, so a fiat invoice then participates
//! in amount-matching exactly like a Grin-denominated one. Grin-denominated
//! invoices never touch this module.
//!
//! Transport (owner ruling, same as the M4 node client): the oracle HTTP goes
//! DIRECT over normal HTTP (reqwest with the process-installed rustls `ring`
//! provider, no aws-lc-rs), NEVER through the Nym tunnel. The mixnet in
//! gp-nostr carries only the Nostr gift-wrap layer; the price fetch is a server
//! concern that rides clearnet, mirroring the wallet<->node reads. This crate
//! has no Nym linkage at all, so the direct path is structural, not configured.
//!
//! Design:
//! - **Source** (`GP_RATE_SOURCE`, default `coingecko`): where the GRIN price
//!   comes from. CoinGecko lists GRIN under id `grin` and prices many fiats in
//!   one call (`/simple/price?ids=grin&vs_currencies=usd,eur,...`).
//! - **Rate cache** (`GP_RATE_CACHE_TTL`, default 60s): a fetched rate is
//!   reused for the TTL so concurrent checkouts do not hammer the source.
//! - **Quote lock** (`GP_QUOTE_TTL`, default 900s): a created invoice locks its
//!   Grin amount for this window (its `expiry`); an amount-match past the lock
//!   re-quotes rather than honouring a stale rate.
//! - **Stale fallback** (`GP_RATE_STALE_MAX`, default 0 = off): if a live fetch
//!   fails but the last cached rate is within this bound, serve it (flagged
//!   `stale`) instead of failing the checkout. 0 keeps the strict fail-fast.
//!
//! Testing: the conversion math, the CoinGecko parser (against a recorded
//! response fixture), the quote-lock predicate, and the cache-freshness logic
//! are all pure and unit-tested here. No test touches the network; the live
//! fetch path is exercised in the supervised integration round, the same
//! precedent as the M4 confirmation "found" path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{Config, RateSource};

/// The CoinGecko coin id for GRIN.
const COINGECKO_GRIN_ID: &str = "grin";
/// CoinGecko simple-price endpoint base (host-only kept for the log line).
const COINGECKO_BASE: &str = "https://api.coingecko.com/api/v3/simple/price";
/// Per-request timeout for the oracle fetch (a single small JSON GET).
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a quote could not be produced. Mapped to a clear HTTP error by the
/// create-invoice handler so an unpriceable invoice is never silently created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateError {
    /// The requested currency is not in `GP_RATE_CURRENCIES` (a 400: the caller
    /// must send a supported currency). Checked before any network call.
    UnsupportedCurrency(String),
    /// The fiat amount could not be parsed as a non-negative decimal (a 400).
    BadAmount(String),
    /// No fresh rate and no usable stale fallback (source unreachable or the
    /// response had no price for the currency): a 502, fail fast.
    SourceUnavailable(String),
    /// Misconfiguration (an unknown source reached the oracle): a 500.
    Config(String),
}

impl std::fmt::Display for RateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateError::UnsupportedCurrency(c) => {
                write!(f, "currency `{c}` is not enabled (see GP_RATE_CURRENCIES)")
            }
            RateError::BadAmount(a) => write!(f, "fiat amount `{a}` is not a valid decimal"),
            RateError::SourceUnavailable(m) => write!(f, "price oracle unavailable: {m}"),
            RateError::Config(m) => write!(f, "rate oracle misconfigured: {m}"),
        }
    }
}

impl std::error::Error for RateError {}

/// A locked quote: the priced Grin amount plus the rate and source it was
/// derived from, echoed onto the invoice for the receipt/audit trail.
#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    /// The locked Grin amount in nanogrin (the invoice `expected_amount`).
    pub nanogrin: u64,
    /// The currency the quote is in (lowercased ISO code).
    pub currency: String,
    /// The rate used: fiat units per one GRIN (the price of 1 GRIN).
    pub fiat_per_grin: f64,
    /// The source the rate came from (e.g. `coingecko`).
    pub source: &'static str,
    /// True when served from a stale cache entry (a fallback, not a fresh fetch).
    pub stale: bool,
}

/// Parse a fiat amount decimal string into an `f64`, rejecting anything that is
/// not a finite, non-negative number.
pub fn parse_fiat_amount(amount: &str) -> Result<f64, RateError> {
    let trimmed = amount.trim();
    let value: f64 = trimmed
        .parse()
        .map_err(|_| RateError::BadAmount(amount.to_string()))?;
    if !value.is_finite() || value < 0.0 {
        return Err(RateError::BadAmount(amount.to_string()));
    }
    Ok(value)
}

/// Convert a fiat amount to nanogrin at a given rate (fiat units per one GRIN),
/// rounding to the nearest nanogrin (1 GRIN = 1e9 nanogrin).
///
/// `grin = fiat / fiat_per_grin`, then `nanogrin = round(grin * 1e9)`. Pure and
/// deterministic for a fixed `(fiat, rate)`, so the rounding is unit-tested.
pub fn fiat_to_nanogrin(fiat_amount: f64, fiat_per_grin: f64) -> Result<u64, RateError> {
    if !fiat_per_grin.is_finite() || fiat_per_grin <= 0.0 {
        return Err(RateError::SourceUnavailable(format!(
            "non-positive rate {fiat_per_grin}"
        )));
    }
    if !fiat_amount.is_finite() || fiat_amount < 0.0 {
        return Err(RateError::BadAmount(fiat_amount.to_string()));
    }
    let nano = (fiat_amount / fiat_per_grin * 1e9).round();
    if !nano.is_finite() || nano < 0.0 || nano > u64::MAX as f64 {
        return Err(RateError::BadAmount(format!(
            "amount {fiat_amount} at rate {fiat_per_grin} overflows nanogrin"
        )));
    }
    Ok(nano as u64)
}

/// Format a rate for storage/display: fiat-per-GRIN to a fixed precision,
/// trailing zeros trimmed. Used for the invoice `quote_rate` column.
pub fn format_rate(fiat_per_grin: f64) -> String {
    let s = format!("{fiat_per_grin:.10}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Parse a CoinGecko `/simple/price` response, returning the fiat-per-GRIN
/// price for `currency` (case-insensitive). The response shape is
/// `{"grin":{"usd":0.021,"eur":0.018}}`.
pub fn parse_coingecko(json: &str, currency: &str) -> Result<f64, RateError> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| RateError::SourceUnavailable(format!("bad JSON from coingecko: {e}")))?;
    let cur = currency.to_lowercase();
    value
        .get(COINGECKO_GRIN_ID)
        .and_then(|m| m.get(&cur))
        .and_then(|v| v.as_f64())
        .filter(|p| p.is_finite() && *p > 0.0)
        .ok_or_else(|| {
            RateError::SourceUnavailable(format!("coingecko returned no `{cur}` price for grin"))
        })
}

/// Whether a quote locked at `quoted_at_unix` for `ttl_secs` is still valid at
/// `now_unix`. The pure predicate behind the invoice `expiry` column: a quote
/// is honoured only inside its lock window; past it, the amount-match fails and
/// the checkout re-quotes.
pub fn quote_valid(quoted_at_unix: i64, ttl_secs: i64, now_unix: i64) -> bool {
    now_unix >= quoted_at_unix && now_unix < quoted_at_unix.saturating_add(ttl_secs)
}

/// One cached rate for a currency: the price and when it was fetched.
#[derive(Debug, Clone, Copy)]
struct CachedRate {
    fiat_per_grin: f64,
    fetched: Instant,
}

/// The configurable price oracle. Holds the supported currency set, the cache,
/// and the lock/TTL knobs; the live fetch reuses one reqwest client.
pub struct Oracle {
    source: RateSource,
    /// Supported fiat currencies (lowercased ISO codes).
    currencies: Vec<String>,
    cache_ttl: Duration,
    stale_max: Duration,
    /// The invoice quote-lock window in seconds (`GP_QUOTE_TTL`).
    quote_ttl_secs: i64,
    cache: Mutex<HashMap<String, CachedRate>>,
    /// A shared HTTP client (DIRECT, never Nym). `None` for a fixed/test oracle
    /// whose cache is pre-seeded so it never fetches.
    client: Option<reqwest::Client>,
}

impl Oracle {
    /// Build the oracle from the resolved config: the live CoinGecko client with
    /// the configured currency set and lock/TTL windows.
    pub fn from_config(cfg: &Config) -> Oracle {
        let client = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            // CoinGecko 403s the default reqwest agent from datacenter IPs; a
            // browser-style UA is accepted (verified from the us-east host).
            .user_agent("Mozilla/5.0 (compatible; GoblinPay/0.1)")
            .build()
            .ok();
        Oracle {
            source: cfg.rate_source,
            currencies: cfg.rate_currencies.clone(),
            cache_ttl: Duration::from_secs(cfg.rate_cache_ttl.max(0) as u64),
            stale_max: Duration::from_secs(cfg.rate_stale_max.max(0) as u64),
            quote_ttl_secs: cfg.quote_ttl,
            cache: Mutex::new(HashMap::new()),
            client,
        }
    }

    /// A network-free oracle with a fixed rate for every supported currency, for
    /// tests and air-gapped/offline operation: the cache is pre-seeded fresh so
    /// `quote` never fetches. `quote_ttl_secs` sets the lock window.
    pub fn fixed(currencies: &[&str], fiat_per_grin: f64, quote_ttl_secs: i64) -> Oracle {
        let mut cache = HashMap::new();
        let now = Instant::now();
        for c in currencies {
            cache.insert(
                c.to_lowercase(),
                CachedRate {
                    fiat_per_grin,
                    fetched: now,
                },
            );
        }
        Oracle {
            source: RateSource::CoinGecko,
            currencies: currencies.iter().map(|c| c.to_lowercase()).collect(),
            // A very long freshness so the seeded entry is always used.
            cache_ttl: Duration::from_secs(u32::MAX as u64),
            stale_max: Duration::ZERO,
            quote_ttl_secs,
            cache: Mutex::new(cache),
            client: None,
        }
    }

    /// The quote-lock window in seconds (the fiat invoice's expiry).
    pub fn quote_ttl_secs(&self) -> i64 {
        self.quote_ttl_secs
    }

    /// Whether a currency is enabled (case-insensitive).
    pub fn supports(&self, currency: &str) -> bool {
        let cur = currency.to_lowercase();
        self.currencies.contains(&cur)
    }

    /// Quote a `{fiat amount, currency}` into a locked Grin amount.
    ///
    /// Fails fast when the currency is not enabled (no network call), the amount
    /// is malformed, or no fresh/stale rate can be sourced. On success the
    /// returned [`Quote`] carries the nanogrin the invoice `expected_amount` is
    /// set to plus the rate/source for the audit trail.
    pub async fn quote(&self, fiat_amount: &str, currency: &str) -> Result<Quote, RateError> {
        if !self.supports(currency) {
            return Err(RateError::UnsupportedCurrency(currency.to_string()));
        }
        let amount = parse_fiat_amount(fiat_amount)?;
        let cur = currency.to_lowercase();

        let (fiat_per_grin, stale) = self.rate_for(&cur).await?;
        let nanogrin = fiat_to_nanogrin(amount, fiat_per_grin)?;
        Ok(Quote {
            nanogrin,
            currency: cur,
            fiat_per_grin,
            source: self.source.as_str(),
            stale,
        })
    }

    /// Resolve a currency's fiat-per-GRIN rate: a fresh cache hit, else a live
    /// fetch, else a stale-cache fallback within `GP_RATE_STALE_MAX`. Returns
    /// `(rate, stale)`.
    async fn rate_for(&self, cur: &str) -> Result<(f64, bool), RateError> {
        let now = Instant::now();
        // Fresh cache hit.
        if let Some(entry) = self.cache_get(cur) {
            if is_fresh(now.saturating_duration_since(entry.fetched), self.cache_ttl) {
                return Ok((entry.fiat_per_grin, false));
            }
        }
        // Live fetch (DIRECT).
        match self.fetch(cur).await {
            Ok(rate) => {
                self.cache_put(cur, rate, now);
                Ok((rate, false))
            }
            Err(fetch_err) => {
                // Stale fallback within the bounded window, if any.
                if let Some(entry) = self.cache_get(cur) {
                    if !self.stale_max.is_zero()
                        && is_fresh(now.saturating_duration_since(entry.fetched), self.stale_max)
                    {
                        log::warn!(
                            "rates: {} fetch failed, serving stale {cur} rate: {fetch_err}",
                            self.source.as_str()
                        );
                        return Ok((entry.fiat_per_grin, true));
                    }
                }
                Err(fetch_err)
            }
        }
    }

    /// The live, DIRECT HTTP fetch for one currency's GRIN price. Never called
    /// by the fixed/test oracle (its cache is always fresh).
    async fn fetch(&self, cur: &str) -> Result<f64, RateError> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| RateError::SourceUnavailable("HTTP client unavailable".into()))?;
        match self.source {
            RateSource::CoinGecko => {
                let url = format!("{COINGECKO_BASE}?ids={COINGECKO_GRIN_ID}&vs_currencies={cur}");
                let resp = client.get(&url).send().await.map_err(|e| {
                    RateError::SourceUnavailable(format!("coingecko request failed: {e}"))
                })?;
                if !resp.status().is_success() {
                    return Err(RateError::SourceUnavailable(format!(
                        "coingecko HTTP {}",
                        resp.status().as_u16()
                    )));
                }
                let body = resp.text().await.map_err(|e| {
                    RateError::SourceUnavailable(format!("coingecko body read failed: {e}"))
                })?;
                parse_coingecko(&body, cur)
            }
        }
    }

    fn cache_get(&self, cur: &str) -> Option<CachedRate> {
        self.cache.lock().ok().and_then(|m| m.get(cur).copied())
    }

    fn cache_put(&self, cur: &str, fiat_per_grin: f64, fetched: Instant) {
        if let Ok(mut m) = self.cache.lock() {
            m.insert(
                cur.to_string(),
                CachedRate {
                    fiat_per_grin,
                    fetched,
                },
            );
        }
    }
}

/// Whether an entry aged `age` is still fresh under `ttl`. A zero TTL means
/// "always refetch" (never fresh).
fn is_fresh(age: Duration, ttl: Duration) -> bool {
    !ttl.is_zero() && age <= ttl
}

#[cfg(test)]
mod tests {
    use super::*;

    // A REAL CoinGecko `/simple/price?ids=grin&vs_currencies=usd,eur,gbp`
    // response, captured read-only 2026-07-01. GRIN is listed under id `grin`.
    // The parser is asserted against this exact wire shape so a production
    // response and this test agree; no test hits the live oracle.
    const COINGECKO_FIXTURE: &str =
        r#"{"grin":{"usd":0.02097549,"eur":0.01841713,"gbp":0.01577731}}"#;

    #[test]
    fn parses_recorded_coingecko_fixture() {
        assert_eq!(
            parse_coingecko(COINGECKO_FIXTURE, "usd").unwrap(),
            0.02097549
        );
        assert_eq!(
            parse_coingecko(COINGECKO_FIXTURE, "eur").unwrap(),
            0.01841713
        );
        assert_eq!(
            parse_coingecko(COINGECKO_FIXTURE, "gbp").unwrap(),
            0.01577731
        );
        // Case-insensitive currency selection.
        assert_eq!(
            parse_coingecko(COINGECKO_FIXTURE, "USD").unwrap(),
            0.02097549
        );
    }

    #[test]
    fn coingecko_missing_currency_is_source_error() {
        // A currency not present in the response is a source error, not a panic.
        assert!(matches!(
            parse_coingecko(COINGECKO_FIXTURE, "jpy"),
            Err(RateError::SourceUnavailable(_))
        ));
        assert!(matches!(
            parse_coingecko("not json", "usd"),
            Err(RateError::SourceUnavailable(_))
        ));
    }

    #[test]
    fn conversion_rounds_to_nearest_nanogrin() {
        // Clean case: 10.00 USD at 0.02 USD/GRIN = 500 GRIN exactly.
        assert_eq!(fiat_to_nanogrin(10.0, 0.02).unwrap(), 500_000_000_000);
        // Rounding case: 1.00 at 0.03 = 33.3333... GRIN -> 33_333_333_333 nano.
        assert_eq!(fiat_to_nanogrin(1.0, 0.03).unwrap(), 33_333_333_333);
        // A tiny amount still rounds to the nearest nanogrin.
        assert_eq!(fiat_to_nanogrin(0.00000000002, 0.02).unwrap(), 1);
        // Zero fiat is a zero-nanogrin quote, not an error.
        assert_eq!(fiat_to_nanogrin(0.0, 0.02).unwrap(), 0);
    }

    #[test]
    fn conversion_rejects_bad_inputs() {
        assert!(matches!(
            fiat_to_nanogrin(10.0, 0.0),
            Err(RateError::SourceUnavailable(_))
        ));
        assert!(matches!(
            fiat_to_nanogrin(10.0, -1.0),
            Err(RateError::SourceUnavailable(_))
        ));
        assert!(matches!(
            fiat_to_nanogrin(-1.0, 0.02),
            Err(RateError::BadAmount(_))
        ));
        assert!(matches!(
            fiat_to_nanogrin(f64::NAN, 0.02),
            Err(RateError::BadAmount(_))
        ));
    }

    #[test]
    fn parses_fiat_amount_strings() {
        assert_eq!(parse_fiat_amount("19.99").unwrap(), 19.99);
        assert_eq!(parse_fiat_amount("  5 ").unwrap(), 5.0);
        assert_eq!(parse_fiat_amount("0").unwrap(), 0.0);
        assert!(matches!(
            parse_fiat_amount("abc"),
            Err(RateError::BadAmount(_))
        ));
        assert!(matches!(
            parse_fiat_amount("-3.00"),
            Err(RateError::BadAmount(_))
        ));
    }

    #[test]
    fn rate_formatting_trims_zeros() {
        assert_eq!(format_rate(0.02097549), "0.02097549");
        assert_eq!(format_rate(0.02), "0.02");
        assert_eq!(format_rate(1.0), "1");
    }

    #[test]
    fn quote_lock_expires_after_ttl() {
        // Locked at t=1000 for 900s: valid inside the window, rejected past it.
        assert!(quote_valid(1000, 900, 1000)); // at lock time
        assert!(quote_valid(1000, 900, 1899)); // last valid second
        assert!(!quote_valid(1000, 900, 1900)); // TTL elapsed -> re-quote
        assert!(!quote_valid(1000, 900, 2500)); // long past
        assert!(!quote_valid(1000, 900, 999)); // before the lock (clock skew)
    }

    #[test]
    fn cache_freshness_respects_ttl() {
        assert!(is_fresh(Duration::from_secs(30), Duration::from_secs(60)));
        assert!(is_fresh(Duration::from_secs(60), Duration::from_secs(60)));
        assert!(!is_fresh(Duration::from_secs(61), Duration::from_secs(60)));
        // A zero TTL is never fresh (always refetch).
        assert!(!is_fresh(Duration::ZERO, Duration::ZERO));
    }

    #[tokio::test]
    async fn fixed_oracle_quotes_without_network() {
        // 0.02 USD per GRIN, so 10.00 USD = 500 GRIN.
        let oracle = Oracle::fixed(&["usd", "eur"], 0.02, 900);
        let q = oracle.quote("10.00", "usd").await.unwrap();
        assert_eq!(q.nanogrin, 500_000_000_000);
        assert_eq!(q.currency, "usd");
        assert_eq!(q.fiat_per_grin, 0.02);
        assert!(!q.stale);
        assert_eq!(oracle.quote_ttl_secs(), 900);
        // Case-insensitive on the way in, lowercased out.
        let q2 = oracle.quote("10.00", "USD").await.unwrap();
        assert_eq!(q2.nanogrin, 500_000_000_000);
    }

    #[tokio::test]
    async fn fixed_oracle_rejects_unsupported_currency_before_any_fetch() {
        let oracle = Oracle::fixed(&["usd"], 0.02, 900);
        assert_eq!(
            oracle.quote("10.00", "jpy").await,
            Err(RateError::UnsupportedCurrency("jpy".into()))
        );
        assert!(!oracle.supports("jpy"));
        assert!(oracle.supports("USD"));
    }

    #[tokio::test]
    async fn fixed_oracle_rejects_bad_amount() {
        let oracle = Oracle::fixed(&["usd"], 0.02, 900);
        assert!(matches!(
            oracle.quote("not-a-number", "usd").await,
            Err(RateError::BadAmount(_))
        ));
    }
}
