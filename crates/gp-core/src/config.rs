//! Runtime configuration. Everything that identifies a particular operator's
//! GoblinPay instance is read from the environment at startup (env-first,
//! same shape as goblin-nip05d), so a second operator can run their own
//! instance without touching the source.
//!
//! Secrets (`GP_MNEMONIC`, `GP_NSEC`) can come from the environment directly
//! or from a mounted file via the `*_FILE` variants, never from the repo.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Default listen address (loopback; put a proxy or `GP_TLS=rustls` in front
/// for public exposure).
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";
/// Default SQLite database file, relative to the working directory.
pub const DEFAULT_DB_PATH: &str = "./goblinpay.db";
/// Default data directory (wallet files, encrypted seed at rest).
pub const DEFAULT_DATA_DIR: &str = "./gp-data";
/// Default external Grin node (read-only: confirmations and balance).
///
/// `main.gri.mw`, not `api.grin.money`: the milestone-2/dev round found
/// `api.grin.money`'s bulk UTXO scan (`get_unspent_outputs`) returns errors,
/// while `main.gri.mw` serves the foreign API (`get_tip`, `get_kernel`)
/// cleanly. GoblinPay only ever reads (kernel confirmation + a cached balance),
/// and this traffic goes DIRECT over normal HTTP, never through the Nym tunnel
/// (owner ruling: node reads are a server concern, like Goblin's own
/// wallet->node reads which never ride the mixnet; the mixnet carries only the
/// Nostr gift-wrap layer in gp-nostr).
pub const DEFAULT_NODE_URL: &str = "https://main.gri.mw";

/// Default URL of the bundled relay in `bundled` relay mode: the co-located
/// relay GoblinPay ships in `deploy/docker-compose.yml` (a vendored
/// nostr-rs-relay), so a merchant needs no third-party relay. Override with
/// `GP_BUNDLED_RELAY_URL`. In a public deployment set this to the relay's
/// publicly reachable `wss://<domain>` URL, because the same value is both
/// dialed by the server AND advertised to payers in the checkout `nprofile`.
pub const DEFAULT_BUNDLED_RELAY: &str = "ws://127.0.0.1:7777";

/// TLS mode for the HTTP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tls {
    /// Plain HTTP (default). Run behind a reverse proxy, or local only.
    Off,
    /// In-process rustls with a PEM certificate chain and private key.
    Rustls { cert: String, key: String },
}

/// Grin network to operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// Grin mainnet (default).
    Mainnet,
    /// Grin testnet.
    Testnet,
}

/// Where the Nostr relay lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelayMode {
    /// GoblinPay talks to its own co-located relay (default): the bundled
    /// nostr-rs-relay from `deploy/docker-compose.yml`, reached at
    /// `GP_BUNDLED_RELAY_URL`. That relay is what the checkout `nprofile`
    /// advertises, so a merchant needs no third-party relay. Any `GP_RELAYS`
    /// are added alongside it for redundancy.
    Bundled,
    /// Only external relays from `GP_RELAYS` are used.
    External,
}

/// Where the conversion oracle fetches the GRIN price (module `rates`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateSource {
    /// CoinGecko simple-price API (default; GRIN is listed under id `grin`).
    CoinGecko,
}

impl RateSource {
    /// Stable string id, used on the quote/receipt and in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            RateSource::CoinGecko => "coingecko",
        }
    }
}

/// Global default payment-matching mode (per-invoice override comes later).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// Match by the payer's memo/reference tag.
    Memo,
    /// Match by a per-invoice derived Nostr identity.
    Derived,
    /// Match by expected amount within tolerance and expiry.
    Amount,
}

/// A sensitive value. Debug and serde output never reveal it, so a config
/// dump or a startup log line cannot leak a seed or key. The backing buffer is
/// zeroized on drop (defense in depth against the value lingering in freed
/// heap; the seed is also handed to grin-wallet as a `ZeroingString`).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(value)
    }

    /// Access the underlying value. Call sites should be deliberate.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Resolved, validated runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address the HTTP server binds (`GP_BIND`).
    pub bind: String,
    /// TLS mode (`GP_TLS`: `off` or `rustls`, plus `GP_TLS_CERT`/`GP_TLS_KEY`).
    pub tls: Tls,
    /// SQLite database path (`GP_DB_PATH`); created on first start.
    pub db_path: String,
    /// Data directory (`GP_DATA_DIR`); holds the wallet files, including the
    /// encrypted seed at rest.
    pub data_dir: String,
    /// External Grin node URL (`GP_NODE_URL`), read-only.
    pub node_url: String,
    /// Grin network (`GP_CHAIN`: `mainnet` or `testnet`).
    pub chain: Chain,
    /// Relay mode (`GP_RELAY_MODE`: `bundled` or `external`).
    pub relay_mode: RelayMode,
    /// External relays (`GP_RELAYS`, comma separated).
    pub relays: Vec<String>,
    /// URL of the bundled relay used in `bundled` relay mode
    /// (`GP_BUNDLED_RELAY_URL`, default `ws://127.0.0.1:7777`). Both dialed by
    /// the ingest service and advertised to payers in the checkout `nprofile`.
    pub bundled_relay_url: String,
    /// Run the Nostr ingest service (`GP_INGEST`: `on` or `off`, default on).
    /// When on, the wallet and identity secrets are required at boot.
    pub ingest: bool,
    /// Show the Nostr (Goblin Wallet, `nprofile`) method on the hosted checkout
    /// page. Part of `GP_CHECKOUT_METHODS` (comma list of `nostr`/`slatepack`;
    /// unset = both). This gates only the hosted PAGE display, not the connector
    /// API or the ingest service.
    pub checkout_nostr: bool,
    /// Show the Slatepack (`grin1`) method on the hosted checkout page. Part of
    /// `GP_CHECKOUT_METHODS`. Still requires a loaded wallet to actually appear:
    /// an enabled method that cannot work is simply hidden.
    pub checkout_slatepack: bool,
    /// Global default matching mode (`GP_MATCH_MODE`).
    pub match_mode: MatchMode,
    /// Grin seed mnemonic (`GP_MNEMONIC` or `GP_MNEMONIC_FILE`). Money secret.
    #[serde(skip)]
    pub mnemonic: Option<Secret>,
    /// Password encrypting the wallet seed file at rest (`GP_WALLET_PASSWORD`
    /// or `GP_WALLET_PASSWORD_FILE`). Required to open the wallet. Also
    /// encrypts the auto-generated Nostr identity file at rest.
    #[serde(skip)]
    pub wallet_password: Option<Secret>,
    /// Nostr identity key (`GP_NSEC` or `GP_NSEC_FILE`). Payment identity
    /// secret, deliberately independent of the Grin seed.
    #[serde(skip)]
    pub nsec: Option<Secret>,
    /// NIP-49 encrypted Nostr identity key (`GP_NCRYPTSEC` or
    /// `GP_NCRYPTSEC_FILE`), unlocked with the wallet password. Mutually
    /// exclusive with `GP_NSEC`.
    #[serde(skip)]
    pub ncryptsec: Option<Secret>,
    /// Public base URL of this instance (`GP_PUBLIC_URL`), used to build the
    /// hosted `/pay/<token>` links. Defaults to `http://<bind>`.
    pub public_url: String,
    /// Bearer token for the connector/create-invoice API (`GP_API_TOKEN`).
    /// When unset, the write API is closed (503) rather than open.
    #[serde(skip)]
    pub api_token: Option<Secret>,
    /// Bearer token for the admin dashboard/API (`GP_ADMIN_TOKEN`).
    #[serde(skip)]
    pub admin_token: Option<Secret>,
    /// Webhook endpoint (`GP_WEBHOOK_URL`) payment events are delivered to.
    pub webhook_url: Option<String>,
    /// HMAC secret for signing webhooks (`GP_WEBHOOK_SECRET`).
    #[serde(skip)]
    pub webhook_secret: Option<Secret>,
    /// Center-logo source for checkout QR codes (`GP_QR_LOGO`): unset (or
    /// `off`/`none`) = a plain QR, the default; `builtin`/`goblin` = the
    /// inlined Goblin mark (self-contained, opt-in); else a URL used as an
    /// external image.
    pub qr_logo: Option<String>,
    /// Merchant npub for confirmed-payment DMs (`GP_MERCHANT_NPUB`).
    pub merchant_npub: Option<String>,
    /// Send a NIP-17 DM to the merchant on a received payment
    /// (`GP_NOTIFY_MERCHANT_DM`, default off).
    pub notify_merchant_dm: bool,
    /// Send a NIP-17 receipt DM to the payer (`GP_NOTIFY_PAYER_RECEIPT`,
    /// default off).
    pub notify_payer_receipt: bool,
    /// Default per-user endpub rotation interval in seconds
    /// (`GP_ENDPUB_ROTATE_INTERVAL`, 0 = off).
    pub endpub_rotate_interval: i64,
    /// How many past epochs to keep watching after a rotation
    /// (`GP_ENDPUB_OVERLAP_EPOCHS`, default 1).
    pub endpub_overlap_epochs: i64,
    /// Conversion-rate source (`GP_RATE_SOURCE`, default `coingecko`).
    pub rate_source: RateSource,
    /// Supported fiat currencies (`GP_RATE_CURRENCIES`, comma separated,
    /// lowercased ISO codes; default `usd`). A fiat invoice in any other
    /// currency is rejected up front.
    pub rate_currencies: Vec<String>,
    /// Seconds a fetched rate is reused before refetching
    /// (`GP_RATE_CACHE_TTL`, default 60).
    pub rate_cache_ttl: i64,
    /// Seconds a created fiat invoice locks its Grin quote (`GP_QUOTE_TTL`,
    /// default 900); this becomes the invoice expiry window.
    pub quote_ttl: i64,
    /// Bounded stale-rate fallback in seconds (`GP_RATE_STALE_MAX`, default 0
    /// = off): if a live fetch fails, a cached rate this recent is served
    /// rather than failing the checkout.
    pub rate_stale_max: i64,
    /// On-chain confirmation depth at which an invoice is final
    /// (`GP_CONFIRMATIONS`, default 10). Once the paying kernel reaches this
    /// many confirmations the invoice advances `paid` -> `confirmed`. Must be
    /// >= 1.
    pub confirmations_required: i64,
    /// Arm the native grin1 payment rail (`GP_GRIN1_RAIL`, packaged default
    /// OFF, owner ruling). Off (or unset), GoblinPay behaves exactly as before
    /// the rail existed: no Tor onion service or arti bootstrap, no loopback
    /// Foreign API listener, no invoice slates issued, and the pay page shows
    /// ONLY the "Pay with Goblin" (Nostr) method. On (and with a wallet
    /// loaded), an exact-amount invoice also issues a Grin invoice slate, the
    /// onion service + Foreign endpoint start, and the pay page gains the
    /// two-rail switcher ("Pay with Goblin" stays the default tab).
    pub grin1_rail: bool,
    /// Loopback port the Grin Foreign API v2 (`/v2/foreign`) binds, which the
    /// onion service proxies to (`GP_GRIN1_FOREIGN_PORT`, default 3416). Only
    /// used when `grin1_rail` is on.
    pub grin1_foreign_port: u16,
}

/// Default supported fiat currency when `GP_RATE_CURRENCIES` is unset.
pub const DEFAULT_RATE_CURRENCY: &str = "usd";
/// Default rate cache freshness (seconds).
pub const DEFAULT_RATE_CACHE_TTL: i64 = 60;
/// Default quote lock window (seconds).
pub const DEFAULT_QUOTE_TTL: i64 = 900;
/// Default on-chain confirmation depth at which a payment counts as final
/// (house standard). An invoice advances `paid` -> `confirmed` once its
/// kernel reaches this many confirmations.
pub const DEFAULT_CONFIRMATIONS: i64 = 10;
/// Default loopback port for the Grin Foreign API v2 the onion service proxies
/// to. 3416 sits just past the stock wallet listener (3415) / owner (3420).
pub const DEFAULT_GRIN1_FOREIGN_PORT: u16 = 3416;

/// Sentinel `qr_logo` value selecting the inlined Goblin mark
/// (`GP_QR_LOGO=builtin`, opt-in; the default is a plain QR). Kept out of the
/// `Href` space so it is never treated as a URL.
pub const QR_LOGO_BUILTIN: &str = "builtin";

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: DEFAULT_BIND.into(),
            tls: Tls::Off,
            db_path: DEFAULT_DB_PATH.into(),
            data_dir: DEFAULT_DATA_DIR.into(),
            node_url: DEFAULT_NODE_URL.into(),
            chain: Chain::Mainnet,
            relay_mode: RelayMode::Bundled,
            relays: Vec::new(),
            bundled_relay_url: DEFAULT_BUNDLED_RELAY.into(),
            ingest: true,
            checkout_nostr: true,
            checkout_slatepack: true,
            match_mode: MatchMode::Memo,
            mnemonic: None,
            wallet_password: None,
            nsec: None,
            ncryptsec: None,
            public_url: format!("http://{DEFAULT_BIND}"),
            api_token: None,
            admin_token: None,
            webhook_url: None,
            webhook_secret: None,
            qr_logo: None,
            merchant_npub: None,
            notify_merchant_dm: false,
            notify_payer_receipt: false,
            endpub_rotate_interval: 0,
            endpub_overlap_epochs: 1,
            rate_source: RateSource::CoinGecko,
            rate_currencies: vec![DEFAULT_RATE_CURRENCY.to_string()],
            rate_cache_ttl: DEFAULT_RATE_CACHE_TTL,
            quote_ttl: DEFAULT_QUOTE_TTL,
            rate_stale_max: 0,
            confirmations_required: DEFAULT_CONFIRMATIONS,
            grin1_rail: false,
            grin1_foreign_port: DEFAULT_GRIN1_FOREIGN_PORT,
        }
    }
}

impl Config {
    /// Load from the process environment, applying defaults, then validate.
    /// Returns an error string on misconfiguration (caller should fail fast).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// Load from an arbitrary key lookup (the environment in production, a
    /// map in tests, so tests never mutate global process state).
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let defaults = Config::default();

        let bind = get("GP_BIND").unwrap_or(defaults.bind);

        let tls = match get("GP_TLS").as_deref().unwrap_or("off") {
            "off" => Tls::Off,
            "rustls" => {
                let cert = get("GP_TLS_CERT")
                    .ok_or("GP_TLS=rustls requires GP_TLS_CERT (PEM certificate chain path)")?;
                let key = get("GP_TLS_KEY")
                    .ok_or("GP_TLS=rustls requires GP_TLS_KEY (PEM private key path)")?;
                Tls::Rustls { cert, key }
            }
            other => return Err(format!("GP_TLS must be `off` or `rustls` (got `{other}`)")),
        };

        let db_path = get("GP_DB_PATH").unwrap_or(defaults.db_path);
        let data_dir = get("GP_DATA_DIR").unwrap_or(defaults.data_dir);
        let node_url = get("GP_NODE_URL").unwrap_or(defaults.node_url);

        let chain = match get("GP_CHAIN").as_deref().unwrap_or("mainnet") {
            "mainnet" => Chain::Mainnet,
            "testnet" => Chain::Testnet,
            other => {
                return Err(format!(
                    "GP_CHAIN must be `mainnet` or `testnet` (got `{other}`)"
                ))
            }
        };

        let relay_mode = match get("GP_RELAY_MODE").as_deref().unwrap_or("bundled") {
            "bundled" => RelayMode::Bundled,
            "external" => RelayMode::External,
            other => {
                return Err(format!(
                    "GP_RELAY_MODE must be `bundled` or `external` (got `{other}`)"
                ))
            }
        };

        let relays = get("GP_RELAYS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let bundled_relay_url = get("GP_BUNDLED_RELAY_URL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or(defaults.bundled_relay_url);

        let ingest = match get("GP_INGEST").as_deref().unwrap_or("on") {
            "on" => true,
            "off" => false,
            other => return Err(format!("GP_INGEST must be `on` or `off` (got `{other}`)")),
        };

        let (checkout_nostr, checkout_slatepack) =
            parse_checkout_methods(get("GP_CHECKOUT_METHODS"));

        let match_mode = match get("GP_MATCH_MODE").as_deref().unwrap_or("memo") {
            "memo" => MatchMode::Memo,
            "derived" => MatchMode::Derived,
            "amount" => MatchMode::Amount,
            other => {
                return Err(format!(
                    "GP_MATCH_MODE must be `memo`, `derived`, or `amount` (got `{other}`)"
                ))
            }
        };

        let mnemonic = secret(get, "GP_MNEMONIC")?;
        let wallet_password = secret(get, "GP_WALLET_PASSWORD")?;
        let nsec = secret(get, "GP_NSEC")?;
        let ncryptsec = secret(get, "GP_NCRYPTSEC")?;

        let public_url = get("GP_PUBLIC_URL")
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| format!("http://{bind}"));
        let api_token = secret(get, "GP_API_TOKEN")?;
        let admin_token = secret(get, "GP_ADMIN_TOKEN")?;
        let webhook_url = get("GP_WEBHOOK_URL").filter(|s| !s.trim().is_empty());
        let webhook_secret = secret(get, "GP_WEBHOOK_SECRET")?;
        let qr_logo = match get("GP_QR_LOGO").as_deref() {
            None | Some("off") | Some("none") | Some("") => None,
            Some("builtin") | Some("goblin") => Some(QR_LOGO_BUILTIN.to_string()),
            Some(other) => Some(other.to_string()),
        };
        let merchant_npub = get("GP_MERCHANT_NPUB").filter(|s| !s.trim().is_empty());
        let notify_merchant_dm = parse_bool(get, "GP_NOTIFY_MERCHANT_DM", false)?;
        let notify_payer_receipt = parse_bool(get, "GP_NOTIFY_PAYER_RECEIPT", false)?;
        let endpub_rotate_interval = parse_i64(get, "GP_ENDPUB_ROTATE_INTERVAL", 0)?;
        let endpub_overlap_epochs = parse_i64(get, "GP_ENDPUB_OVERLAP_EPOCHS", 1)?;

        let rate_source = match get("GP_RATE_SOURCE").as_deref().unwrap_or("coingecko") {
            "coingecko" => RateSource::CoinGecko,
            other => {
                return Err(format!(
                    "GP_RATE_SOURCE must be `coingecko` (got `{other}`)"
                ))
            }
        };
        let rate_currencies = match get("GP_RATE_CURRENCIES") {
            None => vec![DEFAULT_RATE_CURRENCY.to_string()],
            Some(raw) => {
                let list = raw
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();
                if list.is_empty() {
                    return Err("GP_RATE_CURRENCIES must list at least one currency".into());
                }
                list
            }
        };
        let rate_cache_ttl = parse_i64(get, "GP_RATE_CACHE_TTL", DEFAULT_RATE_CACHE_TTL)?;
        let quote_ttl = parse_i64(get, "GP_QUOTE_TTL", DEFAULT_QUOTE_TTL)?;
        let rate_stale_max = parse_i64(get, "GP_RATE_STALE_MAX", 0)?;
        let confirmations_required = parse_i64(get, "GP_CONFIRMATIONS", DEFAULT_CONFIRMATIONS)?;
        // Packaged default OFF (owner ruling): the grin1/Tor rail is operator
        // opt-in; unset behaves exactly like the pre-rail server.
        let grin1_rail = parse_bool(get, "GP_GRIN1_RAIL", false)?;
        let grin1_foreign_port = match get("GP_GRIN1_FOREIGN_PORT") {
            None => DEFAULT_GRIN1_FOREIGN_PORT,
            Some(v) => v
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("GP_GRIN1_FOREIGN_PORT must be a port 1-65535 (got `{v}`)"))?,
        };

        let cfg = Config {
            bind,
            tls,
            db_path,
            data_dir,
            node_url,
            chain,
            relay_mode,
            relays,
            bundled_relay_url,
            ingest,
            checkout_nostr,
            checkout_slatepack,
            match_mode,
            mnemonic,
            wallet_password,
            nsec,
            ncryptsec,
            public_url,
            api_token,
            admin_token,
            webhook_url,
            webhook_secret,
            qr_logo,
            merchant_npub,
            notify_merchant_dm,
            notify_payer_receipt,
            endpub_rotate_interval,
            endpub_overlap_epochs,
            rate_source,
            rate_currencies,
            rate_cache_ttl,
            quote_ttl,
            rate_stale_max,
            confirmations_required,
            grin1_rail,
            grin1_foreign_port,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// The QR center logo to render: the inlined Goblin mark by default, an
    /// external image when the operator sets a custom URL, or none.
    pub fn qr_logo(&self) -> crate::qr::Logo<'_> {
        match self.qr_logo.as_deref() {
            None => crate::qr::Logo::None,
            Some(QR_LOGO_BUILTIN) => crate::qr::Logo::Builtin,
            Some(href) => crate::qr::Logo::Href(href),
        }
    }

    /// The enabled checkout methods as a stable comma list, for the startup log.
    fn checkout_methods_str(&self) -> String {
        let mut methods = Vec::new();
        if self.checkout_nostr {
            methods.push("nostr");
        }
        if self.checkout_slatepack {
            methods.push("slatepack");
        }
        methods.join(",")
    }

    /// Fail-fast consistency checks.
    fn validate(&self) -> Result<(), String> {
        if self.bind.is_empty() {
            return Err("GP_BIND must not be empty".into());
        }
        if self.db_path.is_empty() {
            return Err("GP_DB_PATH must not be empty".into());
        }
        if self.data_dir.is_empty() {
            return Err("GP_DATA_DIR must not be empty".into());
        }
        if !self.node_url.starts_with("http://") && !self.node_url.starts_with("https://") {
            return Err(format!(
                "GP_NODE_URL must start with http:// or https:// (got `{}`)",
                self.node_url
            ));
        }
        if self.relay_mode == RelayMode::External && self.relays.is_empty() {
            return Err("GP_RELAY_MODE=external requires GP_RELAYS".into());
        }
        if self.relay_mode == RelayMode::Bundled && self.bundled_relay_url.trim().is_empty() {
            return Err("GP_RELAY_MODE=bundled requires a non-empty GP_BUNDLED_RELAY_URL".into());
        }
        if self.nsec.is_some() && self.ncryptsec.is_some() {
            return Err("set only one of GP_NSEC and GP_NCRYPTSEC".into());
        }
        if self.webhook_url.is_some() && self.webhook_secret.is_none() {
            return Err(
                "GP_WEBHOOK_URL requires GP_WEBHOOK_SECRET (webhooks are HMAC-signed)".into(),
            );
        }
        if self.endpub_overlap_epochs < 0 {
            return Err("GP_ENDPUB_OVERLAP_EPOCHS must be >= 0".into());
        }
        if self.endpub_rotate_interval < 0 {
            return Err("GP_ENDPUB_ROTATE_INTERVAL must be >= 0 (0 = off)".into());
        }
        if self.rate_currencies.is_empty() {
            return Err("GP_RATE_CURRENCIES must list at least one currency".into());
        }
        if self.quote_ttl <= 0 {
            return Err("GP_QUOTE_TTL must be > 0 (seconds)".into());
        }
        if self.rate_cache_ttl < 0 {
            return Err("GP_RATE_CACHE_TTL must be >= 0 (0 = always refetch)".into());
        }
        if self.rate_stale_max < 0 {
            return Err("GP_RATE_STALE_MAX must be >= 0 (0 = off)".into());
        }
        if self.confirmations_required < 1 {
            return Err("GP_CONFIRMATIONS must be >= 1".into());
        }
        Ok(())
    }

    /// One-line summary for the startup log. Secrets show only as set/unset.
    pub fn summary(&self) -> String {
        let set = |o: bool| if o { "set" } else { "unset" };
        format!(
            "bind={} tls={} db={} data_dir={} node={} chain={:?} relay_mode={:?} \
             relays={:?} bundled_relay={} ingest={} checkout_methods={} match_mode={:?} \
             mnemonic={} \
             wallet_password={} \
             nsec={} ncryptsec={} public_url={} api_token={} admin_token={} webhook_url={} \
             webhook_secret={} qr_logo={} merchant_npub={} notify_merchant_dm={} \
             notify_payer_receipt={} endpub_rotate_interval={} endpub_overlap_epochs={} \
             rate_source={} rate_currencies={:?} rate_cache_ttl={} quote_ttl={} \
             rate_stale_max={} confirmations_required={} grin1_rail={} grin1_foreign_port={}",
            self.bind,
            match &self.tls {
                Tls::Off => "off".to_string(),
                Tls::Rustls { cert, key } => format!("rustls(cert={cert},key={key})"),
            },
            self.db_path,
            self.data_dir,
            self.node_url,
            self.chain,
            self.relay_mode,
            self.relays,
            self.bundled_relay_url,
            if self.ingest { "on" } else { "off" },
            self.checkout_methods_str(),
            self.match_mode,
            set(self.mnemonic.is_some()),
            set(self.wallet_password.is_some()),
            set(self.nsec.is_some()),
            set(self.ncryptsec.is_some()),
            self.public_url,
            set(self.api_token.is_some()),
            set(self.admin_token.is_some()),
            self.webhook_url.as_deref().unwrap_or("unset"),
            set(self.webhook_secret.is_some()),
            self.qr_logo.as_deref().unwrap_or("off"),
            self.merchant_npub.as_deref().unwrap_or("unset"),
            if self.notify_merchant_dm { "on" } else { "off" },
            if self.notify_payer_receipt {
                "on"
            } else {
                "off"
            },
            self.endpub_rotate_interval,
            self.endpub_overlap_epochs,
            self.rate_source.as_str(),
            self.rate_currencies,
            self.rate_cache_ttl,
            self.quote_ttl,
            self.rate_stale_max,
            self.confirmations_required,
            if self.grin1_rail { "on" } else { "off" },
            self.grin1_foreign_port,
        )
    }
}

/// Parse `GP_CHECKOUT_METHODS` (comma list of `nostr`/`slatepack`) into the two
/// display flags. Parsing is lenient: tokens are trimmed, lowercased, and
/// unknown tokens are ignored with a warning. Unset (`None`) enables both, which
/// preserves the historical default of showing every available method. If a set
/// value parses to no known methods, both are enabled (a checkout must offer at
/// least one way to pay) and a warning is logged.
fn parse_checkout_methods(raw: Option<String>) -> (bool, bool) {
    let Some(raw) = raw else {
        return (true, true);
    };
    let mut nostr = false;
    let mut slatepack = false;
    for tok in raw.split(',') {
        match tok.trim().to_lowercase().as_str() {
            "" => {}
            "nostr" => nostr = true,
            "slatepack" => slatepack = true,
            other => log::warn!("GP_CHECKOUT_METHODS: ignoring unknown method `{other}`"),
        }
    }
    if !nostr && !slatepack {
        log::warn!(
            "GP_CHECKOUT_METHODS enabled no known methods; defaulting to both (nostr,slatepack)"
        );
        return (true, true);
    }
    (nostr, slatepack)
}

/// Parse an `on`/`off` flag with a default.
fn parse_bool(
    get: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    match get(key).as_deref() {
        None => Ok(default),
        Some("on") => Ok(true),
        Some("off") => Ok(false),
        Some(other) => Err(format!("{key} must be `on` or `off` (got `{other}`)")),
    }
}

/// Parse an integer with a default.
fn parse_i64(get: &dyn Fn(&str) -> Option<String>, key: &str, default: i64) -> Result<i64, String> {
    match get(key) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<i64>()
            .map_err(|_| format!("{key} must be an integer (got `{v}`)")),
    }
}

/// Read a secret from `KEY` or `KEY_FILE` (mounted file, trailing newline
/// trimmed). Setting both is a hard error, so a stray env var can never
/// silently shadow the mounted file or vice versa.
fn secret(get: &dyn Fn(&str) -> Option<String>, key: &str) -> Result<Option<Secret>, String> {
    let file_key = format!("{key}_FILE");
    match (get(key), get(&file_key)) {
        (Some(_), Some(_)) => Err(format!("set only one of {key} and {file_key}")),
        (Some(value), None) => Ok(Some(Secret::new(value))),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("{file_key} `{path}` unreadable: {e}"))?;
            let value = text.trim_end_matches(['\n', '\r']).to_string();
            if value.is_empty() {
                return Err(format!("{file_key} `{path}` is empty"));
            }
            Ok(Some(Secret::new(value)))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn load(vars: &[(&str, &str)]) -> Result<Config, String> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(&|key| map.get(key).cloned())
    }

    #[test]
    fn empty_env_yields_defaults() {
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.bind, DEFAULT_BIND);
        assert_eq!(cfg.tls, Tls::Off);
        assert_eq!(cfg.db_path, DEFAULT_DB_PATH);
        assert_eq!(cfg.data_dir, DEFAULT_DATA_DIR);
        assert_eq!(cfg.node_url, DEFAULT_NODE_URL);
        assert_eq!(cfg.chain, Chain::Mainnet);
        assert_eq!(cfg.relay_mode, RelayMode::Bundled);
        assert!(cfg.relays.is_empty());
        assert_eq!(cfg.bundled_relay_url, DEFAULT_BUNDLED_RELAY);
        assert!(cfg.ingest);
        assert_eq!(cfg.match_mode, MatchMode::Memo);
        assert!(cfg.mnemonic.is_none());
        assert!(cfg.wallet_password.is_none());
        assert!(cfg.nsec.is_none());
        assert!(cfg.ncryptsec.is_none());
    }

    #[test]
    fn overrides_are_applied() {
        let cfg = load(&[
            ("GP_BIND", "0.0.0.0:9000"),
            ("GP_DB_PATH", "/var/lib/goblinpay/gp.db"),
            ("GP_DATA_DIR", "/var/lib/goblinpay/data"),
            ("GP_NODE_URL", "http://127.0.0.1:3413"),
            ("GP_CHAIN", "testnet"),
            ("GP_RELAY_MODE", "external"),
            ("GP_RELAYS", "wss://relay.example, wss://relay2.example ,"),
            ("GP_BUNDLED_RELAY_URL", "wss://relay.mystore.example"),
            ("GP_INGEST", "off"),
            ("GP_MATCH_MODE", "derived"),
        ])
        .unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:9000");
        assert_eq!(cfg.db_path, "/var/lib/goblinpay/gp.db");
        assert_eq!(cfg.data_dir, "/var/lib/goblinpay/data");
        assert_eq!(cfg.node_url, "http://127.0.0.1:3413");
        assert_eq!(cfg.chain, Chain::Testnet);
        assert_eq!(cfg.relay_mode, RelayMode::External);
        assert_eq!(
            cfg.relays,
            vec!["wss://relay.example", "wss://relay2.example"]
        );
        assert_eq!(cfg.bundled_relay_url, "wss://relay.mystore.example");
        assert!(!cfg.ingest);
        assert_eq!(cfg.match_mode, MatchMode::Derived);
    }

    #[test]
    fn checkout_methods_default_and_parsing() {
        // Unset: both methods on (unchanged historical behavior).
        let cfg = load(&[]).unwrap();
        assert!(cfg.checkout_nostr);
        assert!(cfg.checkout_slatepack);

        // Single method selects only that method.
        let cfg = load(&[("GP_CHECKOUT_METHODS", "nostr")]).unwrap();
        assert!(cfg.checkout_nostr);
        assert!(!cfg.checkout_slatepack);

        let cfg = load(&[("GP_CHECKOUT_METHODS", "slatepack")]).unwrap();
        assert!(!cfg.checkout_nostr);
        assert!(cfg.checkout_slatepack);

        // Both, order/whitespace/case insensitive, unknown tokens ignored.
        let cfg = load(&[("GP_CHECKOUT_METHODS", " Slatepack , NOSTR ,bogus,")]).unwrap();
        assert!(cfg.checkout_nostr);
        assert!(cfg.checkout_slatepack);

        // Empty or all-garbage parses to no methods -> defaults to both.
        let cfg = load(&[("GP_CHECKOUT_METHODS", "")]).unwrap();
        assert!(cfg.checkout_nostr);
        assert!(cfg.checkout_slatepack);
        let cfg = load(&[("GP_CHECKOUT_METHODS", "lightning, bitcoin")]).unwrap();
        assert!(cfg.checkout_nostr);
        assert!(cfg.checkout_slatepack);
    }

    #[test]
    fn tls_rustls_requires_cert_and_key() {
        assert!(load(&[("GP_TLS", "rustls")]).is_err());
        assert!(load(&[("GP_TLS", "rustls"), ("GP_TLS_CERT", "/c.pem")]).is_err());
        let cfg = load(&[
            ("GP_TLS", "rustls"),
            ("GP_TLS_CERT", "/c.pem"),
            ("GP_TLS_KEY", "/k.pem"),
        ])
        .unwrap();
        assert_eq!(
            cfg.tls,
            Tls::Rustls {
                cert: "/c.pem".into(),
                key: "/k.pem".into()
            }
        );
    }

    #[test]
    fn rejects_unknown_enum_values() {
        assert!(load(&[("GP_TLS", "acme")]).is_err());
        assert!(load(&[("GP_CHAIN", "floonet")]).is_err());
        assert!(load(&[("GP_RELAY_MODE", "both")]).is_err());
        assert!(load(&[("GP_INGEST", "yes")]).is_err());
        assert!(load(&[("GP_MATCH_MODE", "exact")]).is_err());
    }

    #[test]
    fn nsec_and_ncryptsec_together_is_an_error() {
        assert!(load(&[("GP_NSEC", "nsec1a"), ("GP_NCRYPTSEC", "ncryptsec1b")]).is_err());
        assert!(load(&[("GP_NCRYPTSEC", "ncryptsec1b")]).is_ok());
    }

    #[test]
    fn rejects_bad_node_url_and_external_without_relays() {
        assert!(load(&[("GP_NODE_URL", "grin.money")]).is_err());
        assert!(load(&[("GP_RELAY_MODE", "external")]).is_err());
        assert!(load(&[("GP_DATA_DIR", "")]).is_err());
    }

    #[test]
    fn secret_from_env_var() {
        let cfg = load(&[("GP_MNEMONIC", "abandon ability able")]).unwrap();
        assert_eq!(cfg.mnemonic.unwrap().reveal(), "abandon ability able");
    }

    #[test]
    fn secret_from_mounted_file_trims_trailing_newline() {
        let path = std::env::temp_dir().join(format!("gp-nsec-{}", std::process::id()));
        std::fs::write(&path, "nsec1testvalue\n").unwrap();
        let cfg = load(&[("GP_NSEC_FILE", path.to_str().unwrap())]).unwrap();
        assert_eq!(cfg.nsec.unwrap().reveal(), "nsec1testvalue");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn secret_env_and_file_together_is_an_error() {
        assert!(load(&[("GP_NSEC", "a"), ("GP_NSEC_FILE", "/tmp/x")]).is_err());
    }

    #[test]
    fn secret_missing_file_is_an_error() {
        assert!(load(&[("GP_MNEMONIC_FILE", "/nonexistent/gp-seed")]).is_err());
    }

    #[test]
    fn m5_m6_defaults_and_overrides() {
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.public_url, format!("http://{DEFAULT_BIND}"));
        assert!(cfg.qr_logo.is_none(), "plain QR by default");
        assert!(!cfg.notify_merchant_dm);
        assert!(!cfg.notify_payer_receipt);
        assert_eq!(cfg.endpub_rotate_interval, 0);
        assert_eq!(cfg.endpub_overlap_epochs, 1);
        assert!(cfg.api_token.is_none());

        let cfg = load(&[
            ("GP_PUBLIC_URL", "https://pay.example/"),
            ("GP_API_TOKEN", "apitok"),
            ("GP_ADMIN_TOKEN", "admintok"),
            ("GP_QR_LOGO", "off"),
            ("GP_NOTIFY_MERCHANT_DM", "on"),
            ("GP_ENDPUB_ROTATE_INTERVAL", "3600"),
            ("GP_ENDPUB_OVERLAP_EPOCHS", "2"),
        ])
        .unwrap();
        assert_eq!(cfg.public_url, "https://pay.example"); // trailing slash trimmed
        assert_eq!(cfg.api_token.unwrap().reveal(), "apitok");
        assert!(cfg.qr_logo.is_none(), "off disables the logo");
        assert!(cfg.notify_merchant_dm);
        assert_eq!(cfg.endpub_rotate_interval, 3600);
        assert_eq!(cfg.endpub_overlap_epochs, 2);

        // The center logo is opt-in: builtin sentinel or a custom image URL.
        let cfg = load(&[("GP_QR_LOGO", "builtin")]).unwrap();
        assert_eq!(cfg.qr_logo.as_deref(), Some(QR_LOGO_BUILTIN));
        assert_eq!(cfg.qr_logo(), crate::qr::Logo::Builtin);
        let cfg = load(&[("GP_QR_LOGO", "https://cdn.example/logo.svg")]).unwrap();
        assert_eq!(
            cfg.qr_logo(),
            crate::qr::Logo::Href("https://cdn.example/logo.svg")
        );
    }

    #[test]
    fn webhook_url_requires_secret_and_flags_validate() {
        assert!(load(&[("GP_WEBHOOK_URL", "https://store/hook")]).is_err());
        assert!(load(&[
            ("GP_WEBHOOK_URL", "https://store/hook"),
            ("GP_WEBHOOK_SECRET", "shh"),
        ])
        .is_ok());
        assert!(load(&[("GP_NOTIFY_MERCHANT_DM", "yes")]).is_err());
        assert!(load(&[("GP_ENDPUB_ROTATE_INTERVAL", "-5")]).is_err());
        assert!(load(&[("GP_ENDPUB_ROTATE_INTERVAL", "notanumber")]).is_err());
    }

    #[test]
    fn m7_rate_defaults_and_overrides() {
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.rate_source, RateSource::CoinGecko);
        assert_eq!(cfg.rate_currencies, vec!["usd".to_string()]);
        assert_eq!(cfg.rate_cache_ttl, DEFAULT_RATE_CACHE_TTL);
        assert_eq!(cfg.quote_ttl, DEFAULT_QUOTE_TTL);
        assert_eq!(cfg.rate_stale_max, 0);

        let cfg = load(&[
            ("GP_RATE_SOURCE", "coingecko"),
            ("GP_RATE_CURRENCIES", "USD, eur , GBP,"),
            ("GP_RATE_CACHE_TTL", "30"),
            ("GP_QUOTE_TTL", "600"),
            ("GP_RATE_STALE_MAX", "1800"),
        ])
        .unwrap();
        // Currencies are lowercased and trimmed, blanks dropped.
        assert_eq!(cfg.rate_currencies, vec!["usd", "eur", "gbp"]);
        assert_eq!(cfg.rate_cache_ttl, 30);
        assert_eq!(cfg.quote_ttl, 600);
        assert_eq!(cfg.rate_stale_max, 1800);
    }

    #[test]
    fn confirmations_default_is_ten_and_overridable() {
        // House standard: 10 confirmations by default.
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.confirmations_required, DEFAULT_CONFIRMATIONS);
        assert_eq!(cfg.confirmations_required, 10);

        let cfg = load(&[("GP_CONFIRMATIONS", "3")]).unwrap();
        assert_eq!(cfg.confirmations_required, 3);
    }

    #[test]
    fn grin1_rail_defaults_off_and_is_operator_opt_in() {
        // Packaged default OFF (owner ruling): unset and explicit off both
        // behave like the pre-rail server; only an explicit `on` arms it.
        let cfg = load(&[]).unwrap();
        assert!(!cfg.grin1_rail, "grin1 rail must default OFF");
        assert_eq!(cfg.grin1_foreign_port, DEFAULT_GRIN1_FOREIGN_PORT);

        let cfg = load(&[("GP_GRIN1_RAIL", "off")]).unwrap();
        assert!(!cfg.grin1_rail);

        let cfg = load(&[("GP_GRIN1_RAIL", "on"), ("GP_GRIN1_FOREIGN_PORT", "3999")]).unwrap();
        assert!(cfg.grin1_rail);
        assert_eq!(cfg.grin1_foreign_port, 3999);

        assert!(load(&[("GP_GRIN1_RAIL", "yes")]).is_err());
        assert!(load(&[("GP_GRIN1_FOREIGN_PORT", "notaport")]).is_err());
        assert!(load(&[("GP_GRIN1_FOREIGN_PORT", "70000")]).is_err());
    }

    #[test]
    fn confirmations_must_be_at_least_one() {
        assert!(load(&[("GP_CONFIRMATIONS", "0")]).is_err());
        assert!(load(&[("GP_CONFIRMATIONS", "-1")]).is_err());
        assert!(load(&[("GP_CONFIRMATIONS", "notanumber")]).is_err());
    }

    #[test]
    fn m7_rate_validation_rejects_bad_values() {
        assert!(load(&[("GP_RATE_SOURCE", "messari")]).is_err());
        assert!(load(&[("GP_RATE_CURRENCIES", " , ")]).is_err());
        assert!(load(&[("GP_QUOTE_TTL", "0")]).is_err());
        assert!(load(&[("GP_QUOTE_TTL", "-1")]).is_err());
        assert!(load(&[("GP_RATE_CACHE_TTL", "-1")]).is_err());
        assert!(load(&[("GP_RATE_STALE_MAX", "-5")]).is_err());
    }

    #[test]
    fn debug_and_summary_never_leak_secrets() {
        let cfg = load(&[
            ("GP_MNEMONIC", "topsecret words"),
            ("GP_WALLET_PASSWORD", "hushhush"),
        ])
        .unwrap();
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("topsecret"));
        assert!(!debug.contains("hushhush"));
        assert!(debug.contains("Secret(redacted)"));
        let summary = cfg.summary();
        assert!(!summary.contains("topsecret"));
        assert!(!summary.contains("hushhush"));
        assert!(summary.contains("mnemonic=set"));
        assert!(summary.contains("wallet_password=set"));
        assert!(summary.contains("nsec=unset"));
    }
}
