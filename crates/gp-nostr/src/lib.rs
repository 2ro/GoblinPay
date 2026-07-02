//! Nostr transport and secure handoff for GoblinPay, mirroring Goblin's
//! proven `src/nostr` + `src/nym` stack adapted to a headless daemon:
//!
//! - [`identity`]: a random standalone nsec (or an imported one), NIP-49
//!   encrypted at rest, deliberately independent of the Grin seed (the
//!   two-secrets rule).
//! - [`wrap`]: NIP-59 gift wrap build/unwrap with the NIP-17 backward-compat
//!   extension — NIP-44 v3 (kind/scope context binding, via the companion
//!   `nip44` crate) negotiated per recipient, v2 via nostr-sdk as the
//!   mandatory baseline.
//! - [`protocol`]: the Goblin payment message layout (kind-14 rumor carrying
//!   one slatepack armor block).
//! - [`ingest`]: the guarded ingest pipeline (dedupe, rate limits, the pure
//!   `decide()` policy) handing S1 slatepacks to the wallet and building the
//!   S2 reply rumor.
//! - [`service`]: the daemon loop — relay pool over the in-process Nym
//!   mixnet, kind-10050 publishing, catch-up + live subscription, reply
//!   dispatch, boot-time reconcile.
//! - [`nym`]: the smolmix tunnel, mix-dns and the relay websocket transport,
//!   ported from Goblin (G14).
//!
//! Privacy: log lines carry short event/key prefixes and hosts only — never
//! armor contents, full URLs, or secrets (Goblin's host-only level).

pub mod identity;
pub mod ingest;
pub mod nym;
pub mod protocol;
pub mod receipt;
pub mod relays;
pub mod service;
pub mod wrap;

/// Re-exported so downstream crates (gp-server) can name the identity key types
/// without depending on nostr-sdk directly.
pub use nostr_sdk::{Keys, PublicKey};

/// What the wallet hands back for one received S1 slatepack. Mirrors
/// `gp_wallet::Received`, redefined here so the transport crate never links
/// the Grin stack (the wallet side plugs in through [`SlatepackReceiver`]).
#[derive(Debug, Clone)]
pub struct ReceivedPayment {
    /// Slate UUID, shared by S1, S2, and the final transaction.
    pub slate_id: String,
    /// Amount in nanogrin, as stated by the slate.
    pub amount: u64,
    /// The S2 reply slatepack armor for the payer to finalize.
    pub s2_armor: String,
}

/// A payment whose S2 reply has not (verifiably) reached the payer yet,
/// surfaced by the store for the boot-time reconcile pass.
#[derive(Debug, Clone)]
pub struct UnrepliedPayment {
    /// Slate UUID.
    pub slate_id: String,
    /// Payer public key, hex.
    pub payer_hex: String,
    /// The stored S2 reply armor.
    pub s2_armor: String,
    /// Our identity that received it (master or a derived child), x-only hex,
    /// so the reply is re-sent from the right key.
    pub recipient_hex: String,
}

/// Context threaded from the ingest pipeline into the wallet handoff: who paid,
/// which of our identities received the payment (the master key or a per-invoice
/// / per-user derived child), and the payer's memo. The recipient and memo are
/// what the matching layer (milestone 5) keys off.
#[derive(Debug, Clone)]
pub struct IncomingContext<'a> {
    /// Seal-verified sender public key, hex.
    pub payer_hex: &'a str,
    /// The identity that received it (x-only hex).
    pub recipient_hex: &'a str,
    /// The payer's sanitized memo (subject tag), if any.
    pub memo: Option<&'a str>,
}

/// Why a receive was refused.
#[derive(Debug)]
pub enum ReceiveError {
    /// This slate was already received — drop the wrap permanently.
    Duplicate,
    /// The slatepack is invalid (bad armor, wrong state, garbage) — drop the
    /// wrap permanently.
    Rejected(String),
    /// Transient failure (wallet/db hiccup) — leave the wrap unmarked so the
    /// next catch-up retries it (an incoming payment must never be silently
    /// lost on a momentary hiccup; Goblin's rule).
    Failed(String),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveError::Duplicate => write!(f, "slate already received"),
            ReceiveError::Rejected(m) => write!(f, "slatepack rejected: {m}"),
            ReceiveError::Failed(m) => write!(f, "receive failed: {m}"),
        }
    }
}

impl std::error::Error for ReceiveError {}

/// The secure handoff seam into the wallet (gp-server implements it over
/// `gp_wallet::GpWallet` + SQLite). Only armored slatepack strings cross the
/// boundary, exactly like production Goblin.
#[allow(async_fn_in_trait)] // consumed generically, never as `dyn`
pub trait SlatepackReceiver: Send + Sync {
    /// Receive an S1 slatepack (parse, `receive_tx`, persist, match to an
    /// invoice/user) and return the S2 reply. `ctx` carries the payer, the
    /// receiving identity, and the memo the matching layer keys off.
    async fn receive(
        &self,
        s1_armor: &str,
        ctx: &IncomingContext<'_>,
    ) -> Result<ReceivedPayment, ReceiveError>;

    /// Mark a payment's S2 reply as dispatched (a relay accepted it).
    async fn mark_replied(&self, slate_id: &str);

    /// Payments still awaiting their S2 dispatch (for boot-time reconcile).
    async fn unreplied(&self) -> Vec<UnrepliedPayment>;
}

/// Resolves an incoming gift wrap's `p` tag (the recipient x-only hex) to the
/// secret keys we hold for it, and lists the identities we currently watch.
///
/// The default is the master identity alone; gp-server supplies a DB-backed
/// directory that also resolves per-invoice (matching mode 2) and per-user
/// (5b) derived children, so a payment sent to any of those unwraps and its
/// reply is signed by the same identity the payer addressed.
pub trait KeyDirectory: Send + Sync {
    /// The keys for a recipient pubkey (hex), or `None` if we do not hold it.
    fn resolve(&self, recipient_hex: &str) -> Option<nostr_sdk::Keys>;
    /// Every pubkey we currently watch (always includes the master), for the
    /// relay subscription filter.
    fn watched(&self) -> Vec<nostr_sdk::PublicKey>;
}

/// The default single-identity directory: the server master key only.
pub struct MasterDirectory(pub nostr_sdk::Keys);

impl KeyDirectory for MasterDirectory {
    fn resolve(&self, recipient_hex: &str) -> Option<nostr_sdk::Keys> {
        if self.0.public_key().to_hex() == recipient_hex {
            Some(self.0.clone())
        } else {
            None
        }
    }

    fn watched(&self) -> Vec<nostr_sdk::PublicKey> {
        vec![self.0.public_key()]
    }
}

/// Build `Keys` from a raw 32-byte secret (used by DB-backed directories to
/// reconstruct a derived child from its recomputed secret).
pub fn keys_from_secret(secret: &[u8; 32]) -> Result<nostr_sdk::Keys, String> {
    let sk = nostr_sdk::SecretKey::from_slice(secret).map_err(|e| e.to_string())?;
    Ok(nostr_sdk::Keys::new(sk))
}

/// Bech32 npub for a key pair (for logs and the merchant QR).
pub fn npub(keys: &nostr_sdk::Keys) -> String {
    use nostr_sdk::ToBech32;
    keys.public_key().to_bech32().unwrap_or_default()
}

/// Bech32 npub for a public key (checkout page display).
pub fn npub_of(pk: nostr_sdk::PublicKey) -> String {
    use nostr_sdk::ToBech32;
    pk.to_bech32().unwrap_or_default()
}

/// Parse a public key from a bech32 `npub` or a raw hex string (for the
/// configured merchant identity).
pub fn pubkey_from_str(s: &str) -> Option<nostr_sdk::PublicKey> {
    use nostr_sdk::FromBech32;
    let s = s.trim();
    nostr_sdk::PublicKey::from_bech32(s)
        .ok()
        .or_else(|| nostr_sdk::PublicKey::from_hex(s).ok())
}

/// Bech32 `nprofile` for a public key plus its relay hints (the checkout QR
/// payload; a Goblin wallet scans it to know where to send).
pub fn nprofile(pk: nostr_sdk::PublicKey, relays: &[String]) -> String {
    use nostr_sdk::nips::nip19::Nip19Profile;
    use nostr_sdk::{RelayUrl, ToBech32};
    let urls: Vec<RelayUrl> = relays
        .iter()
        .filter_map(|r| RelayUrl::parse(r).ok())
        .collect();
    Nip19Profile::new(pk, urls).to_bech32().unwrap_or_default()
}

/// Unix time in seconds (mirrors Goblin's helper).
pub(crate) fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
