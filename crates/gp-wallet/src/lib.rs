//! Grin wallet handoff for GoblinPay: the receive-only half of a standard
//! Grin interactive transaction, built on the official upstream `grin-wallet`
//! crates (never a reimplementation of Grin crypto).
//!
//! What this crate does:
//! - opens (or creates) a wallet from a BIP-39 mnemonic; the seed is stored
//!   encrypted at rest under the gp data dir with file mode 0600,
//! - `receive_slatepack`: parse an S1 slatepack -> `receive_tx` (fully
//!   offline, no node involved) -> return the S2 slatepack armor for the
//!   payer to finalize and post,
//! - exposes the wallet's slatepack address (payers can encrypt to it).
//!
//! What this crate never does: initiate a send, finalize, or post to chain.
//!
//! Two-secrets rule: the Grin mnemonic handled here is the money secret. It
//! must never be used for anything Nostr; the payment identity is a separate
//! random nsec owned by `gp-nostr`.
//!
//! The upstream crates are pinned to the exact tag validated by the
//! Milestone-2 round-trip gate against Goblin's wallet stack (see
//! `Cargo.toml` and `tests/goblin_roundtrip.rs`).

pub mod confirm;
pub mod proof;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::{Arc, OnceLock};

use gp_core::config::{Chain, Config};
use grin_core::global::{self, ChainTypes};
use grin_keychain::ExtKeychain;
use grin_util::secp::key::SecretKey;
use grin_util::{Mutex, ZeroingString};
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
use grin_wallet_libwallet::api_impl::{foreign, owner};
use grin_wallet_libwallet::{SlateState, StatusMessage, WalletInst};
use serde::Serialize;

pub use confirm::{confirm_status, ConfirmStatus};
pub use proof::{verify_receiver_proof, ReceiverProof};

/// The wallet instance type this crate drives (upstream grin-wallet stack).
type Provider = DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>;
type Instance = Arc<Mutex<Box<dyn WalletInst<'static, Provider, HTTPNodeClient, ExtKeychain>>>>;

/// Errors from the wallet handoff. String-based on purpose: callers report,
/// they do not branch on Grin internals.
#[derive(Debug)]
pub enum WalletError {
    /// Bad or missing configuration (fail fast at startup).
    Config(String),
    /// The wallet stack itself failed (lifecycle, receive, keychain).
    Wallet(String),
    /// The incoming slatepack could not be parsed, decrypted, or is not an
    /// S1 send slatepack.
    Slatepack(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::Config(m) => write!(f, "wallet config error: {m}"),
            WalletError::Wallet(m) => write!(f, "wallet error: {m}"),
            WalletError::Slatepack(m) => write!(f, "slatepack error: {m}"),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<grin_wallet_libwallet::Error> for WalletError {
    fn from(e: grin_wallet_libwallet::Error) -> Self {
        WalletError::Wallet(e.to_string())
    }
}

/// Result of receiving an S1 slatepack: what gp-core needs for matching and
/// what the transport needs to send back to the payer.
#[derive(Debug, Clone)]
pub struct Received {
    /// Slate UUID, shared by S1, S2, and the final transaction.
    pub slate_id: String,
    /// Amount in nanogrin, as stated by the S1 slate.
    pub amount: u64,
    /// The S2 reply slatepack (plain armor; transport encryption is the
    /// Nostr layer's job, matching Goblin's behavior).
    pub s2_armor: String,
    /// Tx kernel excess commitment, hex (33 bytes). Computed via the upstream
    /// `Slate::calc_excess` (identical to what the wallet's own updater uses
    /// for kernel confirmation and to what the proof signature binds). Stored
    /// per payment so the confirmation poll can query the node for this kernel.
    pub kernel_excess: String,
    /// The receiver-side Grin payment proof as JSON, present only when the
    /// payer's S1 requested one (carried a proof address). `None` otherwise
    /// (today's Goblin senders do not request proofs).
    pub proof: Option<String>,
}

/// Cheap wallet balance snapshot (nanogrin), read from the local DB without a
/// node scan (the heavy updater stays disabled per the plan).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Balance {
    /// Total across unspent, unconfirmed, and immature outputs.
    pub total: u64,
    /// Currently spendable (confirmed, unlocked).
    pub spendable: u64,
}

/// A receive-only Grin wallet over the upstream grin-wallet stack.
///
/// Cheaply cloneable: the wallet instance is an `Arc<Mutex<..>>`, so a clone
/// shares one underlying wallet + seed. Both the Nostr ingest service and the
/// HTTP manual-slatepack handler hold a clone and serialize on the inner mutex.
#[derive(Clone)]
pub struct GpWallet {
    instance: Instance,
    mask: Option<SecretKey>,
    /// Configured node URL for confirmation reads (DIRECT HTTP, never Nym).
    node_url: String,
}

impl fmt::Debug for GpWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose keys or the mask.
        f.write_str("GpWallet(open)")
    }
}

impl GpWallet {
    /// Open (or create on first run) the wallet described by the gp config.
    /// Requires `GP_MNEMONIC` (or `_FILE`) and `GP_WALLET_PASSWORD` (or
    /// `_FILE`); fails fast when either is missing.
    pub fn open(cfg: &Config) -> Result<GpWallet, WalletError> {
        let mnemonic = cfg.mnemonic.as_ref().ok_or_else(|| {
            WalletError::Config("GP_MNEMONIC (or GP_MNEMONIC_FILE) is required".into())
        })?;
        let password = cfg.wallet_password.as_ref().ok_or_else(|| {
            WalletError::Config(
                "GP_WALLET_PASSWORD (or GP_WALLET_PASSWORD_FILE) is required to \
                 encrypt the wallet seed at rest"
                    .into(),
            )
        })?;
        let chain = match cfg.chain {
            Chain::Mainnet => ChainTypes::Mainnet,
            Chain::Testnet => ChainTypes::Testnet,
        };
        Self::open_at(
            Path::new(&cfg.data_dir),
            mnemonic.reveal(),
            password.reveal(),
            &cfg.node_url,
            chain,
        )
    }

    /// Open (or create) a wallet under `data_dir` from a BIP-39 mnemonic.
    /// The seed is written encrypted (with `password`) to
    /// `<data_dir>/wallet/wallet_data/wallet.seed`, mode 0600. The receive path
    /// is fully offline; `node_url` is used only for lightweight confirmation
    /// reads (a single `get_kernel` per pending payment), which go DIRECT over
    /// HTTP, never through the Nym tunnel.
    pub fn open_at(
        data_dir: &Path,
        mnemonic: &str,
        password: &str,
        node_url: &str,
        chain: ChainTypes,
    ) -> Result<GpWallet, WalletError> {
        init_chain_type(chain)?;

        let top_dir = data_dir.join("wallet");
        fs::create_dir_all(&top_dir)
            .map_err(|e| WalletError::Config(format!("cannot create {top_dir:?}: {e}")))?;
        restrict_permissions(data_dir, 0o700)?;
        restrict_permissions(&top_dir, 0o700)?;
        let top_dir_str = top_dir
            .to_str()
            .ok_or_else(|| WalletError::Config(format!("non-UTF8 data dir {top_dir:?}")))?;

        let node_client = HTTPNodeClient::new(node_url, None)
            .map_err(|e| WalletError::Config(format!("bad node URL `{node_url}`: {e}")))?;
        let mut wallet = Box::new(
            DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client)
                .map_err(|e| WalletError::Wallet(e.to_string()))?,
        )
            as Box<dyn WalletInst<'static, Provider, HTTPNodeClient, ExtKeychain>>;

        let mask = {
            let lc = wallet.lc_provider()?;
            lc.set_top_level_directory(top_dir_str)?;
            if lc.wallet_exists(None)? {
                // The data dir already holds a wallet: refuse to run against
                // a different seed than the configured one.
                let existing = lc.get_mnemonic(None, ZeroingString::from(password))?;
                if &*existing != mnemonic {
                    return Err(WalletError::Config(format!(
                        "data dir {top_dir:?} already holds a wallet created from a \
                         different mnemonic; refusing to open"
                    )));
                }
            } else {
                lc.create_wallet(
                    None,
                    Some(ZeroingString::from(mnemonic)),
                    32,
                    ZeroingString::from(password),
                    false,
                )?;
            }
            lc.open_wallet(None, ZeroingString::from(password), true, false)?
        };

        // The seed is encrypted, but belt and braces: nobody else on the
        // host gets to read it.
        let wallet_data = top_dir.join("wallet_data");
        restrict_permissions(&wallet_data, 0o700)?;
        restrict_permissions(&wallet_data.join("wallet.seed"), 0o600)?;

        Ok(GpWallet {
            instance: Arc::new(Mutex::new(wallet)),
            mask,
            node_url: node_url.to_string(),
        })
    }

    /// The wallet's slatepack address (derivation index 0). Payers may
    /// encrypt slatepacks to it; it is also the payment-proof address.
    pub fn slatepack_address(&self) -> Result<String, WalletError> {
        let addr = owner::get_slatepack_address(self.instance.clone(), self.mask.as_ref(), 0)?;
        Ok(addr.to_string())
    }

    /// Receive a payment: parse the S1 slatepack (plain or encrypted to our
    /// address), run `receive_tx` (offline), and return the S2 reply armor.
    pub fn receive_slatepack(&self, s1_armor: &str) -> Result<Received, WalletError> {
        let slate = owner::slate_from_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            s1_armor.trim().to_string(),
            vec![0],
        )
        .map_err(|e| WalletError::Slatepack(format!("cannot read slatepack: {e}")))?;

        if slate.state != SlateState::Standard1 {
            return Err(WalletError::Slatepack(format!(
                "expected an S1 (standard send) slatepack, got {:?}",
                slate.state
            )));
        }
        // Captured before receive_tx zeroes it on the S2 slate; this is the
        // amount the proof signature binds to.
        let amount = slate.amount;

        // Receive offline.
        let s2 = {
            let mut w_lock = self.instance.lock();
            let lc = w_lock.lc_provider()?;
            let w = lc.wallet_inst()?;
            foreign::receive_tx(&mut **w, self.mask.as_ref(), &slate, None, false)?
        };

        // The kernel excess is read from the tx log, NOT recomputed from the
        // returned S2: compact-slate receive strips the sender's participant
        // data off S2 before returning it, so `s2.calc_excess()` would sum only
        // our own excess and be wrong. The value the wallet logged during
        // receive is summed over both participants (and is offset-independent),
        // so it equals both the excess receive_tx signed into the payment proof
        // and the on-chain kernel excess the node returns — the single anchor
        // for confirmation and proof.
        let kernel_excess = {
            let channel: Option<Sender<StatusMessage>> = None;
            let (_refreshed, txs) = owner::retrieve_txs(
                self.instance.clone(),
                self.mask.as_ref(),
                &channel,
                false, // local read only; the heavy updater stays disabled
                None,
                Some(slate.id),
                None,
            )?;
            let excess = txs
                .iter()
                .find_map(|t| t.kernel_excess.as_ref())
                .ok_or_else(|| {
                    WalletError::Wallet("received tx has no recorded kernel excess".into())
                })?;
            proof::encode_hex(&excess.0)
        };

        // If the payer's S1 requested a payment proof, receive_tx has filled in
        // the receiver signature on the returned slate; capture the full
        // receiver-side proof for storage + independent verification.
        let proof = self.build_proof(&s2, amount, &kernel_excess)?;

        // Plain armor, like Goblin: transport encryption (NIP-44 gift wrap)
        // is the Nostr layer's job, not the slatepack's.
        let s2_armor = owner::create_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            &s2,
            Some(0),
            vec![],
        )?;

        Ok(Received {
            slate_id: s2.id.to_string(),
            amount,
            s2_armor,
            kernel_excess,
            proof,
        })
    }

    /// Extract the receiver-side payment proof from a post-`receive_tx` slate,
    /// serialized to JSON. Returns `None` when the slate carried no proof
    /// request (or, defensively, no receiver signature).
    fn build_proof(
        &self,
        s2: &grin_wallet_libwallet::Slate,
        amount: u64,
        kernel_excess: &str,
    ) -> Result<Option<String>, WalletError> {
        let Some(info) = s2.payment_proof.as_ref() else {
            return Ok(None);
        };
        let Some(sig) = info.receiver_signature.as_ref() else {
            return Ok(None);
        };
        let receiver_proof = ReceiverProof {
            amount,
            kernel_excess: kernel_excess.to_string(),
            sender_address: proof::encode_hex(&info.sender_address.to_bytes()),
            recipient_address: proof::encode_hex(&info.receiver_address.to_bytes()),
            recipient_sig: proof::encode_hex(&sig.to_bytes()),
        };
        // Belt and braces: never store a proof we cannot verify ourselves.
        if !receiver_proof.verify() {
            return Err(WalletError::Wallet(
                "receive_tx produced a payment proof that does not verify".into(),
            ));
        }
        serde_json::to_string(&receiver_proof)
            .map(Some)
            .map_err(|e| WalletError::Wallet(format!("serialize payment proof: {e}")))
    }

    /// Confirmation status for a received payment's kernel, via a DIRECT node
    /// read (never Nym). `kernel_excess_hex` is [`Received::kernel_excess`].
    pub fn confirm_status(&self, kernel_excess_hex: &str) -> Result<ConfirmStatus, WalletError> {
        confirm::confirm_status(&self.node_url, kernel_excess_hex)
    }

    /// The wallet balance from the local DB (no node scan; cheap). Total and
    /// currently-spendable nanogrin.
    pub fn balance(&self) -> Result<Balance, WalletError> {
        let channel: Option<Sender<StatusMessage>> = None;
        let (_refreshed, info) = owner::retrieve_summary_info(
            self.instance.clone(),
            self.mask.as_ref(),
            &channel,
            false, // never refresh from node: the heavy updater stays disabled
            1,
        )?;
        Ok(Balance {
            total: info.total,
            spendable: info.amount_currently_spendable,
        })
    }

    /// Path of the encrypted seed file for a given data dir (for operators
    /// and tests; the two-backups story documents this file).
    pub fn seed_path(data_dir: &Path) -> PathBuf {
        data_dir
            .join("wallet")
            .join("wallet_data")
            .join("wallet.seed")
    }
}

/// Initialize the process-wide Grin chain type exactly once and refuse a
/// conflicting re-initialization (grin globals are process state).
fn init_chain_type(chain: ChainTypes) -> Result<(), WalletError> {
    static CHAIN: OnceLock<ChainTypes> = OnceLock::new();
    let set = CHAIN.get_or_init(|| {
        global::init_global_chain_type(chain);
        chain
    });
    if *set != chain {
        return Err(WalletError::Config(format!(
            "chain type already initialized to {set:?}, cannot switch to {chain:?}"
        )));
    }
    // Make the calling thread consistent even if a local override was set.
    global::set_local_chain_type(chain);
    Ok(())
}

/// chmod, failing fast (the seed must never be world readable).
fn restrict_permissions(path: &Path, mode: u32) -> Result<(), WalletError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| WalletError::Config(format!("cannot chmod {path:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use rand::RngCore;

    use super::*;

    /// Self-cleaning unique temp dir (no extra dev-deps).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "gp-wallet-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A fresh random 24-word test mnemonic. Never a user-provided seed.
    fn random_mnemonic() -> String {
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        grin_keychain::mnemonic::from_entropy(&entropy).unwrap()
    }

    fn open(dir: &TempDir, mnemonic: &str) -> Result<GpWallet, WalletError> {
        GpWallet::open_at(
            &dir.0,
            mnemonic,
            "test-password",
            "http://127.0.0.1:3413",
            ChainTypes::Mainnet,
        )
    }

    #[test]
    fn creates_wallet_with_encrypted_seed_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("create");
        let mnemonic = random_mnemonic();
        let wallet = open(&dir, &mnemonic).unwrap();

        let seed_path = GpWallet::seed_path(&dir.0);
        assert!(seed_path.exists(), "seed file missing at {seed_path:?}");
        let mode = fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seed file must be 0600");

        // Encrypted at rest: no mnemonic word appears in the seed file.
        let raw = fs::read_to_string(&seed_path).unwrap();
        for word in mnemonic.split_whitespace() {
            assert!(!raw.contains(word), "seed file leaks mnemonic word");
        }

        let addr = wallet.slatepack_address().unwrap();
        assert!(addr.starts_with("grin1"), "mainnet address, got {addr}");
    }

    #[test]
    fn reopen_same_mnemonic_yields_same_address() {
        let dir = TempDir::new("reopen");
        let mnemonic = random_mnemonic();
        let first = open(&dir, &mnemonic).unwrap().slatepack_address().unwrap();
        let second = open(&dir, &mnemonic).unwrap().slatepack_address().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn reopen_with_different_mnemonic_is_refused() {
        let dir = TempDir::new("mismatch");
        open(&dir, &random_mnemonic()).unwrap();
        let err = open(&dir, &random_mnemonic()).unwrap_err();
        assert!(matches!(err, WalletError::Config(_)), "got {err}");
    }

    #[test]
    fn invalid_mnemonic_fails_fast() {
        let dir = TempDir::new("badseed");
        assert!(open(&dir, "not a valid bip39 phrase").is_err());
    }

    #[test]
    fn garbage_armor_is_rejected() {
        let dir = TempDir::new("garbage");
        let wallet = open(&dir, &random_mnemonic()).unwrap();
        let err = wallet.receive_slatepack("BEGINSLATEPACK. nope. ENDSLATEPACK.");
        assert!(matches!(err, Err(WalletError::Slatepack(_))));
    }

    #[test]
    fn open_from_config_requires_both_secrets() {
        let cfg = Config::default();
        let err = GpWallet::open(&cfg).unwrap_err();
        assert!(err.to_string().contains("GP_MNEMONIC"), "got {err}");

        let cfg = Config {
            mnemonic: Some(gp_core::config::Secret::new(random_mnemonic())),
            ..Config::default()
        };
        let err = GpWallet::open(&cfg).unwrap_err();
        assert!(err.to_string().contains("GP_WALLET_PASSWORD"), "got {err}");
    }
}
