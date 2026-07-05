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
use grin_wallet_libwallet::{IssueInvoiceTxArgs, SlateState, StatusMessage, WalletInst};
use serde::Serialize;

pub use confirm::{confirm_status, ConfirmStatus};
pub use proof::{verify_receiver_proof, ReceiverProof};

// Foreign API v2 slate types, re-exported so gp-server's `/v2/foreign`
// JSON-RPC handler speaks the exact wire shapes stock Grin senders use.
pub use grin_wallet_libwallet::{Slate, VersionInfo, VersionedSlate};

/// The Foreign API version info (`check_version` JSON-RPC method), byte-shaped
/// exactly like stock grin-wallet: `{ foreign_api_version, supported_slate_versions }`.
pub fn check_version() -> VersionInfo {
    foreign::check_version()
}

/// Decode a `grin1...` slatepack address into its ed25519 public key bytes
/// (32), using grin-wallet's own bech32 decoder. This is the same key the
/// onion service publishes as its identity, so the tor module can prove
/// grin1 address == onion address.
pub fn slatepack_address_pubkey(addr: &str) -> Result<[u8; 32], WalletError> {
    let sp = grin_wallet_libwallet::SlatepackAddress::try_from(addr.trim())
        .map_err(|e| WalletError::Slatepack(format!("bad slatepack address `{addr}`: {e}")))?;
    Ok(sp.pub_key.to_bytes())
}

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

/// Result of issuing an invoice (native invoice flow, receiver-initiated): the
/// I1 slatepack armor for the payer plus the slate id we key settlement on.
#[derive(Debug, Clone)]
pub struct Issued {
    /// Slate UUID, shared by I1, I2, and the final transaction. Stored on the
    /// invoice row so a returning I2 is matched back to this invoice.
    pub slate_id: String,
    /// The armored I1 invoice slatepack (standard armor) the payer imports to
    /// pay. Plain armor, like the receive path; no custom transforms.
    pub i1_armor: String,
}

/// Result of finalizing a returned invoice slate (I2): the completed tx has
/// been posted to the node. Carries what the ledger records for the sale.
#[derive(Debug, Clone)]
pub struct FinalizedInvoice {
    /// Slate UUID (matches the invoice's stored `slate_id`).
    pub slate_id: String,
    /// Amount in nanogrin the invoice was issued for.
    pub amount: u64,
    /// Tx kernel excess commitment, hex (33 bytes) — the on-chain anchor the
    /// confirmation poll queries with `get_kernel`.
    pub kernel_excess: String,
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
    ///
    /// `GP_WALLET_PASSWORD` (or `_FILE`) is required on every boot: it decrypts
    /// the seed at rest. `GP_MNEMONIC` (or `_FILE`) is required ONLY to create
    /// the wallet on first run; once the encrypted seed file exists, boot needs
    /// only the password (init-once). If a mnemonic is still supplied after the
    /// wallet exists it is used only as a non-destructive cross-check that it
    /// matches the seed at rest, never to re-create or re-derive anything (the
    /// caller should drop it from the environment, see `gp-server`).
    pub fn open(cfg: &Config) -> Result<GpWallet, WalletError> {
        let password = cfg.wallet_password.as_ref().ok_or_else(|| {
            WalletError::Config(
                "GP_WALLET_PASSWORD (or GP_WALLET_PASSWORD_FILE) is required to \
                 open the wallet (it decrypts the seed at rest)"
                    .into(),
            )
        })?;
        let chain = match cfg.chain {
            Chain::Mainnet => ChainTypes::Mainnet,
            Chain::Testnet => ChainTypes::Testnet,
        };
        Self::open_at(
            Path::new(&cfg.data_dir),
            cfg.mnemonic.as_ref().map(|m| m.reveal()),
            password.reveal(),
            &cfg.node_url,
            chain,
        )
    }

    /// Open (or create) a wallet under `data_dir`. The seed is written
    /// encrypted (with `password`) to
    /// `<data_dir>/wallet/wallet_data/wallet.seed`, mode 0600. The receive path
    /// is fully offline; `node_url` is used only for lightweight confirmation
    /// reads (a single `get_kernel` per pending payment), which go DIRECT over
    /// HTTP, never through the Nym tunnel.
    ///
    /// `mnemonic` is consumed only on first run (when no wallet exists yet):
    /// - wallet absent + `Some(seed)`: create the wallet from `seed`.
    /// - wallet absent + `None`: error (first-run creation needs the seed).
    /// - wallet present + `Some(seed)`: cross-check `seed` matches the seed at
    ///   rest, refusing on mismatch; never re-creates.
    /// - wallet present + `None`: open with the password alone (init-once).
    pub fn open_at(
        data_dir: &Path,
        mnemonic: Option<&str>,
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
                // Init-once: the wallet already exists, so the password alone
                // opens it. The mnemonic is neither required nor used to
                // re-create it. When one IS still supplied, keep a
                // non-destructive safety cross-check that it matches the seed
                // at rest (catches a wrong-seed / wrong-data-dir misconfig);
                // never re-derive or overwrite anything.
                if let Some(mnemonic) = mnemonic {
                    let existing = lc.get_mnemonic(None, ZeroingString::from(password))?;
                    if &*existing != mnemonic {
                        return Err(WalletError::Config(format!(
                            "data dir {top_dir:?} already holds a wallet created from a \
                             different mnemonic; refusing to open"
                        )));
                    }
                }
            } else {
                // First run: creating the wallet is the ONLY path that consumes
                // the seed. Without it there is nothing to open.
                let mnemonic = mnemonic.ok_or_else(|| {
                    WalletError::Config(
                        "first-run wallet creation requires GP_MNEMONIC (or \
                         GP_MNEMONIC_FILE); none was provided and no wallet exists \
                         yet at this data dir"
                            .into(),
                    )
                })?;
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

    /// The ed25519 SEED of the index-0 slatepack address key (32 bytes). This
    /// is the onion-service identity for the grin1 rail: the same key behind
    /// the `grin1` slatepack address is injected into arti's keystore as the
    /// HsIdKeypair, so grin1 address == onion address (the GRIM pattern).
    /// Money-adjacent secret: callers hand it straight to the keystore and
    /// never log or persist it anywhere else.
    pub fn slatepack_secret_seed(&self) -> Result<[u8; 32], WalletError> {
        let d_skey =
            owner::get_slatepack_secret_key(self.instance.clone(), self.mask.as_ref(), 0)?;
        Ok(d_skey.to_bytes())
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
        let kernel_excess = self.slate_kernel_excess(slate.id)?;

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

    /// Issue an invoice (native invoice flow, we are the receiver-initiator):
    /// run `issue_invoice_tx` for `amount` nanogrin, storing the aggsig context
    /// keyed by the slate id, and return the armored I1 slatepack for the payer
    /// plus that slate id. The payer imports the I1, pays it (producing an I2),
    /// and returns the I2 for [`GpWallet::finalize_invoice_slatepack`].
    ///
    /// This touches the node once (`issue_invoice_tx` reads the chain tip to
    /// stamp the slate height); that read goes DIRECT over HTTP, like every
    /// other node read here.
    pub fn issue_invoice(&self, amount: u64) -> Result<Issued, WalletError> {
        let args = IssueInvoiceTxArgs {
            amount,
            ..Default::default()
        };
        let i1 = {
            let mut w_lock = self.instance.lock();
            let lc = w_lock.lc_provider()?;
            let w = lc.wallet_inst()?;
            owner::issue_invoice_tx(&mut **w, self.mask.as_ref(), args, false)?
        };
        if i1.state != SlateState::Invoice1 {
            return Err(WalletError::Wallet(format!(
                "issue_invoice_tx produced unexpected slate state {:?}",
                i1.state
            )));
        }
        // Plain armor (like the receive path); the QR carries the same text.
        let i1_armor = owner::create_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            &i1,
            Some(0),
            vec![],
        )?;
        Ok(Issued {
            slate_id: i1.id.to_string(),
            i1_armor,
        })
    }

    /// Finalize a returned invoice slate (I2) and post the completed tx to the
    /// node. Loads our stored context by slate id (saved at
    /// [`GpWallet::issue_invoice`]), completes the tx, POSTS it, and returns the
    /// slate id + kernel excess for the ledger. A returned slate that is not an
    /// I2 (wrong state, garbage, or one whose context we never stored) errors
    /// cleanly, so a late finalize after an expiry cancel fails rather than
    /// double-posting.
    pub fn finalize_invoice_slatepack(
        &self,
        i2_armor: &str,
    ) -> Result<FinalizedInvoice, WalletError> {
        let i2 = owner::slate_from_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            i2_armor.trim().to_string(),
            vec![0],
        )
        .map_err(|e| WalletError::Slatepack(format!("cannot read invoice slatepack: {e}")))?;

        if i2.state != SlateState::Invoice2 {
            return Err(WalletError::Slatepack(format!(
                "expected an I2 (invoice return) slatepack, got {:?}",
                i2.state
            )));
        }
        let slate_id = i2.id.to_string();
        let amount = i2.amount;

        // Complete the tx from our stored context (errors if we never issued
        // this invoice or already cancelled it), then post it ourselves.
        let final_slate = {
            let mut w_lock = self.instance.lock();
            let lc = w_lock.lc_provider()?;
            let w = lc.wallet_inst()?;
            owner::finalize_tx(&mut **w, self.mask.as_ref(), &i2)?
        };
        let client = HTTPNodeClient::new(&self.node_url, None).map_err(|e| {
            WalletError::Config(format!("bad node URL `{}`: {e}", self.node_url))
        })?;
        owner::post_tx(&client, final_slate.tx_or_err()?, true)?;

        // Kernel excess from the tx log (offset-independent, summed over both
        // participants), same anchor the receive path records.
        let kernel_excess = self.slate_kernel_excess(final_slate.id)?;
        Ok(FinalizedInvoice {
            slate_id,
            amount,
            kernel_excess,
        })
    }

    /// Cancel the stored context for a slate id (invoice expiry): a subsequent
    /// `finalize_invoice_slatepack` for the same slate then fails cleanly (no
    /// stored context), so a late payer I2 cannot settle an expired invoice.
    /// `cancel_tx` contacts the node to confirm state; a node hiccup surfaces as
    /// an error the sweeper logs and retries.
    pub fn cancel(&self, slate_id: &str) -> Result<(), WalletError> {
        let uuid = uuid::Uuid::parse_str(slate_id)
            .map_err(|e| WalletError::Wallet(format!("bad slate id `{slate_id}`: {e}")))?;
        let channel: Option<Sender<StatusMessage>> = None;
        owner::cancel_tx(
            self.instance.clone(),
            self.mask.as_ref(),
            &channel,
            None,
            Some(uuid),
        )?;
        Ok(())
    }

    /// The tx kernel excess (hex) the wallet logged for `slate_id`, read from
    /// the local tx log (no node scan). Shared by receive and invoice finalize.
    fn slate_kernel_excess(&self, slate_id: uuid::Uuid) -> Result<String, WalletError> {
        let channel: Option<Sender<StatusMessage>> = None;
        let (_refreshed, txs) = owner::retrieve_txs(
            self.instance.clone(),
            self.mask.as_ref(),
            &channel,
            false,
            None,
            Some(slate_id),
            None,
        )?;
        let excess = txs
            .iter()
            .find_map(|t| t.kernel_excess.as_ref())
            .ok_or_else(|| WalletError::Wallet("tx has no recorded kernel excess".into()))?;
        Ok(proof::encode_hex(&excess.0))
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

    /// Receive over the Foreign API JSON path (`receive_tx`): run `receive_tx`
    /// on a slate object (not armor, unlike [`GpWallet::receive_slatepack`]) and
    /// return the S2 slate in the sender's slate version plus the ledger bundle
    /// (slate id, amount, kernel excess, optional proof) the caller persists.
    /// Offline; no node contact.
    pub fn receive_slate(
        &self,
        in_slate: VersionedSlate,
    ) -> Result<(VersionedSlate, Received), WalletError> {
        let version = in_slate.version();
        let slate = Slate::from(in_slate);
        if slate.state != SlateState::Standard1 {
            return Err(WalletError::Slatepack(format!(
                "expected an S1 (standard send) slate, got {:?}",
                slate.state
            )));
        }
        let amount = slate.amount;
        let s2 = {
            let mut w_lock = self.instance.lock();
            let lc = w_lock.lc_provider()?;
            let w = lc.wallet_inst()?;
            foreign::receive_tx(&mut **w, self.mask.as_ref(), &slate, None, false)?
        };
        let kernel_excess = self.slate_kernel_excess(slate.id)?;
        let proof = self.build_proof(&s2, amount, &kernel_excess)?;
        // Armor stored for reply-recovery parity with the Nostr path; the JSON
        // sender already holds the S2 it gets back below.
        let s2_armor = owner::create_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            &s2,
            Some(0),
            vec![],
        )?;
        let received = Received {
            slate_id: s2.id.to_string(),
            amount,
            s2_armor,
            kernel_excess,
            proof,
        };
        let out = VersionedSlate::into_version(s2, version)?;
        Ok((out, received))
    }

    /// Finalize over the Foreign API JSON path (`finalize_tx`): complete the tx
    /// from our stored context and POST it (both the invoice-flow I2 and a
    /// standard S2 are handled by upstream `foreign::finalize_tx`), returning the
    /// final slate plus the ledger bundle. `FinalizedInvoice::amount` is the
    /// slate-reported amount, which is 0 for an invoice-flow I2 (the payer zeroes
    /// it); the settlement side uses the matched invoice's expected amount.
    pub fn finalize_slate(
        &self,
        in_slate: VersionedSlate,
    ) -> Result<(VersionedSlate, FinalizedInvoice), WalletError> {
        let version = in_slate.version();
        let slate = Slate::from(in_slate);
        let slate_id = slate.id.to_string();
        let amount = slate.amount;
        let final_slate = {
            let mut w_lock = self.instance.lock();
            let lc = w_lock.lc_provider()?;
            let w = lc.wallet_inst()?;
            // post_automatically = true: upstream posts the completed tx for us.
            foreign::finalize_tx(&mut **w, self.mask.as_ref(), &slate, true)?
        };
        let kernel_excess = self.slate_kernel_excess(final_slate.id)?;
        let out = VersionedSlate::into_version(final_slate, version)?;
        Ok((
            out,
            FinalizedInvoice {
                slate_id,
                amount,
                kernel_excess,
            },
        ))
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
        open_opt(dir, Some(mnemonic))
    }

    fn open_opt(dir: &TempDir, mnemonic: Option<&str>) -> Result<GpWallet, WalletError> {
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
    fn slatepack_secret_seed_derives_the_address_pubkey() {
        // The index-0 seed handed to the onion keystore must be the exact key
        // behind the wallet's grin1 slatepack address (grin1 == onion identity).
        use ed25519_dalek::{PublicKey as DalekPublicKey, SecretKey as DalekSecretKey};
        let dir = TempDir::new("seed");
        let wallet = open(&dir, &random_mnemonic()).unwrap();
        let seed = wallet.slatepack_secret_seed().unwrap();
        let derived = DalekPublicKey::from(&DalekSecretKey::from_bytes(&seed).unwrap());
        let addr_pub = slatepack_address_pubkey(&wallet.slatepack_address().unwrap()).unwrap();
        assert_eq!(derived.to_bytes(), addr_pub);
    }

    #[test]
    fn bad_slatepack_address_is_rejected() {
        assert!(slatepack_address_pubkey("grin1notanaddress").is_err());
        assert!(slatepack_address_pubkey("").is_err());
    }

    #[test]
    fn finalize_invoice_rejects_garbage_armor() {
        // Parse-before-node: a malformed I2 armor is rejected without any node
        // contact, so this runs offline.
        let dir = TempDir::new("fin-garbage");
        let wallet = open(&dir, &random_mnemonic()).unwrap();
        let err = wallet.finalize_invoice_slatepack("BEGINSLATEPACK. nope. ENDSLATEPACK.");
        assert!(matches!(err, Err(WalletError::Slatepack(_))), "got {err:?}");
    }

    #[test]
    fn cancel_rejects_bad_slate_id() {
        // A non-UUID slate id is rejected before any node contact.
        let dir = TempDir::new("cancel-bad");
        let wallet = open(&dir, &random_mnemonic()).unwrap();
        let err = wallet.cancel("not-a-uuid");
        assert!(matches!(err, Err(WalletError::Wallet(_))), "got {err:?}");
    }

    #[test]
    fn open_from_config_requires_wallet_password() {
        // The wallet password is the always-required secret (it decrypts the
        // seed at rest on every boot), so it is what a bare config is missing
        // first — even when a mnemonic is present.
        let cfg = Config::default();
        let err = GpWallet::open(&cfg).unwrap_err();
        assert!(err.to_string().contains("GP_WALLET_PASSWORD"), "got {err}");

        let cfg = Config {
            mnemonic: Some(gp_core::config::Secret::new(random_mnemonic())),
            ..Config::default()
        };
        let err = GpWallet::open(&cfg).unwrap_err();
        assert!(err.to_string().contains("GP_WALLET_PASSWORD"), "got {err}");
    }

    #[test]
    fn first_run_without_mnemonic_is_refused() {
        // No wallet on disk and no seed supplied: creation is impossible, so
        // this must fail fast and name the missing secret.
        let dir = TempDir::new("firstrun-noseed");
        let err = open_opt(&dir, None).unwrap_err();
        assert!(matches!(err, WalletError::Config(_)), "got {err}");
        assert!(err.to_string().contains("GP_MNEMONIC"), "got {err}");
    }

    #[test]
    fn reopen_without_mnemonic_succeeds_init_once() {
        // Init-once: create the wallet with a seed, then reopen with the
        // password alone (mnemonic dropped from the environment). The reopened
        // wallet must be the same one (same slatepack address).
        let dir = TempDir::new("initonce");
        let mnemonic = random_mnemonic();
        let created = open(&dir, &mnemonic).unwrap().slatepack_address().unwrap();
        let reopened = open_opt(&dir, None).unwrap().slatepack_address().unwrap();
        assert_eq!(
            created, reopened,
            "reopen without the seed must be the same wallet"
        );
    }
}
