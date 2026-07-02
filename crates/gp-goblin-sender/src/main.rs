//! Milestone-2 gate helper: the SENDER half of the slatepack round-trip,
//! running Goblin's actual wallet stack (the grin-wallet fork vendored at
//! goblin/wallet over grin_core 5.4.1).
//!
//! Two subcommands, driven by gp-wallet/tests/goblin_roundtrip.rs:
//!
//!   gen <workdir> <amount_nanogrin> [recipient_slatepack_address]
//!     Creates a throwaway wallet from a fresh random mnemonic under
//!     <workdir>/sender-wallet, injects one spendable output (valid keys and
//!     commitment, never on chain, which offline finalization never checks),
//!     runs init_send_tx, and writes:
//!       <workdir>/s1.armor   S1 slatepack (plain, or encrypted to the
//!                            recipient address when one is given)
//!       <workdir>/meta.json  {"slate_id": "...", "amount": N}
//!
//!   check <workdir> <s2_file>
//!     Reopens the same wallet, parses the S2 reply, finalizes the
//!     transaction (full offline validation: sums, signatures, range
//!     proofs), asserts slate id / kernel consistency, and writes
//!       <workdir>/result.json
//!     Exits nonzero on any mismatch.
//!
//! Everything offline: no node, no chain, mainnet parameters. Only freshly
//! generated random test mnemonics, never any real seed.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rand::RngCore;

use goblin_core::core::{Transaction, TxKernel};
use goblin_core::global as gglobal;
use goblin_impls::{DefaultLCProvider, DefaultWalletImpl};
use goblin_keychain::{ExtKeychain, Keychain};
use goblin_libwallet::api_impl::owner as gowner;
use goblin_libwallet::{
    InitTxArgs, NodeVersionInfo, OutputData, OutputStatus, Slate, SlateState, SlatepackAddress,
    WalletInst,
};
use goblin_util::secp::key::SecretKey;
use goblin_util::secp::pedersen;
use goblin_util::Mutex;
use goblin_util::ZeroingString;

const TIP_HEIGHT: u64 = 10;
const PASSWORD: &str = "gate-sender-pw";

type Error = Box<dyn std::error::Error>;
type Provider = DefaultLCProvider<StubNode, ExtKeychain>;
type WalletBox = Box<dyn WalletInst<'static, Provider, StubNode, ExtKeychain>>;
type Instance = Arc<Mutex<WalletBox>>;

/// Offline stand-in for a Grin node: the send path only ever asks for the
/// chain tip. Everything else is unreachable here.
#[derive(Clone)]
struct StubNode;

fn offline<T>(what: &str) -> Result<T, goblin_libwallet::Error> {
    Err(goblin_libwallet::Error::ClientCallback(format!(
        "offline gate stub: {what}"
    )))
}

impl goblin_libwallet::NodeClient for StubNode {
    fn node_url(&self) -> &str {
        "http://127.0.0.1:13413"
    }
    fn set_node_url(&mut self, _: &str) {}
    fn node_api_secret(&self) -> Option<String> {
        None
    }
    fn set_node_api_secret(&mut self, _: Option<String>) {}
    fn post_tx(&self, _: &Transaction, _: bool) -> Result<(), goblin_libwallet::Error> {
        offline("post_tx")
    }
    fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
        None
    }
    fn get_chain_tip(&self) -> Result<(u64, String), goblin_libwallet::Error> {
        Ok((TIP_HEIGHT, "0".repeat(64)))
    }
    fn get_kernel(
        &mut self,
        _: &pedersen::Commitment,
        _: Option<u64>,
        _: Option<u64>,
    ) -> Result<Option<(TxKernel, u64, u64)>, goblin_libwallet::Error> {
        offline("get_kernel")
    }
    fn get_outputs_from_node(
        &self,
        wallet_outputs: Vec<pedersen::Commitment>,
    ) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, goblin_libwallet::Error> {
        // Goblin's fork refreshes outputs from the node before selecting
        // inputs (updater::refresh_outputs inside add_inputs_to_slate, a
        // deviation from upstream). Report every wallet output as unspent
        // on chain so the injected input stays spendable.
        Ok(wallet_outputs
            .into_iter()
            .map(|c| {
                let hex: String = c.0.iter().map(|b| format!("{b:02x}")).collect();
                (c, (hex, 1, 1))
            })
            .collect())
    }
    fn get_outputs_by_pmmr_index(
        &self,
        _: u64,
        _: Option<u64>,
        _: u64,
    ) -> Result<
        (
            u64,
            u64,
            Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
        ),
        goblin_libwallet::Error,
    > {
        offline("get_outputs_by_pmmr_index")
    }
    fn height_range_to_pmmr_indices(
        &self,
        _: u64,
        _: Option<u64>,
    ) -> Result<(u64, u64), goblin_libwallet::Error> {
        offline("height_range_to_pmmr_indices")
    }
}

struct Sender {
    instance: Instance,
    mask: Option<SecretKey>,
}

impl Sender {
    /// Create a fresh wallet from a random mnemonic (gen phase).
    fn create(dir: &Path) -> Result<Sender, Error> {
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = goblin_keychain::mnemonic::from_entropy(&entropy)
            .map_err(|e| format!("mnemonic generation failed: {e:?}"))?;
        Self::open(dir, Some(mnemonic))
    }

    /// Open the wallet, creating it first when a mnemonic is given.
    fn open(dir: &Path, create_mnemonic: Option<String>) -> Result<Sender, Error> {
        let mut wallet = Box::new(DefaultWalletImpl::<StubNode>::new(StubNode)?) as WalletBox;
        let mask = {
            let lc = wallet.lc_provider()?;
            lc.set_top_level_directory(
                dir.to_str()
                    .ok_or_else(|| format!("non-UTF8 dir {dir:?}"))?,
            )?;
            if let Some(mnemonic) = create_mnemonic {
                lc.create_wallet(
                    None,
                    Some(ZeroingString::from(mnemonic)),
                    32,
                    ZeroingString::from(PASSWORD),
                    false,
                )?;
            }
            lc.open_wallet(None, ZeroingString::from(PASSWORD), true, false)?
        };
        Ok(Sender {
            instance: Arc::new(Mutex::new(wallet)),
            mask,
        })
    }

    /// Give the wallet one ordinary spendable output so init_send_tx has
    /// coins to select. Valid keys and commitment, never on chain.
    fn inject_funds(&self, value: u64) -> Result<(), Error> {
        let mut w_lock = self.instance.lock();
        let lc = w_lock.lc_provider()?;
        let w = lc.wallet_inst()?;
        let parent = w.parent_key_id();
        let key_id = w.next_child(self.mask.as_ref())?;
        let n_child = u32::from(key_id.to_path().path[2]);
        let mut batch = w.batch(self.mask.as_ref())?;
        batch.save(OutputData {
            root_key_id: parent.clone(),
            key_id,
            n_child,
            commit: None,
            mmr_index: None,
            value,
            status: OutputStatus::Unspent,
            height: 1,
            lock_height: 0,
            is_coinbase: false,
            tx_log_entry: None,
        })?;
        batch.save_last_confirmed_height(&parent, TIP_HEIGHT)?;
        batch.commit()?;
        Ok(())
    }

    fn init_send(
        &self,
        amount: u64,
        proof_recipient: Option<SlatepackAddress>,
    ) -> Result<Slate, Error> {
        let mut w_lock = self.instance.lock();
        let lc = w_lock.lc_provider()?;
        let w = lc.wallet_inst()?;
        let args = InitTxArgs {
            amount,
            minimum_confirmations: 1,
            max_outputs: 500,
            num_change_outputs: 1,
            selection_strategy_is_use_all: false,
            // When set, init_send_tx puts a PaymentInfo on the slate (our
            // sender address + this recipient address, no receiver signature
            // yet), which is exactly the payment-proof request the receiver
            // fills in during receive_tx.
            payment_proof_recipient_address: proof_recipient,
            ..Default::default()
        };
        let slate = gowner::init_send_tx(w, self.mask.as_ref(), args, false)?;
        // Lock before transmitting S1, exactly like Goblin does
        // (goblin/src/wallet/wallet.rs calls api.tx_lock_outputs right after
        // init_send_tx). Locking also records the change output in the
        // wallet DB; finalize's repopulate_tx silently drops the change
        // output when it is missing, which breaks the kernel sums.
        gowner::tx_lock_outputs(w, self.mask.as_ref(), &slate)?;
        Ok(slate)
    }

    fn armor(&self, slate: &Slate, recipients: Vec<SlatepackAddress>) -> Result<String, Error> {
        Ok(gowner::create_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            slate,
            Some(0),
            recipients,
        )?)
    }

    fn parse_s2(&self, armor: &str) -> Result<Slate, Error> {
        Ok(gowner::slate_from_slatepack_message(
            self.instance.clone(),
            self.mask.as_ref(),
            armor.trim().to_string(),
            vec![],
        )?)
    }

    fn finalize(&self, slate: &Slate) -> Result<Slate, Error> {
        let mut w_lock = self.instance.lock();
        let lc = w_lock.lc_provider()?;
        let w = lc.wallet_inst()?;
        Ok(gowner::finalize_tx(w, self.mask.as_ref(), slate)?)
    }

    fn calc_excess(&self, slate: &Slate) -> Result<pedersen::Commitment, Error> {
        let mut w_lock = self.instance.lock();
        let lc = w_lock.lc_provider()?;
        let w = lc.wallet_inst()?;
        let keychain = w.keychain(self.mask.as_ref())?;
        Ok(slate.calc_excess(keychain.secp())?)
    }
}

fn wallet_dir(workdir: &Path) -> std::path::PathBuf {
    workdir.join("sender-wallet")
}

fn cmd_gen(workdir: &Path, amount: u64, recipient: Option<&str>) -> Result<(), Error> {
    let dir = wallet_dir(workdir);
    std::fs::create_dir_all(&dir)?;

    let sender = Sender::create(&dir)?;
    // Amount plus generous room for the fee, in one output.
    sender.inject_funds(amount + 1_000_000_000)?;

    let slate = sender.init_send(amount, None)?;
    if slate.state != SlateState::Standard1 {
        return Err(format!("expected S1 out of init_send_tx, got {:?}", slate.state).into());
    }

    let recipients = match recipient {
        Some(addr) => vec![SlatepackAddress::try_from(addr)
            .map_err(|e| format!("recipient address `{addr}` rejected: {e}"))?],
        None => vec![],
    };
    let armor = sender.armor(&slate, recipients)?;

    std::fs::write(workdir.join("s1.armor"), &armor)?;
    let meta = serde_json::json!({
        "slate_id": slate.id.to_string(),
        "amount": amount,
    });
    std::fs::write(workdir.join("meta.json"), meta.to_string())?;
    println!("{meta}");
    Ok(())
}

/// Like `gen`, but the S1 REQUESTS a payment proof to `recipient` (the
/// receiver's slatepack address). Exercises gp-wallet's receiver-side proof
/// path. Armor is plain (proof and armor encryption are orthogonal).
fn cmd_genproof(workdir: &Path, amount: u64, recipient: &str) -> Result<(), Error> {
    let dir = wallet_dir(workdir);
    std::fs::create_dir_all(&dir)?;

    let proof_addr = SlatepackAddress::try_from(recipient)
        .map_err(|e| format!("proof recipient address `{recipient}` rejected: {e}"))?;

    let sender = Sender::create(&dir)?;
    sender.inject_funds(amount + 1_000_000_000)?;

    let slate = sender.init_send(amount, Some(proof_addr))?;
    if slate.state != SlateState::Standard1 {
        return Err(format!("expected S1 out of init_send_tx, got {:?}", slate.state).into());
    }
    if slate.payment_proof.is_none() {
        return Err("init_send_tx did not attach a payment-proof request".into());
    }
    let armor = sender.armor(&slate, vec![])?;

    std::fs::write(workdir.join("s1.armor"), &armor)?;
    let meta = serde_json::json!({
        "slate_id": slate.id.to_string(),
        "amount": amount,
        "proof_recipient": recipient,
    });
    std::fs::write(workdir.join("meta.json"), meta.to_string())?;
    println!("{meta}");
    Ok(())
}

fn cmd_check(workdir: &Path, s2_file: &Path) -> Result<(), Error> {
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(workdir.join("meta.json"))?)?;
    let slate_id = meta["slate_id"]
        .as_str()
        .ok_or("meta.json missing slate_id")?
        .to_string();

    let sender = Sender::open(&wallet_dir(workdir), None)?;
    let s2 = sender.parse_s2(&std::fs::read_to_string(s2_file)?)?;

    if s2.id.to_string() != slate_id {
        return Err(format!("S2 slate id {} != sent {}", s2.id, slate_id).into());
    }
    if s2.state != SlateState::Standard2 {
        return Err(format!("expected S2, got {:?}", s2.state).into());
    }
    // Compact slates: only the receiver's participant entry travels back in
    // S2; the sender's own entry is restored from the stored context during
    // finalize.
    if s2.participant_data.len() != 1 {
        return Err(format!("S2 has {} participants, want 1", s2.participant_data.len()).into());
    }

    // The real crypto gate: finalizing validates the receiver's output,
    // range proof, and partial signature against consensus rules, offline.
    let final_slate = sender.finalize(&s2)?;
    if final_slate.state != SlateState::Standard3 {
        return Err(format!("expected S3 after finalize, got {:?}", final_slate.state).into());
    }
    let tx = final_slate
        .tx
        .clone()
        .ok_or("final slate carries no transaction")?;
    if tx.kernels().len() != 1 || tx.inputs().len() != 1 || tx.outputs().len() != 2 {
        return Err(format!(
            "unexpected tx shape: {} kernels, {} inputs, {} outputs",
            tx.kernels().len(),
            tx.inputs().len(),
            tx.outputs().len()
        )
        .into());
    }
    let kernel = &tx.kernels()[0];
    kernel
        .verify()
        .map_err(|e| format!("kernel signature invalid: {e}"))?;
    let excess = sender.calc_excess(&final_slate)?;
    if kernel.excess != excess {
        return Err("kernel excess inconsistent with slate".into());
    }

    let excess_hex: String = excess.0.iter().map(|b| format!("{b:02x}")).collect();
    let result = serde_json::json!({
        "slate_id": final_slate.id.to_string(),
        "state": "Standard3",
        "kernel_verified": true,
        "kernel_excess": excess_hex,
        "kernels": 1,
        "inputs": 1,
        "outputs": 2,
    });
    std::fs::write(workdir.join("result.json"), result.to_string())?;
    println!("{result}");
    Ok(())
}

/// Harness self-test: the fork wallet receives its own S1 (self-spend) and
/// finalizes, without gp-wallet involved. Proves the injected-funds harness
/// is sound independently of any cross-stack question.
fn cmd_selfcheck(workdir: &Path) -> Result<(), Error> {
    use goblin_libwallet::api_impl::foreign as gforeign;

    let dir = wallet_dir(workdir);
    std::fs::create_dir_all(&dir)?;
    let sender = Sender::create(&dir)?;
    let amount = 2_000_000_000u64;
    sender.inject_funds(amount + 1_000_000_000)?;

    let s1 = sender.init_send(amount, None)?;
    let s1_armor = sender.armor(&s1, vec![])?;

    // Receive with the same fork stack (self-spend), through the armor.
    let parsed = sender.parse_s2(&s1_armor)?; // generic slatepack parse
    let s2 = {
        let mut w_lock = sender.instance.lock();
        let lc = w_lock.lc_provider()?;
        let w = lc.wallet_inst()?;
        gforeign::receive_tx(w, sender.mask.as_ref(), &parsed, None, false)?
    };
    let s2_armor = sender.armor(&s2, vec![])?;

    let s2_back = sender.parse_s2(&s2_armor)?;
    let final_slate = sender.finalize(&s2_back)?;
    if final_slate.state != SlateState::Standard3 {
        return Err(format!("selfcheck: expected S3, got {:?}", final_slate.state).into());
    }
    println!("selfcheck ok: {} {:?}", final_slate.id, final_slate.state);
    Ok(())
}

fn run() -> Result<(), Error> {
    gglobal::init_global_chain_type(gglobal::ChainTypes::Mainnet);
    gglobal::set_local_chain_type(gglobal::ChainTypes::Mainnet);

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") if args.len() == 4 || args.len() == 5 => {
            let amount: u64 = args[3].parse()?;
            cmd_gen(Path::new(&args[2]), amount, args.get(4).map(String::as_str))
        }
        Some("genproof") if args.len() == 5 => {
            let amount: u64 = args[3].parse()?;
            cmd_genproof(Path::new(&args[2]), amount, &args[4])
        }
        Some("check") if args.len() == 4 => cmd_check(Path::new(&args[2]), Path::new(&args[3])),
        Some("selfcheck") if args.len() == 3 => cmd_selfcheck(Path::new(&args[2])),
        _ => Err(
            "usage: gp-goblin-sender gen <workdir> <amount_nanogrin> [recipient] \
                  | genproof <workdir> <amount_nanogrin> <recipient> \
                  | check <workdir> <s2_file> | selfcheck <workdir>"
                .into(),
        ),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("gp-goblin-sender: {e} ({e:?})");
        std::process::exit(1);
    }
}
