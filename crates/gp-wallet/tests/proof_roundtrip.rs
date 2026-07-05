//! Payment-proof round trip: a payer whose S1 REQUESTS a Grin native payment
//! proof (addressed to gp-wallet's slatepack address) pays, gp-wallet receives
//! and produces the receiver-side proof, and that proof verifies. Tampered
//! variants are rejected.
//!
//! The sender is Goblin's actual wallet stack (the `gp-goblin-sender`
//! subprocess `genproof` subcommand, which sets InitTxArgs'
//! `payment_proof_recipient_address`), producing a real S1 with a real
//! PaymentInfo. gp-wallet's upstream `receive_tx` signs the receiver half; we
//! assert the stored proof verifies with the same ed25519 library grin uses.
//!
//! Only freshly generated random test mnemonics; everything offline (no node,
//! no chain). Live on-chain confirmation of the proof's kernel is deferred to
//! the supervised mainnet round.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use gp_wallet::{GpWallet, ReceiverProof};
use grin_core::global::ChainTypes;
use rand::RngCore;

const AMOUNT: u64 = 2_000_000_000; // 2 grin, in nanogrin

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "gp-proof-{tag}-{}-{}",
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

/// Run one gp-goblin-sender subcommand (same helper as the other gates: build
/// the workspace binary if missing, then execute it directly).
fn sender(args: &[&str]) {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));
    let bin = target_dir.join("debug").join("gp-goblin-sender");

    if !bin.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let build = Command::new(cargo)
            .current_dir(&workspace_root)
            .args(["build", "--quiet", "-p", "gp-goblin-sender"])
            .output()
            .expect("failed to spawn cargo build for gp-goblin-sender");
        assert!(
            build.status.success(),
            "building gp-goblin-sender failed:\n{}",
            String::from_utf8_lossy(&build.stderr),
        );
    }

    let output = Command::new(&bin)
        .args(args)
        .output()
        .expect("failed to spawn gp-goblin-sender");
    assert!(
        output.status.success(),
        "gp-goblin-sender {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn new_receiver(dir: &Path) -> GpWallet {
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = grin_keychain::mnemonic::from_entropy(&entropy).unwrap();
    GpWallet::open_at(
        dir,
        Some(mnemonic.as_str()),
        "proof-receiver-pw",
        "http://127.0.0.1:3413",
        ChainTypes::Mainnet,
    )
    .unwrap()
}

#[test]
fn payer_requests_proof_receiver_produces_and_verifies_it() {
    let work = TempDir::new("req");
    let receiver_dir = TempDir::new("req-recv");
    let receiver = new_receiver(&receiver_dir.0);
    let workdir = work.0.to_str().unwrap();

    let recipient = receiver.slatepack_address().unwrap();
    assert!(recipient.starts_with("grin1"));

    // Payer builds an S1 that REQUESTS a proof to our address.
    sender(&["genproof", workdir, &AMOUNT.to_string(), &recipient]);
    let s1_armor = fs::read_to_string(work.0.join("s1.armor")).unwrap();

    let received = receiver.receive_slatepack(&s1_armor).unwrap();
    assert_eq!(received.amount, AMOUNT);

    let proof_json = received
        .proof
        .expect("a proof-requesting S1 must yield a receiver proof");
    let proof: ReceiverProof = serde_json::from_str(&proof_json).unwrap();

    // The genuine proof verifies, and its fields line up with the receive.
    assert!(proof.verify(), "receiver proof must verify");
    assert_eq!(proof.amount, AMOUNT);
    assert_eq!(proof.kernel_excess, received.kernel_excess);
    assert_eq!(proof.kernel_excess.len(), 66); // 33-byte commitment hex
    assert_eq!(proof.recipient_address.len(), 64); // ed25519 hex
    assert_eq!(proof.sender_address.len(), 64);
    assert_eq!(proof.recipient_sig.len(), 128); // 64-byte sig hex

    // Tampering any bound field breaks verification.
    let mut wrong_amount = proof.clone();
    wrong_amount.amount += 1;
    assert!(!wrong_amount.verify(), "wrong amount must not verify");

    let mut wrong_excess = proof.clone();
    // Flip the last hex nibble of the excess (still valid length/hex).
    let mut chars: Vec<char> = wrong_excess.kernel_excess.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    wrong_excess.kernel_excess = chars.into_iter().collect();
    assert!(
        !wrong_excess.verify(),
        "wrong kernel excess must not verify"
    );

    let mut wrong_recipient = proof.clone();
    // Swap recipient for the sender address: a different key did not sign.
    wrong_recipient.recipient_address = proof.sender_address.clone();
    assert!(!wrong_recipient.verify(), "wrong recipient must not verify");
}

#[test]
fn payer_without_proof_request_yields_no_proof() {
    let work = TempDir::new("noreq");
    let receiver_dir = TempDir::new("noreq-recv");
    let receiver = new_receiver(&receiver_dir.0);
    let workdir = work.0.to_str().unwrap();

    // Plain send (no proof request), as today's Goblin sends.
    sender(&["gen", workdir, &AMOUNT.to_string()]);
    let s1_armor = fs::read_to_string(work.0.join("s1.armor")).unwrap();

    let received = receiver.receive_slatepack(&s1_armor).unwrap();
    assert!(
        received.proof.is_none(),
        "no proof should be produced when none was requested"
    );
    // The kernel excess is always recorded, proof or not (confirmation needs it).
    assert_eq!(received.kernel_excess.len(), 66);
}
