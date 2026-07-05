//! THE Milestone-2 gate: prove that gp-wallet's pinned UPSTREAM grin-wallet
//! stack (tag v5.4.1, rev 5c20635a24a1afa48c167775081015cae6321a4f) speaks
//! the same slatepack dialect as Goblin's actual wallet stack (the
//! grin-wallet fork vendored at goblin/wallet, over grin_core 5.4.1).
//!
//! Design: split-process pipeline. The dual-crate-graph design (fork crates
//! as renamed dev-dependencies in this test binary) resolves and compiles,
//! but cannot link: Goblin's fork moved grin_store to heed
//! (lmdb-master-sys) while upstream grin_store uses lmdb-zero
//! (liblmdb-sys), and the two bundled LMDB C libraries collide at link time
//! (duplicate mdb_* symbols; the loser calls the wrong LMDB and dies with
//! MDB_BAD_TXN). So the goblin side lives in its own binary, the sibling
//! `gp-goblin-sender` workspace crate, and this test drives it as a
//! subprocess. Only armored slatepack strings and JSON cross the boundary,
//! exactly like production.
//!
//! Flow (everything offline, mainnet parameters, no node, no chain):
//!   gp-goblin-sender gen:   random wallet + injected spendable output
//!                           -> init_send_tx -> s1.armor + meta.json
//!   gp-wallet (in process): parse S1 -> receive_tx -> S2 armor
//!   gp-goblin-sender check: parse S2 -> finalize_tx (validates the whole
//!                           transaction offline: sums, signatures, range
//!                           proofs) -> result.json
//! with slate id, amount, and kernel consistency asserted at each hop.
//!
//! Only freshly generated random test mnemonics are used, never any real
//! seed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use rand::RngCore;

use gp_wallet::GpWallet;
use grin_core::global::ChainTypes;

const AMOUNT: u64 = 2_000_000_000; // 2 grin, in nanogrin

/// Self-cleaning unique temp dir.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "gp-roundtrip-{tag}-{}-{}",
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

/// Run one gp-goblin-sender subcommand. The binary is a workspace member,
/// so `cargo test --workspace` (and ci.sh) always builds it before tests
/// run; execute it directly to avoid nested-cargo lock contention, and fall
/// back to one `cargo build` when it is missing (e.g. `cargo test -p
/// gp-wallet` on a clean tree).
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

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn new_receiver(dir: &Path) -> GpWallet {
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = grin_keychain::mnemonic::from_entropy(&entropy).unwrap();
    GpWallet::open_at(
        dir,
        Some(mnemonic.as_str()),
        "receiver-pw",
        "http://127.0.0.1:3413",
        ChainTypes::Mainnet,
    )
    .unwrap()
}

/// One full S1 -> receive_tx -> S2 -> finalize round trip, with consistency
/// asserts at every hop. `encrypt_to_receiver` exercises cross-stack
/// slatepack-address parsing and payload encryption.
fn roundtrip(tag: &str, encrypt_to_receiver: bool) {
    let work = TempDir::new(tag);
    let receiver_dir = TempDir::new(&format!("{tag}-recv"));
    let receiver = new_receiver(&receiver_dir.0);
    let workdir = work.0.to_str().unwrap();

    // Goblin side builds the S1 send slatepack.
    let amount = AMOUNT.to_string();
    let mut gen_args = vec!["gen", workdir, &amount];
    let addr_str;
    if encrypt_to_receiver {
        addr_str = receiver.slatepack_address().unwrap();
        assert!(addr_str.starts_with("grin1"), "mainnet address: {addr_str}");
        gen_args.push(&addr_str);
    }
    sender(&gen_args);

    let meta = read_json(&work.0.join("meta.json"));
    assert_eq!(meta["amount"].as_u64().unwrap(), AMOUNT);
    let slate_id = meta["slate_id"].as_str().unwrap().to_string();

    let s1_armor = fs::read_to_string(work.0.join("s1.armor")).unwrap();
    assert!(s1_armor.starts_with("BEGINSLATEPACK."));

    // Upstream receiver: parse S1, receive offline, emit S2.
    let received = receiver.receive_slatepack(&s1_armor).unwrap();
    assert_eq!(received.slate_id, slate_id, "slate id must survive");
    assert_eq!(received.amount, AMOUNT, "amount must survive the armor");
    assert!(received.s2_armor.starts_with("BEGINSLATEPACK."));

    // Goblin side: parse S2 and finalize (full offline validation of the
    // receiver's output, range proof, and partial signature).
    let s2_path = work.0.join("s2.armor");
    fs::write(&s2_path, &received.s2_armor).unwrap();
    sender(&["check", workdir, s2_path.to_str().unwrap()]);

    let result = read_json(&work.0.join("result.json"));
    assert_eq!(result["slate_id"].as_str().unwrap(), slate_id);
    assert_eq!(result["state"].as_str().unwrap(), "Standard3");
    assert!(result["kernel_verified"].as_bool().unwrap());
    assert_eq!(result["kernels"].as_u64().unwrap(), 1);
    assert_eq!(result["inputs"].as_u64().unwrap(), 1);
    assert_eq!(result["outputs"].as_u64().unwrap(), 2);
    assert_eq!(result["kernel_excess"].as_str().unwrap().len(), 66);
}

#[test]
fn goblin_sends_plain_armor_gp_wallet_receives_goblin_finalizes() {
    // Plain armor: exactly what Goblin ships today (transport encryption is
    // the NIP-44 gift wrap, not the slatepack).
    roundtrip("plain", false);
}

#[test]
fn goblin_sends_encrypted_to_gp_wallet_address_and_finalizes() {
    // The fork parses the upstream-derived slatepack address and encrypts
    // the S1 payload to it; gp-wallet decrypts with derivation index 0.
    roundtrip("encrypted", true);
}
