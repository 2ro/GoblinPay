//! Milestone-3 end-to-end proof: pay -> GoblinPay receives -> S2 back,
//! with a REAL slatepack at every hop.
//!
//! The strongest automatable version of the plan's "pay from Goblin ->
//! GoblinPay receives -> S2 back": a live over-the-wire run needs the Goblin
//! GUI, a funded wallet, relays, and the mixnet, none of which are
//! automatable here (headless-test limits) — that run is deferred to the
//! supervised mainnet round. Instead:
//!
//! - The SENDER is Goblin's actual wallet stack (the `gp-goblin-sender`
//!   subprocess from the milestone-2 gate) producing a real S1, plus a
//!   stand-in payer Nostr identity built from nostr-sdk — for the v2 leg the
//!   incoming gift wrap is built by STOCK nostr-sdk (`EventBuilder::
//!   gift_wrap`), byte-compatible with what today's Goblin publishes; the v3
//!   leg uses gp-nostr's manual v3 wrap (the only v3 implementation).
//! - The ingest events are handed to `Ingest::handle_wrap` DIRECTLY rather
//!   than through a local relay stub. Deliberate: the relay leg is
//!   nostr-sdk's own pool driven exactly as Goblin drives it (proven in
//!   production), while everything milestone 3 adds — unwrap dispatch,
//!   policy, wallet handoff, reply construction, version negotiation — sits
//!   behind `handle_wrap`, which the live service loop calls with the same
//!   arguments. A minimal ws relay stub would re-test nostr-sdk, not us.
//! - The RECEIVER is the real production adapter (`WalletReceiver` over
//!   `gp_wallet::GpWallet` + SQLite), so the payment row and the stored S2
//!   are asserted too.
//! - The reply wrap is decrypted BY THE PAYER (both legs; the v2 leg
//!   additionally through stock nostr-sdk's `UnwrappedGift`) and the S2 it
//!   carries is finalized by the Goblin wallet stack (`check` subcommand:
//!   full offline validation of sums, signatures, range proofs).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use gp_nostr::ingest::{Ingest, IngestOutcome};
use gp_nostr::wrap::{self, WrapVersion};
use gp_nostr::{protocol, SlatepackReceiver};
use gp_server::ingest::WalletReceiver;
use gp_wallet::GpWallet;
use nostr_sdk::nips::nip59::UnwrappedGift;
use nostr_sdk::{EventBuilder, JsonUtil, Keys, Kind, Tag};
use rand::RngCore;

const AMOUNT: u64 = 2_000_000_000; // 2 grin, in nanogrin

/// Self-cleaning unique temp dir.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "gp-e2e-{tag}-{}-{}",
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

/// Run one gp-goblin-sender subcommand (same helper as the milestone-2
/// gate: the binary is a workspace member, built by `cargo test --workspace`
/// before tests run; fall back to one `cargo build` for partial runs).
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

fn new_wallet(dir: &Path) -> GpWallet {
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = grin_keychain::mnemonic::from_entropy(&entropy).unwrap();
    GpWallet::open_at(
        dir,
        &mnemonic,
        "e2e-password",
        "http://127.0.0.1:3413",
        grin_core::global::ChainTypes::Mainnet,
    )
    .unwrap()
}

/// Build the payer-side payment rumor exactly as Goblin's `send_payment_dm`
/// does: kind 14, preamble + armor content, goblin/subject tags, p tag.
fn payment_rumor(payer: &Keys, server: &Keys, s1_armor: &str) -> nostr_sdk::UnsignedEvent {
    let mut tags = protocol::build_rumor_tags(Some("e2e test payment"));
    tags.push(Tag::public_key(server.public_key()));
    EventBuilder::new(
        Kind::PrivateDirectMessage,
        protocol::build_payment_content(s1_armor),
    )
    .tags(tags)
    .build(payer.public_key())
}

/// One full leg: real S1 -> gift wrap (v2 via stock nostr-sdk, v3 via
/// gp-nostr) -> ingest -> wallet S2 -> reply wrap (negotiated version) ->
/// payer decrypts -> Goblin stack finalizes.
async fn leg(tag: &str, incoming: WrapVersion, payer_advertises: Option<&str>) {
    let work = TempDir::new(tag);
    let wallet_dir = TempDir::new(&format!("{tag}-wallet"));
    let workdir = work.0.to_str().unwrap();

    // GoblinPay side: real wallet, real DB, real receiver adapter.
    let db_path = work.0.join("gp.db");
    let pool = gp_core::db::init(db_path.to_str().unwrap()).await.unwrap();
    let receiver = WalletReceiver::new(new_wallet(&wallet_dir.0), pool.clone());
    let server_keys = Keys::generate();
    let ingest = Ingest::new(server_keys.clone(), receiver);

    // Payer side: Goblin's wallet stack builds the S1...
    let amount = AMOUNT.to_string();
    sender(&["gen", workdir, &amount]);
    let s1_armor = fs::read_to_string(work.0.join("s1.armor")).unwrap();
    let slate_id = read_json(&work.0.join("meta.json"))["slate_id"]
        .as_str()
        .unwrap()
        .to_string();

    // ...and a stand-in payer identity gift-wraps it to the server npub.
    let payer_keys = Keys::generate();
    let rumor = payment_rumor(&payer_keys, &server_keys, &s1_armor);
    let wrap_event = match incoming {
        // v2 leg: STOCK nostr-sdk, byte-compatible with today's Goblin.
        WrapVersion::V2 => {
            EventBuilder::gift_wrap(&payer_keys, &server_keys.public_key(), rumor, [])
                .await
                .unwrap()
        }
        // v3 leg: the manual v3 wrap (kind/scope-bound seals + wraps).
        WrapVersion::V3 => wrap::gift_wrap(
            &payer_keys,
            &server_keys.public_key(),
            rumor,
            WrapVersion::V3,
        )
        .unwrap(),
    };
    assert_eq!(
        nip44::payload_version(&wrap_event.content).unwrap(),
        match incoming {
            WrapVersion::V2 => 2,
            WrapVersion::V3 => 3,
        }
    );

    // Ingest: unwrap (version dispatch) -> policy -> wallet receive_tx.
    let outcome = ingest.handle_wrap(&wrap_event).await;
    let reply = match outcome {
        IngestOutcome::Received {
            slate_id: got_slate,
            amount: got_amount,
            reply,
        } => {
            assert_eq!(got_slate, slate_id, "slate id must survive the pipeline");
            assert_eq!(got_amount, AMOUNT, "amount must survive the pipeline");
            reply
        }
        other => panic!("expected Received, got {other:?}"),
    };
    assert_eq!(reply.payer, payer_keys.public_key());

    // A redelivered wrap (relay replay) is dropped without a second receive.
    assert!(matches!(
        ingest.handle_wrap(&wrap_event).await,
        IngestOutcome::Dropped(_)
    ));

    // The payment row is durable with the S2 stored for reconcile.
    let (db_amount, db_payer, db_status, db_s2): (i64, String, String, String) =
        sqlx::query_as("SELECT amount, payer, status, s2_armor FROM payment WHERE slate_id = ?1")
            .bind(&slate_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(db_amount as u64, AMOUNT);
    assert_eq!(db_payer, payer_keys.public_key().to_hex());
    assert_eq!(db_status, "received");
    assert!(db_s2.starts_with("BEGINSLATEPACK."));
    assert_eq!(ingest.receiver().unreplied().await.len(), 1);

    // Reply leg: negotiate the version from the payer's advertised 10050
    // encryption tag (None = v2-only peer), wrap, and let the payer open it.
    let reply_version = wrap::choose_version(payer_advertises);
    let reply_event = wrap::gift_wrap(
        &server_keys,
        &reply.payer,
        reply.rumor.clone(),
        reply_version,
    )
    .unwrap();
    assert_eq!(
        nip44::payload_version(&reply_event.content).unwrap(),
        match reply_version {
            WrapVersion::V2 => 2,
            WrapVersion::V3 => 3,
        }
    );

    // The payer decrypts the reply (version-byte dispatch, no hints).
    let unwrapped = wrap::unwrap_gift_wrap(&payer_keys, &reply_event).unwrap();
    assert_eq!(unwrapped.sender, server_keys.public_key());
    let s2_armor = protocol::extract_slatepack(&unwrapped.rumor.content)
        .expect("reply rumor must carry the S2 slatepack");

    // v2 reply leg: prove stock nostr-sdk (today's Goblin) opens our reply
    // and reads the same S2.
    if reply_version == WrapVersion::V2 {
        let gift = UnwrappedGift::from_gift_wrap(&payer_keys, &reply_event)
            .await
            .unwrap();
        assert_eq!(gift.sender, server_keys.public_key());
        assert_eq!(gift.rumor.as_json(), unwrapped.rumor.as_json());
    }

    // A wrong recipient cannot open the reply.
    assert!(wrap::unwrap_gift_wrap(&Keys::generate(), &reply_event).is_err());

    ingest.receiver().mark_replied(&slate_id).await;
    assert!(ingest.receiver().unreplied().await.is_empty());

    // The Goblin wallet stack finalizes the S2: full offline validation of
    // the receiver's output, range proof, and partial signature.
    let s2_path = work.0.join("s2.armor");
    fs::write(&s2_path, &s2_armor).unwrap();
    sender(&["check", workdir, s2_path.to_str().unwrap()]);
    let result = read_json(&work.0.join("result.json"));
    assert_eq!(result["slate_id"].as_str().unwrap(), slate_id);
    assert_eq!(result["state"].as_str().unwrap(), "Standard3");
    assert!(result["kernel_verified"].as_bool().unwrap());
}

/// v2 leg: a stock-nostr-sdk payer (today's Goblin, no encryption tag on its
/// 10050) pays; the reply negotiates down to v2 and stock nostr-sdk opens it.
#[tokio::test]
async fn goblin_pays_over_v2_gift_wrap_and_finalizes_the_reply() {
    leg("v2", WrapVersion::V2, None).await;
}

/// v3 leg: a v3-capable payer (advertising `nip44_v3 nip44_v2`) pays with a
/// v3 wrap; the reply negotiates v3 and the payer decrypts it via the nip44
/// crate's context-bound path.
#[tokio::test]
async fn goblin_pays_over_v3_gift_wrap_and_finalizes_the_reply() {
    leg("v3", WrapVersion::V3, Some("nip44_v3 nip44_v2")).await;
}
