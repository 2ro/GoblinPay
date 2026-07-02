//! Milestone-5 checkout tests: the hosted `/pay/<token>` page renders (Askama
//! render + QR), and the manual-slatepack fallback round-trips a REAL S1
//! through gp-wallet's offline `receive_tx` to an S2, recording + matching the
//! payment. The S1 is produced by the gp-goblin-sender subprocess (the same
//! fixture the milestone-2/3 gate uses), so this is an end-to-end proof of the
//! zero-JS manual path with no live network.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use actix_web::{test, web, App};
use gp_core::config::{Config, MatchMode};
use gp_core::invoice::{self, AmountSpec, NewInvoice};
use gp_nostr::Keys;
use gp_server::checkout;
use gp_server::payments::ReceiptSigner;
use gp_wallet::GpWallet;
use rand::RngCore;
use sqlx::SqlitePool;

const AMOUNT: u64 = 2_000_000_000; // 2 grin, nanogrin

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "gp-checkout-{tag}-{}-{}",
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

/// A migrated single-connection in-memory pool.
async fn pool() -> SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    gp_core::db::MIGRATOR.run(&pool).await.unwrap();
    pool
}

fn cfg() -> Config {
    Config {
        public_url: "https://pay.example".into(),
        ..Config::default()
    }
}

/// Run the gp-goblin-sender subprocess (builds a real Goblin-stack S1).
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
            .expect("build gp-goblin-sender");
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
    }
    let out = Command::new(&bin).args(args).output().expect("run sender");
    assert!(
        out.status.success(),
        "sender {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn new_wallet(dir: &Path) -> GpWallet {
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = grin_keychain::mnemonic::from_entropy(&entropy).unwrap();
    GpWallet::open_at(
        dir,
        &mnemonic,
        "checkout-pw",
        "http://127.0.0.1:3413",
        grin_core::global::ChainTypes::Mainnet,
    )
    .unwrap()
}

/// Create a memo-mode invoice receiving on the master identity.
async fn make_invoice(
    pool: &SqlitePool,
    keys: &Keys,
    amount: AmountSpec,
    order_ref: &str,
) -> invoice::Invoice {
    let sk = keys.secret_key().to_secret_bytes();
    let hex = keys.public_key().to_hex();
    invoice::create(
        pool,
        NewInvoice {
            order_ref: Some(order_ref.to_string()),
            amount,
            memo: Some("Coffee".into()),
            match_mode: Some(MatchMode::Memo),
            expiry_secs: None,
        },
        &sk,
        &hex,
        MatchMode::Memo,
    )
    .await
    .unwrap()
}

#[actix_web::test]
async fn pay_page_renders_zero_js_with_qr_and_nprofile() {
    let pool = pool().await;
    let cfg = cfg();
    let keys = Keys::generate();
    let inv = make_invoice(&pool, &keys, AmountSpec::Grin(1_500_000_000), "order-1").await;
    let token = inv.token.clone().unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(cfg.clone()))
            .app_data(web::Data::new(None::<GpWallet>))
            .app_data(web::Data::new(ReceiptSigner(Some(keys.clone()))))
            .configure(checkout::configure),
    )
    .await;

    let req = test::TestRequest::get()
        .uri(&format!("/pay/{token}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let html = std::str::from_utf8(&body).unwrap();

    assert!(html.contains("Pay with Goblin"));
    assert!(html.contains("1.5 GRIN"), "amount shown");
    assert!(html.contains("<svg"), "server-rendered QR present");
    assert!(html.contains("nprofile1"), "nprofile string present");
    assert!(
        !html.contains("Pay by Slatepack"),
        "no wallet loaded: the grin1 Slatepack option is omitted"
    );
    assert!(
        html.contains("http-equiv=\"refresh\""),
        "live status refresh while open"
    );
    assert!(!html.contains("<script"), "zero JS");

    // The status endpoint reports the open invoice.
    let req = test::TestRequest::get()
        .uri(&format!("/pay/{token}/status"))
        .to_request();
    let status: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(status["status"], "open");
    assert_eq!(status["invoice_id"], inv.id);
}

#[actix_web::test]
async fn manual_slatepack_post_round_trips_and_records_payment() {
    let pool = pool().await;
    let cfg = cfg();
    let keys = Keys::generate();

    // A real wallet to receive into, and an amount-matched invoice.
    let wallet_dir = TempDir::new("wallet");
    let wallet = new_wallet(&wallet_dir.0);
    let inv = make_invoice(&pool, &keys, AmountSpec::Grin(AMOUNT), "order-manual").await;
    let token = inv.token.clone().unwrap();

    // A real S1 from the Goblin wallet stack.
    let work = TempDir::new("s1");
    let workdir = work.0.to_str().unwrap();
    sender(&["gen", workdir, &AMOUNT.to_string()]);
    let s1_armor = fs::read_to_string(work.0.join("s1.armor")).unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(cfg.clone()))
            .app_data(web::Data::new(Some(wallet)))
            .app_data(web::Data::new(ReceiptSigner(Some(keys.clone()))))
            .configure(checkout::configure),
    )
    .await;

    let req = test::TestRequest::post()
        .uri(&format!("/pay/{token}/slatepack"))
        .set_form([("slatepack", s1_armor.as_str())])
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let html = std::str::from_utf8(&body).unwrap();

    assert!(html.contains("Payment received"));
    assert!(html.contains("BEGINSLATEPACK."), "S2 rendered to copy back");
    assert!(html.contains("ENDSLATEPACK."));
    assert!(!html.contains("<script"), "zero JS");

    // The payment landed and matched the (memo-mode, amount-carrying) invoice.
    let (status, matched): (String, Option<String>) =
        sqlx::query_as("SELECT status, invoice_id FROM payment LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "received");
    assert_eq!(matched.as_deref(), Some(inv.id.as_str()));
    // And the invoice flipped to paid.
    let paid = invoice::get(&pool, &inv.id).await.unwrap().unwrap();
    assert_eq!(paid.status(), invoice::InvoiceStatus::Paid);
}
