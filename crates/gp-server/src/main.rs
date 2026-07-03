//! GoblinPay HTTP server: Actix-Web with in-process rustls TLS (off by
//! default), a zero-JS Askama frontend, the SQLite-backed domain core, and
//! (config-gated) the Nostr ingest service receiving payments over the Nym
//! mixnet.

use std::io;
use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use askama::Template;
use gp_core::config::{Config, Tls};
use gp_nostr::{KeyDirectory, Keys};
use gp_server::directory::{self, DbKeyDirectory};
use gp_server::ingest::WalletReceiver;
use gp_server::payments::{self, ReceiptSigner};
use gp_server::{admin, checkout, invoices, webhookd};
use gp_wallet::GpWallet;

/// Landing page ("GoblinPay").
#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage;

async fn index() -> impl Responder {
    match IndexPage.render() {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(err) => HttpResponse::InternalServerError().body(format!("template error: {err}")),
    }
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// The one hand-written stylesheet, embedded at compile time (zero build step).
async fn style() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(include_str!("../../../static/style.css"))
}

/// The bundled Goblin mark (legacy default QR center logo; still served so an
/// operator can keep `GP_QR_LOGO=/static/goblin-mark.svg`).
async fn goblin_mark() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .body(include_str!("../../../static/goblin-mark.svg"))
}

/// The GoblinPay mark, the default QR center logo (dark "P" on the brand gold,
/// sized for contrast on the QR's white backing).
async fn goblinpay_mark() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .body(include_str!("../../../static/goblinpay-mark.svg"))
}

/// The GoblinPay wordmark (white), shown as the checkout page header logo.
async fn goblinpay_wordmark() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .body(include_str!("../../../static/goblinpay-wordmark.svg"))
}

/// Route table, shared by `main` and the tests.
fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(index))
        .route("/health", web::get().to(health))
        .route("/static/style.css", web::get().to(style))
        .route("/static/goblin-mark.svg", web::get().to(goblin_mark))
        .route("/static/goblinpay-mark.svg", web::get().to(goblinpay_mark))
        .route(
            "/static/goblinpay-wordmark.svg",
            web::get().to(goblinpay_wordmark),
        );
    // Payment status + signed-receipt reads (public-by-token, M4).
    payments::configure(cfg);
    // Hosted checkout + manual slatepack (public-by-token, M5).
    checkout::configure(cfg);
    // Connector invoice API (auth, M5) + admin surface (auth, M5b/M6).
    invoices::configure(cfg);
    admin::configure(cfg);
}

/// Boot the Nostr ingest service (M3): open the wallet, resolve the payment
/// identity, build the multi-identity key directory (M5b), seed the initial
/// watch set, and start the relay listener over Nym on its own thread. Fails
/// fast on misconfiguration. Returns the identity keys (for receipts + invoice
/// derivation) and a clone of the wallet (for the manual-slatepack handler).
async fn start_ingest(cfg: &Config, pool: sqlx::SqlitePool) -> (Keys, GpWallet) {
    let wallet = match GpWallet::open(cfg) {
        Ok(wallet) => wallet,
        Err(e) => {
            eprintln!("wallet error: {e}");
            std::process::exit(2);
        }
    };
    match wallet.slatepack_address() {
        Ok(addr) => println!("wallet ready (slatepack address {addr})"),
        Err(e) => {
            eprintln!("wallet error: {e}");
            std::process::exit(2);
        }
    }

    let keys = match gp_nostr::identity::load_or_create(cfg) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("identity error: {e}");
            std::process::exit(2);
        }
    };
    println!(
        "payment identity ready: {} (advertising `{}`)",
        gp_nostr::npub(&keys),
        gp_nostr::wrap::ENCRYPTION_CAPABILITIES
    );

    if cfg.nym {
        gp_nostr::nym::warm_up();
    }
    let merchant = cfg
        .merchant_npub
        .as_deref()
        .and_then(gp_nostr::pubkey_from_str);
    if cfg.notify_merchant_dm && merchant.is_none() {
        eprintln!("warning: GP_NOTIFY_MERCHANT_DM=on but GP_MERCHANT_NPUB is unset/invalid");
    }
    let opts = gp_nostr::service::ServiceOptions {
        relays: gp_nostr::relays::resolve(cfg.relay_mode, &cfg.bundled_relay_url, &cfg.relays),
        nym: cfg.nym,
        notify: gp_nostr::service::NotifyOptions {
            merchant,
            merchant_dm: cfg.notify_merchant_dm,
            payer_receipt: cfg.notify_payer_receipt,
        },
    };
    let receiver = WalletReceiver::with_matching(
        wallet.clone(),
        pool.clone(),
        cfg.match_mode,
        cfg.webhook_url.clone(),
        cfg.webhook_secret.as_ref().map(|s| s.reveal().to_string()),
    );

    // The DB-backed directory (master + per-invoice + endpub children). Seed
    // its snapshot before the service subscribes so existing derived identities
    // are watched from the start, then keep it fresh (and rotate) in the tick.
    let dir = DbKeyDirectory::new(keys.clone());
    let snapshot = dir.snapshot();
    let initial =
        directory::build_snapshot(&pool, &keys, cfg.match_mode, cfg.endpub_overlap_epochs).await;
    if let Ok(mut guard) = snapshot.write() {
        *guard = initial;
    }
    directory::spawn_maintenance(
        pool.clone(),
        keys.clone(),
        cfg.match_mode,
        cfg.endpub_rotate_interval,
        cfg.endpub_overlap_epochs,
        snapshot,
    );
    let directory: Arc<dyn KeyDirectory> = Arc::new(dir);
    gp_nostr::service::spawn_with_directory(keys.clone(), opts, receiver, directory);
    (keys, wallet)
}

/// Build a rustls server config from PEM certificate-chain and key files.
fn tls_server_config(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, String> {
    let mut cert_reader = io::BufReader::new(
        std::fs::File::open(cert_path)
            .map_err(|e| format!("GP_TLS_CERT `{cert_path}` unreadable: {e}"))?,
    );
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("GP_TLS_CERT `{cert_path}` invalid PEM: {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "GP_TLS_CERT `{cert_path}` contains no certificates"
        ));
    }

    let mut key_reader = io::BufReader::new(
        std::fs::File::open(key_path)
            .map_err(|e| format!("GP_TLS_KEY `{key_path}` unreadable: {e}"))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("GP_TLS_KEY `{key_path}` invalid PEM: {e}"))?
        .ok_or_else(|| format!("GP_TLS_KEY `{key_path}` contains no private key"))?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config rejected: {e}"))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Install the rustls ring provider exactly once, before anything else
    // touches rustls. Shared by sqlx, nostr-sdk, tungstenite, reqwest, and the
    // Nym stack (the Build 65/66 gotcha).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring crypto provider");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(2);
        }
    };
    println!(
        "gp-server {} starting: {}",
        env!("CARGO_PKG_VERSION"),
        cfg.summary()
    );

    let pool = gp_core::db::init(&cfg.db_path)
        .await
        .map_err(io::Error::other)?;
    println!("database ready at {}", cfg.db_path);

    let (signer, wallet_opt): (Option<Keys>, Option<GpWallet>) = if cfg.ingest {
        let (keys, wallet) = start_ingest(&cfg, pool.clone()).await;
        (Some(keys), Some(wallet))
    } else {
        println!("ingest disabled (GP_INGEST=off): serving HTTP only");
        (None, None)
    };

    // Confirmation poll (M4): advances received payments to `confirmed` when
    // their kernel lands. Node reads go DIRECT (never Nym).
    payments::spawn_confirm_poll(pool.clone(), cfg.node_url.clone());

    // Webhook dispatcher (M6): drains the persisted queue with backoff.
    if let Some(secret) = cfg.webhook_secret.as_ref() {
        if cfg.webhook_url.is_some() {
            webhookd::spawn(pool.clone(), secret.reveal().to_string());
        }
    }

    let receipt_signer = ReceiptSigner(signer);
    let cfg_data = web::Data::new(cfg.clone());
    let wallet_data = web::Data::new(wallet_opt);
    // The conversion-rate oracle (M7): shared across workers, prices fiat
    // invoices at create time over DIRECT HTTP (never Nym).
    let oracle_data = web::Data::new(gp_core::rates::Oracle::from_config(&cfg));
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(receipt_signer.clone()))
            .app_data(cfg_data.clone())
            .app_data(wallet_data.clone())
            .app_data(oracle_data.clone())
            .configure(routes)
    });

    match &cfg.tls {
        Tls::Off => {
            println!("listening on http://{}", cfg.bind);
            server.bind(&cfg.bind)?.run().await
        }
        Tls::Rustls { cert, key } => {
            let tls = tls_server_config(cert, key).map_err(io::Error::other)?;
            println!("listening on https://{}", cfg.bind);
            server.bind_rustls_0_23(&cfg.bind, tls)?.run().await
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{test, App};

    use super::*;

    #[actix_web::test]
    async fn health_returns_ok_and_version() {
        let app = test::init_service(App::new().configure(routes)).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    #[actix_web::test]
    async fn index_renders_goblinpay() {
        let app = test::init_service(App::new().configure(routes)).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("GoblinPay"));
        assert!(html.contains("/static/style.css"));
        assert!(!html.contains("<script"));
    }

    #[actix_web::test]
    async fn stylesheet_is_served() {
        let app = test::init_service(App::new().configure(routes)).await;
        let req = test::TestRequest::get()
            .uri("/static/style.css")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let content_type = resp.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().starts_with("text/css"));
    }
}
