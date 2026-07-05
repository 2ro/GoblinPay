//! GoblinPay HTTP server: Actix-Web with in-process rustls TLS (off by
//! default), a zero-JS Askama frontend, the SQLite-backed domain core, and
//! (config-gated) the Nostr ingest service receiving payments over Nostr.

use std::io;
use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use askama::Template;
use gp_core::config::{Config, Tls};
use gp_nostr::{KeyDirectory, Keys};
use gp_server::directory::{self, DbKeyDirectory};
use gp_server::ingest::WalletReceiver;
use gp_server::payments::{self, ReceiptSigner};
use gp_server::{admin, checkout, foreign, invoices, tor, webhookd};
use gp_wallet::GpWallet;

/// Landing page ("GoblinPay").
#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    /// Mount path prefix for root-relative asset links, so the landing page
    /// works when the till is reverse-proxied on a path (zero new DNS records).
    base: String,
}

async fn index(cfg: web::Data<Config>) -> impl Responder {
    match (IndexPage {
        base: gp_core::setup::base_path(&cfg.public_url),
    })
    .render()
    {
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

/// The black GoblinPay badge (goblin mark + "Pay"), Apple Pay style. The
/// light-surface counterpart to the white wordmark: a compact payment-method
/// mark for connector checkout rows and light pay-page surfaces.
async fn goblinpay_badge_black() -> impl Responder {
    HttpResponse::Ok()
        .content_type("image/svg+xml")
        .body(include_str!("../../../static/goblinpay-badge-black.svg"))
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
        )
        .route(
            "/static/goblinpay-badge-black.svg",
            web::get().to(goblinpay_badge_black),
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
/// watch set, and start the relay listener on its own thread. Fails
/// fast on misconfiguration. Returns the identity keys (for receipts + invoice
/// derivation) and a clone of the wallet (for the manual-slatepack handler).
async fn start_ingest(cfg: &Config, pool: sqlx::SqlitePool) -> (Keys, GpWallet) {
    // Init-once: whether the encrypted seed already exists decides if the
    // mnemonic is still needed. Check before opening (open creates it on first
    // run), so we can nudge the operator to remove a now-redundant seed.
    let was_initialized = GpWallet::seed_path(std::path::Path::new(&cfg.data_dir)).exists();
    let wallet = match GpWallet::open(cfg) {
        Ok(wallet) => wallet,
        Err(e) => {
            eprintln!("wallet error: {e}");
            std::process::exit(2);
        }
    };
    if was_initialized && cfg.mnemonic.is_some() {
        eprintln!(
            "warning: the wallet at {} is already initialized, so GP_MNEMONIC is \
             no longer needed. Remove it (and GP_MNEMONIC_FILE) so the seed is not \
             present in this service's environment on every boot; keep only \
             GP_WALLET_PASSWORD. The seed lives encrypted at rest in the data dir.",
            cfg.data_dir
        );
    }
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

    let merchant = cfg
        .merchant_npub
        .as_deref()
        .and_then(gp_nostr::pubkey_from_str);
    if cfg.notify_merchant_dm && merchant.is_none() {
        eprintln!("warning: GP_NOTIFY_MERCHANT_DM=on but GP_MERCHANT_NPUB is unset/invalid");
    }
    let opts = gp_nostr::service::ServiceOptions {
        relays: gp_nostr::relays::resolve(cfg.relay_mode, &cfg.bundled_relay_url, &cfg.relays),
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

/// Run the interactive setup wizard (`gp-server setup [flags]`) and exit,
/// before any of the async server machinery starts. Argv is parsed by hand (no
/// clap), matching `gp-goblin-sender`'s convention. Returns the process exit
/// code.
fn run_setup(args: &[String]) -> i32 {
    use std::io::IsTerminal;
    use std::path::PathBuf;

    use gp_server::setup::{self, SetupOptions};

    let mut opts = SetupOptions {
        reconfigure: false,
        prefix: None,
        node_override: None,
        force_run: false,
        stdin_is_tty: std::io::stdin().is_terminal(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reconfigure" => opts.reconfigure = true,
            "--batch" => opts.force_run = true,
            "--prefix" => {
                i += 1;
                match args.get(i) {
                    Some(p) => opts.prefix = Some(PathBuf::from(p)),
                    None => {
                        eprintln!("--prefix needs a directory argument");
                        return 2;
                    }
                }
            }
            "--node" => {
                i += 1;
                match args.get(i) {
                    Some(u) => opts.node_override = Some(u.clone()),
                    None => {
                        eprintln!("--node needs a URL argument");
                        return 2;
                    }
                }
            }
            other => {
                eprintln!("unknown setup flag `{other}`");
                eprintln!(
                    "usage: gp-server setup [--reconfigure] [--prefix DIR] [--node URL] [--batch]"
                );
                return 2;
            }
        }
        i += 1;
    }

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    match setup::run(stdin.lock(), &mut stdout, &opts) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("setup: {e}");
            1
        }
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Subcommand branch (manual argv, no clap): `gp-server setup` runs the
    // onboarding wizard and exits before the Actix server boots. Any other
    // invocation falls through to the normal server startup below.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("setup") {
        std::process::exit(run_setup(&argv[2..]));
    }

    // Install the rustls ring provider exactly once, before anything else
    // touches rustls. Shared by sqlx, nostr-sdk, tungstenite, and reqwest.
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
    // their kernel lands, and advances the paying invoice `paid` -> `confirmed`
    // once it reaches GP_CONFIRMATIONS depth (firing a payment.confirmed
    // webhook). Node reads go DIRECT (never Nym).
    payments::spawn_confirm_poll(
        pool.clone(),
        cfg.node_url.clone(),
        payments::ConfirmPolicy::from_config(&cfg),
    );

    // Webhook dispatcher (M6): drains the persisted queue with backoff.
    if let Some(secret) = cfg.webhook_secret.as_ref() {
        if cfg.webhook_url.is_some() {
            webhookd::spawn(pool.clone(), secret.reveal().to_string());
        }
    }

    let receipt_signer = ReceiptSigner(signer);
    let cfg_data = web::Data::new(cfg.clone());
    let wallet_data = web::Data::new(wallet_opt);

    // grin1 rail (Phase 1): the Grin Foreign API v2 on loopback, plus the
    // in-process arti onion service proxying onion:80 -> 127.0.0.1:<port>.
    // Only started when the rail is armed and a wallet is loaded; a stock Grin
    // sender's receive/finalize lands here over Tor. The wallet's index-0
    // slatepack address key IS the onion identity, so grin1 address == onion
    // address (one key, two encodings).
    if cfg.grin1_rail {
        if let Some(wallet) = wallet_data.get_ref().as_ref() {
            // Expiry sweep: cancel the stored context of expired grin1 invoices
            // so a late payer I2 cannot settle an expired invoice.
            foreign::spawn_expiry_cancel(pool.clone(), wallet.clone());

            let foreign_bind = format!("127.0.0.1:{}", cfg.grin1_foreign_port);
            let pool_f = pool.clone();
            let cfg_f = cfg_data.clone();
            let wallet_f = wallet_data.clone();
            match HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(pool_f.clone()))
                    .app_data(cfg_f.clone())
                    .app_data(wallet_f.clone())
                    .configure(foreign::configure)
            })
            .bind(&foreign_bind)
            {
                Ok(srv) => {
                    println!("grin1 Foreign API v2 listening on http://{foreign_bind}/v2/foreign");
                    actix_web::rt::spawn(srv.run());

                    // The onion transport: arti state/keystore under the data
                    // dir, service identity = the wallet's index-0 address key.
                    match wallet.slatepack_secret_seed() {
                        Ok(seed) => {
                            let onion = tor::onion_address_from_seed(&seed);
                            println!(
                                "grin1 onion identity: http://{onion}/v2/foreign \
                                 (same key as the grin1 slatepack address; bootstrapping tor)"
                            );
                            let rx = tor::spawn(
                                std::path::PathBuf::from(&cfg.data_dir),
                                seed,
                                cfg.grin1_foreign_port,
                            );
                            // Report the launch outcome without blocking boot.
                            std::thread::spawn(move || match rx.recv() {
                                Ok(Ok(addr)) => {
                                    println!("grin1 onion service running at http://{addr}")
                                }
                                Ok(Err(e)) => eprintln!("grin1 onion service failed: {e}"),
                                Err(_) => {
                                    eprintln!("grin1 onion service exited before reporting")
                                }
                            });
                        }
                        Err(e) => eprintln!("grin1: cannot read onion identity key: {e}"),
                    }
                }
                Err(e) => eprintln!("grin1 Foreign API bind {foreign_bind} failed: {e}"),
            }
        } else {
            println!("grin1 rail armed but no wallet loaded: Foreign API not started");
        }
    }
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
        // The index handler reads Config (for the mount-path prefix), so provide
        // a default one as app data.
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(Config::default()))
                .configure(routes),
        )
        .await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("GoblinPay"));
        // Default (root) mount: the prefix is empty, so assets stay root-relative.
        assert!(html.contains("/static/style.css"));
        assert!(!html.contains("<script"));
    }

    #[actix_web::test]
    async fn index_respects_path_prefix() {
        // Path hosting (GP_PUBLIC_URL with a path) prefixes asset links so a
        // reverse-proxied path mount works with zero new DNS records.
        let cfg = Config {
            public_url: "https://myshop.com/pay".into(),
            ..Config::default()
        };
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(cfg))
                .configure(routes),
        )
        .await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        let body = test::read_body(resp).await;
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("/pay/static/style.css"), "asset link is prefixed");
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
