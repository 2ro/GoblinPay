//! REAL Tor round trip for the grin1 rail's onion transport (Phase 1 gate):
//!
//!   1. serve the REAL Foreign API v2 handler (`gp_server::foreign`) on a
//!      loopback port (no wallet: `check_version` needs none),
//!   2. launch the in-process arti onion service with a THROWAWAY key,
//!      proxying onion:80 -> that port (`gp_server::tor`, the GRIM port),
//!   3. from a SEPARATE arti client (own state dirs), dial the `.onion` over
//!      the real Tor network and POST a JSON-RPC `check_version`,
//!   4. assert the reply envelope (`result.foreign_api_version == 2`).
//!
//! Network-bound and slow (bootstrap + descriptor publish can take minutes),
//! so `#[ignore]`d out of the normal suite. Run once per change to the tor
//! module:
//!
//!   CARGO_TARGET_DIR=~/.cache/gp_target \
//!     cargo test -p gp-server --test tor_roundtrip -- --ignored --nocapture

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use actix_web::{web, App, HttpServer};
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tor_rtcompat::ToplevelBlockOn;

/// Total deadline for the onion round trip once the service reports running
/// (descriptor publish + client fetch). Generous: fresh v3 descriptors can
/// take a couple of minutes to become fetchable.
const ROUNDTRIP_DEADLINE: Duration = Duration::from_secs(600);
/// Pause between dial attempts while the descriptor propagates.
const RETRY_PAUSE: Duration = Duration::from_secs(15);

/// A free loopback port (bind :0, read, drop).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Serve the real Foreign API app (no wallet) on `port`, on its own thread.
fn serve_foreign(port: u16) {
    thread::spawn(move || {
        actix_web::rt::System::new().block_on(async move {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .expect("open in-memory sqlite");
            gp_core::db::MIGRATOR.run(&pool).await.expect("migrate");
            HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(pool.clone()))
                    .app_data(web::Data::new(gp_core::config::Config::default()))
                    .app_data(web::Data::new(None::<gp_wallet::GpWallet>))
                    .configure(gp_server::foreign::configure)
            })
            .bind(("127.0.0.1", port))
            .expect("bind foreign port")
            .run()
            .await
            .expect("foreign server run");
        });
    });
}

/// One dial attempt: connect to `onion:80` through `client`, POST the JSON-RPC
/// `check_version` request to `/v2/foreign`, and return the response body.
async fn post_check_version(
    client: &TorClient<TokioNativeTlsRuntime>,
    onion: &str,
) -> Result<String, String> {
    let stream = client
        .connect((onion, 80))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"check_version","params":[]}"#;
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("http://{onion}/v2/foreign"))
        .header("content-type", "application/json")
        .header("host", onion)
        .body(Full::<Bytes>::from(body))
        .map_err(|e| format!("request build: {e}"))?;
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes).to_string();
    if !status.is_success() {
        return Err(format!("http {status}: {text}"));
    }
    Ok(text)
}

#[test]
#[ignore = "real Tor network round trip; run explicitly with -- --ignored"]
fn onion_roundtrip_check_version_over_real_tor() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,tor_proto=warn,tor_chanmgr=warn"),
    )
    .is_test(false)
    .try_init();

    // Under $HOME, not /tmp: arti's fs-mistrust rejects state dirs with a
    // world-writable ancestor (/tmp is 1777).
    let home = std::env::var("HOME").expect("HOME set");
    let tmp = std::path::PathBuf::from(home)
        .join(".cache")
        .join(format!("gp-tor-roundtrip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // 1. The real Foreign API on a loopback port.
    let port = free_port();
    serve_foreign(port);

    // 2. The onion service with a throwaway key (NOT a wallet key).
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut seed);
    let expected_onion = gp_server::tor::onion_address_from_seed(&seed);
    println!("throwaway onion identity: {expected_onion}");

    let rx: mpsc::Receiver<Result<String, String>> =
        gp_server::tor::spawn(tmp.join("svc"), seed, port);
    let onion = rx
        .recv_timeout(Duration::from_secs(420))
        .expect("onion service reported nothing within 7 minutes")
        .expect("onion service failed to launch");
    assert_eq!(
        onion, expected_onion,
        "published onion address must equal the seed-derived one"
    );
    println!("onion service up: http://{onion}/v2/foreign");

    // 3. A separate arti client dials the onion over the real network.
    let client_state = tmp.join("client/state");
    let client_cache = tmp.join("client/cache");
    std::fs::create_dir_all(&client_state).unwrap();
    std::fs::create_dir_all(&client_cache).unwrap();
    // fs-mistrust wants private state dirs (0700), like the service side.
    for d in [
        tmp.join("client"),
        client_state.clone(),
        client_cache.clone(),
    ] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut builder = TorClientConfigBuilder::from_directories(&client_state, &client_cache);
    builder.address_filter().allow_onion_addrs(true);
    let config = builder.build().expect("client tor config");

    let runtime = TokioNativeTlsRuntime::create().expect("client runtime");
    let rt = runtime.clone();
    let body = runtime.block_on(async move {
        let client = tokio::time::timeout(
            Duration::from_secs(300),
            TorClient::with_runtime(rt)
                .config(config)
                .create_bootstrapped(),
        )
        .await
        .expect("client bootstrap timed out")
        .expect("client bootstrap failed");
        println!("client bootstrapped; dialing the onion (descriptor may still be publishing)");

        // Bounded retry loop while the fresh descriptor propagates.
        let deadline = Instant::now() + ROUNDTRIP_DEADLINE;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match post_check_version(&client, &onion).await {
                Ok(body) => break body,
                Err(e) => {
                    println!("attempt {attempt}: {e}");
                    assert!(
                        Instant::now() < deadline,
                        "onion round trip did not succeed within {ROUNDTRIP_DEADLINE:?} \
                         (last error: {e})"
                    );
                    tokio::time::sleep(RETRY_PAUSE).await;
                }
            }
        }
    });

    // 4. The JSON-RPC reply is the real Foreign API check_version envelope.
    println!("onion round-trip response: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON-RPC reply");
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 1);
    assert_eq!(
        v["result"]["foreign_api_version"], 2,
        "check_version over the onion returns the Foreign API v2 envelope"
    );
    assert!(v["result"]["supported_slate_versions"].is_array());

    let _ = std::fs::remove_dir_all(&tmp);
}
