//! The grin1 rail's onion transport: an in-process arti Tor client publishing
//! ONE stable onion service whose identity IS the till wallet's index-0
//! slatepack address key, proxying `onion:80 -> 127.0.0.1:<foreign port>`
//! (the loopback Grin Foreign API v2 in [`crate::foreign`]).
//!
//! Because the slatepack (`grin1`) address and a v3 onion address are both just
//! encodings of the same ed25519 public key, a payer's wallet can derive the
//! `.onion` endpoint from the `grin1` address alone: grin1 address == onion
//! address, one key. [`onion_address_from_pubkey`] /
//! [`onion_address_from_seed`] make that equivalence testable.
//!
//! This is a direct port of GRIM's onion-service pattern
//! (`grim/src/tor/tor.rs`): `start_service` (~:507) -> [`spawn`],
//! `run_service_proxy` (~:766) -> the proxy setup inside [`run`], and
//! `add_service_key` (~:819) -> [`add_service_key`], on the same arti 0.43
//! stack. Differences are deliberate scope cuts: no bridges/pluggable
//! transports (a server has no censor to evade), no restart supervisor (the
//! service runs for the process lifetime; systemd restarts the process), and
//! the service identity always comes from the wallet (GRIM also supports
//! keyless services).
//!
//! Arti state/cache/keystore live under `<GP_DATA_DIR>/tor/`; the keystore is
//! arti's default `<state>/keystore`, so the launched service finds the
//! injected HsIdKeypair.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use fs_mistrust::Mistrust;
use log::{error, info};
use safelog::DisplayRedacted;
use sha2::{Digest, Sha512};
use tor_hscrypto::pk::{HsId, HsIdKey, HsIdKeypair};
use tor_hsrproxy::config::{
    Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier, HsNickname};
use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tor_rtcompat::{SleepProviderExt, ToplevelBlockOn};

/// The onion service nickname (keys in the keystore are filed under it).
const NICKNAME: &str = "goblinpay";

/// Bootstrap deadline. First bootstrap downloads the consensus; generous.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);

/// Expand a 32-byte ed25519 seed into tor's expanded keypair form, exactly as
/// GRIM does (and as ed25519 itself defines): `SHA-512(seed)` -> clamped
/// scalar + hash prefix. The seed here is the wallet's index-0 slatepack
/// address secret, so the resulting public key IS the grin1 address key.
fn expanded_keypair(seed: &[u8; 32]) -> ExpandedKeypair {
    let expanded_sk =
        ExpandedSecretKey::from_bytes(Sha512::default().chain_update(seed).finalize().as_ref());
    let mut sk_bytes = [0u8; 64];
    sk_bytes[0..32].copy_from_slice(&expanded_sk.scalar.to_bytes());
    sk_bytes[32..64].copy_from_slice(&expanded_sk.hash_prefix);
    ExpandedKeypair::from_secret_key_bytes(sk_bytes).expect("valid expanded ed25519 key")
}

/// The v3 onion address (`<56 chars>.onion`) for a 32-byte ed25519 seed: the
/// address the onion service launched with that seed publishes. Pure key math,
/// no network; used for the startup log and the equivalence tests.
pub fn onion_address_from_seed(seed: &[u8; 32]) -> String {
    let kp = expanded_keypair(seed);
    let hs_id: HsId = HsIdKey::from(*kp.public()).id();
    let addr = hs_id.display_unredacted().to_string();
    addr
}

/// The v3 onion address for a raw ed25519 public key (32 bytes) — e.g. the key
/// decoded from a `grin1` slatepack address. Same encoding tor itself uses
/// (rend-spec-v3: base32(pubkey || checksum || version) + ".onion").
pub fn onion_address_from_pubkey(pubkey: [u8; 32]) -> String {
    let hs_id = HsId::from(pubkey);
    let addr = hs_id.display_unredacted().to_string();
    addr
}

/// Save the onion service identity to arti's keystore (GRIM's
/// `add_service_key`, ~:819): insert the HsId public key and expanded keypair
/// under the service nickname, overwriting any previous entry so a re-launch
/// with the same wallet is idempotent.
fn add_service_key(
    mistrust: &Mistrust,
    seed: &[u8; 32],
    keystore_dir: &Path,
    nickname: &HsNickname,
) -> Result<(), String> {
    let arti_store = ArtiNativeKeystore::from_path_and_mistrust(keystore_dir, mistrust)
        .map_err(|e| format!("open keystore {keystore_dir:?}: {e}"))?;
    let key_manager = KeyMgrBuilder::default()
        .primary_store(Box::new(arti_store))
        .build()
        .map_err(|e| format!("build key manager: {e}"))?;

    let expanded_kp = expanded_keypair(seed);
    key_manager
        .insert(
            HsIdKey::from(*expanded_kp.public()),
            &HsIdPublicKeySpecifier::new(nickname.clone()),
            KeystoreSelector::Primary,
            true,
        )
        .map_err(|e| format!("insert service public key: {e}"))?;
    key_manager
        .insert(
            HsIdKeypair::from(expanded_kp),
            &HsIdKeypairSpecifier::new(nickname.clone()),
            KeystoreSelector::Primary,
            true,
        )
        .map_err(|e| format!("insert service keypair: {e}"))?;
    Ok(())
}

/// Launch the onion service on a dedicated thread: bootstrap an arti client
/// (state under `<data_dir>/tor/`), inject the wallet seed as the service
/// identity, publish the service, and reverse-proxy `onion:80` to
/// `127.0.0.1:<local_port>`. The returned channel yields exactly one message:
/// `Ok(onion_address)` once the proxy is accepting rendezvous requests (the
/// descriptor upload continues in the background), or `Err(reason)`. The
/// thread then keeps the service alive for the process lifetime.
pub fn spawn(data_dir: PathBuf, seed: [u8; 32], local_port: u16) -> mpsc::Receiver<Result<String, String>> {
    let (tx, rx) = mpsc::channel();
    let tx_err = tx.clone();
    if let Err(e) = thread::Builder::new()
        .name("gp-onion".into())
        .spawn(move || {
            if let Err(e) = run(&data_dir, &seed, local_port, tx) {
                error!("grin1 onion service failed: {e}");
                let _ = tx_err.send(Err(e));
            }
        })
    {
        error!("grin1 onion service thread failed to start: {e}");
    }
    rx
}

/// The onion service body (runs on the dedicated thread, GRIM's
/// `start_service` + `run_service_proxy` combined). Blocks for the process
/// lifetime on the reverse proxy once launched.
fn run(
    data_dir: &Path,
    seed: &[u8; 32],
    local_port: u16,
    tx: mpsc::Sender<Result<String, String>>,
) -> Result<(), String> {
    let tor_dir = data_dir.join("tor");
    let state_dir = tor_dir.join("state");
    let cache_dir = tor_dir.join("cache");
    let keystore_dir = state_dir.join("keystore"); // arti's default keystore location
    fs::create_dir_all(&state_dir).map_err(|e| format!("create {state_dir:?}: {e}"))?;
    fs::create_dir_all(&cache_dir).map_err(|e| format!("create {cache_dir:?}: {e}"))?;
    // arti's fs-mistrust refuses group/world-accessible state (it holds the
    // onion identity key). The gp data dir is already 0700; make the tor tree
    // explicitly so, matching the wallet-dir posture.
    for dir in [&tor_dir, &state_dir, &cache_dir] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {dir:?}: {e}"))?;
    }

    let mut builder = TorClientConfigBuilder::from_directories(&state_dir, &cache_dir);
    builder.address_filter().allow_onion_addrs(true);
    let config = builder.build().map_err(|e| format!("tor config: {e}"))?;

    let nickname =
        HsNickname::new(NICKNAME.into()).map_err(|e| format!("service nickname: {e}"))?;
    add_service_key(config.fs_mistrust(), seed, &keystore_dir, &nickname)?;
    let onion_address = onion_address_from_seed(seed);

    let runtime =
        TokioNativeTlsRuntime::create().map_err(|e| format!("tor runtime: {e}"))?;
    let client = TorClient::with_runtime(runtime.clone())
        .config(config)
        .create_unbootstrapped()
        .map_err(|e| format!("tor client: {e}"))?;

    let proxy_runtime = runtime.clone();
    let timeout_runtime = runtime.clone();
    runtime.block_on(async move {
        info!("grin1 onion: bootstrapping tor (state under {tor_dir:?})");
        timeout_runtime
            .timeout(BOOTSTRAP_TIMEOUT, client.bootstrap())
            .await
            .map_err(|_| format!("tor bootstrap timed out after {BOOTSTRAP_TIMEOUT:?}"))?
            .map_err(|e| format!("tor bootstrap: {e}"))?;

        let service_config = OnionServiceConfigBuilder::default()
            .nickname(nickname.clone())
            .build()
            .map_err(|e| format!("onion service config: {e}"))?;
        let (service, rend_requests) = client
            .launch_onion_service(service_config)
            .map_err(|e| format!("launch onion service: {e}"))?
            .ok_or_else(|| "onion service disabled in arti config".to_string())?;

        // Reverse proxy onion:80 -> 127.0.0.1:local_port (GRIM ~:766).
        let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), local_port);
        let proxy_rule = ProxyRule::new(
            ProxyPattern::one_port(80).expect("port 80 is a valid proxy pattern"),
            ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(addr)),
        );
        let mut proxy_cfg_builder = ProxyConfigBuilder::default();
        proxy_cfg_builder.set_proxy_ports(vec![proxy_rule]);
        let proxy = OnionServiceReverseProxy::new(
            proxy_cfg_builder
                .build()
                .map_err(|e| format!("proxy config: {e}"))?,
        );

        info!(
            "grin1 onion service running: http://{onion_address}/v2/foreign -> \
             127.0.0.1:{local_port} (descriptor publish continues in background)"
        );
        let _ = tx.send(Ok(onion_address.clone()));

        // Drive the proxy for the process lifetime; keep `service` alive (its
        // drop would shut the service down).
        let res = proxy
            .handle_requests(proxy_runtime, nickname.clone(), rend_requests)
            .await;
        drop(service);
        match res {
            Ok(()) => Err("onion service proxy terminated".to_string()),
            Err(e) => Err(format!("onion service proxy failed: {e}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// grin1 address == onion address, one key: derive the onion address from
    /// a REAL wallet's secret seed and, independently, from the ed25519 public
    /// key decoded out of its `grin1` slatepack address. Both encodings must
    /// name the same identity.
    #[test]
    fn onion_address_equals_grin1_address_identity() {
        use rand::RngCore;
        let dir = std::env::temp_dir().join(format!(
            "gp-tor-equiv-{}-{}",
            std::process::id(),
            rand::thread_rng().next_u32()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = grin_keychain::mnemonic::from_entropy(&entropy).unwrap();
        let wallet = gp_wallet::GpWallet::open_at(
            &dir,
            &mnemonic,
            "test-password",
            "http://127.0.0.1:3413",
            grin_core::global::ChainTypes::Mainnet,
        )
        .unwrap();

        let grin1 = wallet.slatepack_address().unwrap();
        assert!(grin1.starts_with("grin1"));
        let seed = wallet.slatepack_secret_seed().unwrap();

        // Path A: seed -> expanded keypair -> onion address (what the service
        // publishes). Path B: grin1 address -> ed25519 pubkey -> onion address.
        let from_seed = onion_address_from_seed(&seed);
        let pubkey = gp_wallet::slatepack_address_pubkey(&grin1).unwrap();
        let from_grin1 = onion_address_from_pubkey(pubkey);

        assert_eq!(
            from_seed, from_grin1,
            "onion identity derived from the wallet seed must equal the onion \
             encoding of the grin1 address"
        );
        assert!(from_seed.ends_with(".onion"));
        assert_eq!(from_seed.len(), 56 + ".onion".len());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The seed expansion matches ed25519: the expanded keypair's public key is
    /// the same key dalek derives from the seed (so tor signs for exactly the
    /// grin1 identity).
    #[test]
    fn expanded_keypair_public_matches_dalek_seed_derivation() {
        use ed25519_dalek::SigningKey;
        let seed = [7u8; 32];
        let kp = expanded_keypair(&seed);
        let dalek_pub = SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(kp.public().to_bytes(), dalek_pub.to_bytes());
    }
}
