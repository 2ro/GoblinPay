//! In-process Nym mixnet tunnel (ported from `goblin/src/nym/nymproc.rs`).
//! smolmix is linked directly — no sidecar subprocess, no loopback SOCKS5
//! seam. One process-lifetime [`Tunnel`] carries every relay websocket as raw
//! TCP over the mixnet to an AUTO-SELECTED IPR exit gateway: losing any one
//! exit just re-selects, so there is no single-exit SPOF. Hostnames are
//! resolved through the same tunnel by [`super::dns`] (mix-dns); nothing goes
//! clearnet.
//!
//! Same liveness posture as Goblin: a fresh tunnel must pass an end-to-end
//! probe before it is published (some exits accept the IPR handshake but
//! never deliver data), and a keepalive watchdog rebuilds on sustained
//! failure.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::thread;
use std::time::{Duration, Instant};

use log::{error, info, warn};
use smolmix::Tunnel;

/// The shared process-lifetime tunnel, set once the mixnet bootstrap finishes.
static TUNNEL: RwLock<Option<Tunnel>> = RwLock::new(None);

/// Set once the tunnel is up (mirrors `TUNNEL`, but cheap to poll).
static MIXNET_READY: AtomicBool = AtomicBool::new(false);

/// Guards the background bootstrap thread so `warm_up()` is idempotent.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Pre-warm the mixnet tunnel in the background so relays are ready by first
/// use. Idempotent — later calls (including the lazy-init path in
/// [`wait_for_tunnel`]) are no-ops.
pub fn warm_up() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(run_tunnel);
}

/// Whether the mixnet tunnel is warm. Cheap and cached. Distinct from a
/// relay being connected.
pub fn is_ready() -> bool {
    MIXNET_READY.load(Ordering::Relaxed)
}

/// The shared tunnel, if it is up. Cloning is a cheap `Arc` bump.
pub fn tunnel() -> Option<Tunnel> {
    TUNNEL.read().expect("tunnel lock").clone()
}

/// Wait until the shared tunnel is up, starting the bootstrap if nothing has
/// yet (lazy init on first use). Returns `None` once `timeout` lapses.
pub async fn wait_for_tunnel(timeout: Duration) -> Option<Tunnel> {
    warm_up();
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(t) = tunnel() {
            return Some(t);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Build the mixnet tunnel on a dedicated multi-thread tokio runtime, then
/// keep the tunnel (its bridge + smoltcp reactor tasks) AND the runtime alive
/// for the lifetime of the process. Retries with backoff on bootstrap failure
/// (a dead gateway pick just re-selects on the next attempt). Blocks the
/// calling thread.
fn run_tunnel() {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("nym: could not build mixnet runtime: {e}");
            return;
        }
    };
    rt.block_on(async move {
        let mut delay = Duration::from_secs(5);
        loop {
            let started = Instant::now();
            info!("nym: starting in-process mixnet tunnel (smolmix, auto-selected exit)");
            match build_tunnel().await {
                Ok(tunnel) => {
                    // Gate readiness on one end-to-end probe: some exits accept
                    // the IPR handshake but never deliver data (seen live);
                    // publishing such a tunnel would blackhole every consumer
                    // until the watchdog caught it minutes later. Re-select
                    // immediately instead.
                    if !probe_fresh(&tunnel).await {
                        error!(
                            "nym: fresh tunnel failed its liveness probe (dead exit); re-selecting"
                        );
                        tunnel.shutdown().await;
                        delay = (delay * 2).min(Duration::from_secs(60));
                        continue;
                    }
                    info!(
                        "nym: tunnel ready in ~{}ms (allocated ip {}, probe ok)",
                        started.elapsed().as_millis(),
                        tunnel.allocated_ips().ipv4
                    );
                    *TUNNEL.write().expect("tunnel lock") = Some(tunnel.clone());
                    MIXNET_READY.store(true, Ordering::Relaxed);
                    delay = Duration::from_secs(5);
                    // Hold the tunnel warm for the whole process lifetime with
                    // a cheap keepalive: the probe keeps the gateway
                    // connection + IPR session from idling out while the relay
                    // subscription rides it — and verifies the path end to
                    // end. When the tunnel dies anyway (exit gateway gone),
                    // rebuild with a freshly auto-selected exit: losing any
                    // one exit must never take the server down.
                    watch_tunnel(&tunnel).await;
                    error!("nym: tunnel unresponsive; rebuilding with a fresh exit");
                    MIXNET_READY.store(false, Ordering::Relaxed);
                    *TUNNEL.write().expect("tunnel lock") = None;
                    tunnel.shutdown().await;
                }
                Err(e) => {
                    error!(
                        "nym: mixnet tunnel failed to start: {e}; retrying in {}s",
                        delay.as_secs()
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(60));
                }
            }
        }
    });
}

/// Two probe attempts before rejecting a fresh tunnel: mixnet UDP does lose
/// the odd datagram, and one lost packet must not condemn a healthy exit.
async fn probe_fresh(tunnel: &Tunnel) -> bool {
    for _ in 0..2 {
        if super::dns::probe(tunnel).await {
            return true;
        }
    }
    false
}

/// Keepalive period and the consecutive probe failures that declare death.
const KEEPALIVE_PERIOD: Duration = Duration::from_secs(60);
const KEEPALIVE_MAX_FAILS: u32 = 3;

/// Probe the tunnel every [`KEEPALIVE_PERIOD`] (one tiny DNS round trip over
/// the mixnet); returns once [`KEEPALIVE_MAX_FAILS`] probes fail in a row.
async fn watch_tunnel(tunnel: &Tunnel) {
    let mut fails = 0u32;
    loop {
        tokio::time::sleep(KEEPALIVE_PERIOD).await;
        if super::dns::probe(tunnel).await {
            fails = 0;
        } else {
            fails += 1;
            warn!("nym: tunnel keepalive probe failed ({fails}/{KEEPALIVE_MAX_FAILS})");
            if fails >= KEEPALIVE_MAX_FAILS {
                return;
            }
        }
    }
}

/// Build the tunnel with an auto-selected IPR exit. Ephemeral in-memory keys
/// (a fresh mixnet identity per run — no sqlite, no persisted gateway).
///
/// NEVER pin an exit here in shipped code: pinning turns off auto-selection
/// and re-introduces the single-exit SPOF. `GP_NYM_IPR` exists for DEBUGGING
/// only and defaults to unset.
async fn build_tunnel() -> Result<Tunnel, smolmix::SmolmixError> {
    let mut builder = Tunnel::builder();
    if let Ok(pin) = std::env::var("GP_NYM_IPR") {
        if !pin.is_empty() {
            match pin.parse() {
                Ok(recipient) => {
                    warn!("nym: GP_NYM_IPR set — pinning IPR exit (debug only, SPOF!)");
                    builder = builder.ipr_address(recipient);
                }
                Err(e) => warn!("nym: ignoring invalid GP_NYM_IPR: {e}"),
            }
        }
    }
    builder.build().await
}
