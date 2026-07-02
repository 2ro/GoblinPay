//! The DB-backed key directory: resolves an incoming gift wrap's `p` tag to
//! the identity we hold for it (the master key, a per-invoice derived child,
//! or a per-user endpub), and lists the identities to subscribe to.
//!
//! Derived child secrets are never stored: the directory keeps a periodically
//! refreshed snapshot of `pubkey -> secret` computed on the fly from the open
//! derived invoices and the watched endpubs (current + overlap epochs). The
//! same maintenance tick advances endpub rotation, so the watch set rolls
//! forward with the users' clocks.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use gp_core::config::MatchMode;
use gp_core::{derive, endpub};
use gp_nostr::{keys_from_secret, KeyDirectory, Keys, PublicKey};
use log::{info, warn};
use sqlx::SqlitePool;

/// How often the watch set is rebuilt (and rotation advanced).
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Snapshot of derived identities we currently watch: pubkey hex -> secret.
type Snapshot = Arc<RwLock<HashMap<String, [u8; 32]>>>;

/// A directory over the master identity plus a refreshed set of derived
/// children.
pub struct DbKeyDirectory {
    master: Keys,
    master_hex: String,
    snapshot: Snapshot,
}

impl DbKeyDirectory {
    pub fn new(master: Keys) -> DbKeyDirectory {
        let master_hex = master.public_key().to_hex();
        DbKeyDirectory {
            master,
            master_hex,
            snapshot: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// A handle to the shared snapshot, for the maintenance task.
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.clone()
    }
}

impl KeyDirectory for DbKeyDirectory {
    fn resolve(&self, recipient_hex: &str) -> Option<Keys> {
        if recipient_hex == self.master_hex {
            return Some(self.master.clone());
        }
        let secret = *self.snapshot.read().ok()?.get(recipient_hex)?;
        keys_from_secret(&secret).ok()
    }

    fn watched(&self) -> Vec<PublicKey> {
        let mut out = vec![self.master.public_key()];
        if let Ok(snap) = self.snapshot.read() {
            for hex in snap.keys() {
                if let Ok(pk) = PublicKey::from_hex(hex) {
                    out.push(pk);
                }
            }
        }
        out
    }
}

/// Master secret bytes for deriving child keys.
fn master_secret(master: &Keys) -> [u8; 32] {
    master.secret_key().to_secret_bytes()
}

/// Rebuild the derived-identity snapshot from the open derived invoices and the
/// watched endpubs (current + `overlap` epochs).
pub async fn build_snapshot(
    pool: &SqlitePool,
    master: &Keys,
    default_mode: MatchMode,
    overlap: i64,
) -> HashMap<String, [u8; 32]> {
    let sk = master_secret(master);
    let mut map = HashMap::new();

    // Open, derived-mode invoices: recompute each child secret from its id.
    let default = match default_mode {
        MatchMode::Memo => "memo",
        MatchMode::Derived => "derived",
        MatchMode::Amount => "amount",
    };
    let derived_invoices: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, recipient_pubkey FROM invoice \
         WHERE status = 'open' AND COALESCE(match_mode, ?1) = 'derived'",
    )
    .bind(default)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        warn!("directory: derived-invoice scan failed: {e}");
        vec![]
    });
    for (id, recipient) in derived_invoices {
        let pubkey = recipient.unwrap_or_else(|| derive::invoice_pubkey_hex(&sk, &id));
        map.insert(pubkey, derive::invoice_secret(&sk, &id));
    }

    // Watched endpubs (current + overlap epochs) per user.
    match endpub::watched_pubkeys(pool, overlap).await {
        Ok(endpubs) => {
            for ep in endpubs {
                map.insert(ep.pubkey, derive::endpub_secret(&sk, &ep.user_id, ep.epoch));
            }
        }
        Err(e) => warn!("directory: endpub scan failed: {e}"),
    }
    map
}

/// Spawn the maintenance tick on the current (Actix) runtime: advance endpub
/// rotation, then rebuild the watch snapshot. Runs for the process lifetime.
pub fn spawn_maintenance(
    pool: SqlitePool,
    master: Keys,
    default_mode: MatchMode,
    rotate_interval: i64,
    overlap: i64,
    snapshot: Snapshot,
) {
    actix_web::rt::spawn(async move {
        let sk = master_secret(&master);
        loop {
            // Advance any users whose rotation clock elapsed (staggered).
            if rotate_interval > 0 {
                match endpub::rotate_due(&pool, &sk, rotate_interval).await {
                    Ok(n) if n > 0 => info!("endpub: rotated {n} user(s)"),
                    Ok(_) => {}
                    Err(e) => warn!("endpub: rotation tick failed: {e}"),
                }
            }
            let fresh = build_snapshot(&pool, &master, default_mode, overlap).await;
            if let Ok(mut guard) = snapshot.write() {
                *guard = fresh;
            }
            actix_web::rt::time::sleep(REFRESH_INTERVAL).await;
        }
    });
}
