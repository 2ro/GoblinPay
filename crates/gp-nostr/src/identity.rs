//! The server's Nostr payment identity: a random standalone nsec or an
//! imported one, NEVER derived from the Grin mnemonic (the two-secrets rule:
//! the mnemonic is the money secret, the nsec is the payment identity; losing
//! one must never compromise or resurrect the other). Mirrors Goblin's
//! `nostr/identity.rs`, trimmed to what a headless daemon needs.
//!
//! Resolution order (see [`load_or_create`]):
//! 1. `GP_NSEC` — plaintext key from the environment (mounted-file variant
//!    supported by gp-core). Used as-is, never persisted.
//! 2. `GP_NCRYPTSEC` — NIP-49 encrypted key, unlocked with the wallet
//!    password. Never persisted.
//! 3. Neither set — load `<data_dir>/nostr/identity.json`, or generate a
//!    fresh RANDOM key and persist it NIP-49 encrypted (wallet password),
//!    file mode 0600.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use gp_core::config::Config;
use nostr_sdk::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr_sdk::{FromBech32, Keys, SecretKey, ToBech32};
use serde::{Deserialize, Serialize};

/// NIP-49 scrypt work factor (~64 MiB, interactive-grade; same as Goblin).
const NCRYPTSEC_LOG_N: u8 = 16;

/// Identity file stored at `<data_dir>/nostr/identity.json`. Only the
/// encrypted key and the public key: a headless till has no NIP-05 name, no
/// contact metadata.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerIdentity {
    pub ver: u8,
    /// NIP-49 encrypted secret key (bech32 ncryptsec).
    pub ncryptsec: String,
    /// Public key, bech32 npub (plaintext for logs and the QR).
    pub npub: String,
}

#[derive(Debug)]
pub enum IdentityError {
    /// Missing or inconsistent configuration (fail fast at startup).
    Config(String),
    /// Key parse/encrypt/decrypt failure (includes wrong password).
    Key(String),
    /// Filesystem failure persisting or reading the identity file.
    Io(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Config(m) => write!(f, "identity config error: {m}"),
            IdentityError::Key(m) => write!(f, "identity key error: {m}"),
            IdentityError::Io(m) => write!(f, "identity io error: {m}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl ServerIdentity {
    pub const FILE_NAME: &'static str = "identity.json";

    /// Identity file path for a data dir.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("nostr").join(Self::FILE_NAME)
    }

    /// Load the identity file if it exists and parses.
    pub fn load(data_dir: &Path) -> Option<ServerIdentity> {
        let raw = fs::read_to_string(Self::path(data_dir)).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Persist with owner-only permissions (the ncryptsec blob must not be
    /// world readable: a local attacker could grind the password offline).
    pub fn save(&self, data_dir: &Path) -> Result<(), IdentityError> {
        let dir = data_dir.join("nostr");
        fs::create_dir_all(&dir).map_err(|e| IdentityError::Io(format!("create {dir:?}: {e}")))?;
        restrict(&dir, 0o700)?;
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| IdentityError::Io(format!("serialize identity: {e}")))?;
        let path = Self::path(data_dir);
        fs::write(&path, raw).map_err(|e| IdentityError::Io(format!("write {path:?}: {e}")))?;
        restrict(&path, 0o600)?;
        Ok(())
    }

    /// Unlock the stored key with the wallet password.
    pub fn unlock(&self, password: &str) -> Result<Keys, IdentityError> {
        decrypt_ncryptsec(&self.ncryptsec, password)
    }

    fn from_keys(keys: &Keys, password: &str) -> Result<ServerIdentity, IdentityError> {
        let encrypted = EncryptedSecretKey::new(
            keys.secret_key(),
            password,
            NCRYPTSEC_LOG_N,
            KeySecurity::Medium,
        )
        .map_err(|e| IdentityError::Key(format!("encrypt failed: {e}")))?;
        Ok(ServerIdentity {
            ver: 1,
            ncryptsec: encrypted
                .to_bech32()
                .map_err(|e| IdentityError::Key(format!("bech32 failed: {e}")))?,
            npub: keys
                .public_key()
                .to_bech32()
                .map_err(|e| IdentityError::Key(format!("bech32 failed: {e}")))?,
        })
    }
}

/// Resolve the identity keys from the configuration (see the module doc for
/// the order). Fails fast on a missing wallet password whenever the at-rest
/// encryption needs one.
pub fn load_or_create(cfg: &Config) -> Result<Keys, IdentityError> {
    // 1. Plaintext nsec from the environment: authoritative, not persisted.
    if let Some(nsec) = &cfg.nsec {
        let secret = SecretKey::parse(nsec.reveal().trim())
            .map_err(|e| IdentityError::Key(format!("invalid GP_NSEC: {e}")))?;
        return Ok(Keys::new(secret));
    }

    let password = cfg
        .wallet_password
        .as_ref()
        .ok_or_else(|| {
            IdentityError::Config(
                "GP_WALLET_PASSWORD (or _FILE) is required to unlock or persist the \
                 Nostr identity (set GP_NSEC to bypass at-rest encryption)"
                    .into(),
            )
        })?
        .reveal()
        .to_string();

    // 2. NIP-49 encrypted key from the environment: unlocked, not persisted.
    if let Some(ncryptsec) = &cfg.ncryptsec {
        return decrypt_ncryptsec(ncryptsec.reveal().trim(), &password);
    }

    // 3. Persisted identity, or a fresh RANDOM key (never seed-derived).
    let data_dir = Path::new(&cfg.data_dir);
    if let Some(identity) = ServerIdentity::load(data_dir) {
        return identity.unlock(&password);
    }
    let keys = Keys::generate();
    ServerIdentity::from_keys(&keys, &password)?.save(data_dir)?;
    Ok(keys)
}

fn decrypt_ncryptsec(ncryptsec: &str, password: &str) -> Result<Keys, IdentityError> {
    let encrypted = EncryptedSecretKey::from_bech32(ncryptsec)
        .map_err(|e| IdentityError::Key(format!("invalid ncryptsec: {e}")))?;
    let secret = encrypted
        .decrypt(password)
        .map_err(|_| IdentityError::Key("wrong password for ncryptsec".into()))?;
    Ok(Keys::new(secret))
}

/// chmod, failing fast (Unix only; the daemon targets Linux servers).
fn restrict(path: &Path, mode: u32) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| IdentityError::Io(format!("chmod {path:?}: {e}")))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use gp_core::config::Secret;

    use super::*;

    /// Self-cleaning unique temp dir (no extra dev-deps).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "gp-nostr-id-{tag}-{}-{}",
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

    fn cfg(dir: &TempDir) -> Config {
        Config {
            data_dir: dir.0.to_str().unwrap().to_string(),
            wallet_password: Some(Secret::new("hunter2".into())),
            ..Config::default()
        }
    }

    #[test]
    fn generates_persists_and_reloads_the_same_key() {
        let dir = TempDir::new("gen");
        let cfg = cfg(&dir);
        let first = load_or_create(&cfg).unwrap();
        let second = load_or_create(&cfg).unwrap();
        assert_eq!(first.public_key(), second.public_key());

        // Encrypted at rest: no bech32 nsec in the file.
        let raw = fs::read_to_string(ServerIdentity::path(&dir.0)).unwrap();
        let nsec = first.secret_key().to_bech32().unwrap();
        assert!(!raw.contains(&nsec), "identity file leaks the nsec");
        assert!(raw.contains("ncryptsec1"), "key must be NIP-49 encrypted");
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("perm");
        load_or_create(&cfg(&dir)).unwrap();
        let meta = fs::metadata(ServerIdentity::path(&dir.0)).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o077,
            0,
            "identity.json must be 0600"
        );
    }

    #[test]
    fn wrong_password_fails_and_never_regenerates() {
        let dir = TempDir::new("wrongpw");
        let mut c = cfg(&dir);
        let keys = load_or_create(&c).unwrap();
        c.wallet_password = Some(Secret::new("not-it".into()));
        // A wrong password must be a hard error, not a silent fresh identity
        // (payers hold the old npub; regenerating would strand their sends).
        assert!(load_or_create(&c).is_err());
        c.wallet_password = Some(Secret::new("hunter2".into()));
        assert_eq!(load_or_create(&c).unwrap().public_key(), keys.public_key());
    }

    #[test]
    fn imports_nsec_without_persisting() {
        let dir = TempDir::new("nsec");
        let external = Keys::generate();
        let mut c = cfg(&dir);
        c.nsec = Some(Secret::new(external.secret_key().to_bech32().unwrap()));
        c.wallet_password = None; // not needed on this path
        let keys = load_or_create(&c).unwrap();
        assert_eq!(keys.public_key(), external.public_key());
        assert!(
            !ServerIdentity::path(&dir.0).exists(),
            "env-provided keys must not be written to disk"
        );
    }

    #[test]
    fn imports_ncryptsec_from_env() {
        let dir = TempDir::new("ncryptsec");
        let external = Keys::generate();
        let encrypted = EncryptedSecretKey::new(
            external.secret_key(),
            "hunter2",
            NCRYPTSEC_LOG_N,
            KeySecurity::Medium,
        )
        .unwrap();
        let mut c = cfg(&dir);
        c.ncryptsec = Some(Secret::new(encrypted.to_bech32().unwrap()));
        let keys = load_or_create(&c).unwrap();
        assert_eq!(keys.public_key(), external.public_key());
        assert!(!ServerIdentity::path(&dir.0).exists());
    }

    #[test]
    fn missing_password_fails_fast() {
        let dir = TempDir::new("nopw");
        let mut c = cfg(&dir);
        c.wallet_password = None;
        let err = load_or_create(&c).unwrap_err();
        assert!(err.to_string().contains("GP_WALLET_PASSWORD"), "{err}");
    }

    #[test]
    fn random_identities_are_independent() {
        // Fresh entropy every time — nothing chains identities to each other
        // (or to any wallet seed; there is no derivation path at all).
        let a = load_or_create(&cfg(&TempDir::new("ind-a"))).unwrap();
        let b = load_or_create(&cfg(&TempDir::new("ind-b"))).unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }
}
