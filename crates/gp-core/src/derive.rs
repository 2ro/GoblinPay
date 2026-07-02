//! Deterministic, stateless child-identity derivation from the server's Nostr
//! secret key.
//!
//! Both matching mode 2 (per-invoice derived identity) and the per-user
//! endpubs of milestone 5b derive a fresh Nostr identity as a child of the
//! server nsec, keyed by a context (the invoice id, or `user_id || epoch`):
//!
//! ```text
//! child_sk = SHA256(master_sk || context)   (retry with a counter if the
//!                                             digest is not a valid scalar)
//! ```
//!
//! This is deliberately derived from the **Nostr** master secret, never the
//! Grin seed (the two-secrets rule, G6): a child identity can decrypt a gift
//! wrap, it can never touch the money. Nothing is stored: any child key
//! recomputes from its context on demand, so the database holds only public
//! keys, assignments, and the rotation clock.
//!
//! The happy path is exactly `SHA256(master_sk || context)`; a one-byte
//! big-endian counter is appended only on the (cryptographically negligible)
//! chance the digest is zero or exceeds the curve order, so derivation stays a
//! pure function of `(master_sk, context)`.

use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// The derived child secret key (32 bytes), guaranteed a valid secp256k1
/// scalar. `context` is the domain material appended after the master key
/// (e.g. the invoice id bytes, or `user_id` bytes followed by the epoch).
pub fn child_secret(master_sk: &[u8; 32], context: &[&[u8]]) -> [u8; 32] {
    // Rejection sampling: hash, and if the digest is not a valid scalar
    // (probability ~2^-128), append an incrementing counter and rehash. The
    // counter is absent on the first, near-certain attempt, so the derivation
    // matches the documented `SHA256(master_sk || context)` exactly.
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(master_sk);
        for part in context {
            hasher.update(part);
        }
        if counter > 0 {
            hasher.update(counter.to_be_bytes());
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if SecretKey::from_byte_array(digest).is_ok() {
            return digest;
        }
    }
    unreachable!("a valid secp256k1 scalar is found within the first few counters")
}

/// The x-only (BIP-340) public key of a derived child, lowercase hex. This is
/// the same 32-byte key a Nostr `npub` encodes, so it compares directly
/// against the `p` tag of an incoming gift wrap.
pub fn child_pubkey_hex(master_sk: &[u8; 32], context: &[&[u8]]) -> String {
    let secret = child_secret(master_sk, context);
    let secp = Secp256k1::new();
    let sk = SecretKey::from_byte_array(secret).expect("child_secret returns a valid scalar");
    let (xonly, _parity) = sk.x_only_public_key(&secp);
    hex::encode(xonly.serialize())
}

/// Context for a per-invoice derived identity (matching mode 2):
/// `SHA256(master_sk || invoice_id)`.
pub fn invoice_context(invoice_id: &str) -> Vec<Vec<u8>> {
    vec![invoice_id.as_bytes().to_vec()]
}

/// Context for a per-user endpub (milestone 5b):
/// `SHA256(master_sk || user_id || epoch)` with the epoch big-endian.
pub fn endpub_context(user_id: &str, epoch: i64) -> Vec<Vec<u8>> {
    vec![user_id.as_bytes().to_vec(), epoch.to_be_bytes().to_vec()]
}

/// Derive the child secret for an invoice.
pub fn invoice_secret(master_sk: &[u8; 32], invoice_id: &str) -> [u8; 32] {
    let ctx = invoice_context(invoice_id);
    let parts: Vec<&[u8]> = ctx.iter().map(|p| p.as_slice()).collect();
    child_secret(master_sk, &parts)
}

/// Derive the child x-only pubkey hex for an invoice.
pub fn invoice_pubkey_hex(master_sk: &[u8; 32], invoice_id: &str) -> String {
    let ctx = invoice_context(invoice_id);
    let parts: Vec<&[u8]> = ctx.iter().map(|p| p.as_slice()).collect();
    child_pubkey_hex(master_sk, &parts)
}

/// Derive the child secret for a user's endpub at a given epoch.
pub fn endpub_secret(master_sk: &[u8; 32], user_id: &str, epoch: i64) -> [u8; 32] {
    let ctx = endpub_context(user_id, epoch);
    let parts: Vec<&[u8]> = ctx.iter().map(|p| p.as_slice()).collect();
    child_secret(master_sk, &parts)
}

/// Derive the child x-only pubkey hex for a user's endpub at a given epoch.
pub fn endpub_pubkey_hex(master_sk: &[u8; 32], user_id: &str, epoch: i64) -> String {
    let ctx = endpub_context(user_id, epoch);
    let parts: Vec<&[u8]> = ctx.iter().map(|p| p.as_slice()).collect();
    child_pubkey_hex(master_sk, &parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = [7u8; 32];

    #[test]
    fn derivation_is_deterministic_and_stateless() {
        // Same inputs, same key — every time, with no stored state.
        let a = invoice_secret(&MASTER, "inv-abc");
        let b = invoice_secret(&MASTER, "inv-abc");
        assert_eq!(a, b);
        assert_eq!(
            invoice_pubkey_hex(&MASTER, "inv-abc"),
            invoice_pubkey_hex(&MASTER, "inv-abc")
        );
    }

    #[test]
    fn distinct_contexts_yield_distinct_keys() {
        assert_ne!(
            invoice_secret(&MASTER, "inv-1"),
            invoice_secret(&MASTER, "inv-2")
        );
        // Per-user, per-epoch keys are all distinct.
        assert_ne!(
            endpub_secret(&MASTER, "alice", 0),
            endpub_secret(&MASTER, "alice", 1)
        );
        assert_ne!(
            endpub_secret(&MASTER, "alice", 0),
            endpub_secret(&MASTER, "bob", 0)
        );
        // And an invoice context never collides with an endpub context of the
        // same textual prefix (the epoch bytes keep them apart).
        assert_ne!(
            invoice_pubkey_hex(&MASTER, "alice"),
            endpub_pubkey_hex(&MASTER, "alice", 0)
        );
    }

    #[test]
    fn a_different_master_gives_a_different_child() {
        let other = [9u8; 32];
        assert_ne!(
            invoice_secret(&MASTER, "inv-abc"),
            invoice_secret(&other, "inv-abc")
        );
    }

    #[test]
    fn derived_secret_is_a_valid_scalar_and_pubkey_is_32_hex_bytes() {
        let secret = endpub_secret(&MASTER, "carol", 3);
        assert!(SecretKey::from_byte_array(secret).is_ok());
        let pk = endpub_pubkey_hex(&MASTER, "carol", 3);
        assert_eq!(pk.len(), 64, "x-only pubkey is 32 bytes = 64 hex chars");
        assert!(hex::decode(&pk).is_ok());
        // The pubkey matches an independent recomputation of the secret.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_byte_array(secret).unwrap();
        let (xonly, _) = sk.x_only_public_key(&secp);
        assert_eq!(pk, hex::encode(xonly.serialize()));
    }
}
