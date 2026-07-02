//! Server-signed payment receipt: the DM-less trust primitive.
//!
//! A [`Receipt`] bundles what a store needs to trust a payment without relying
//! on a webhook payload or a DM: the payment id, amount, the on-chain kernel
//! excess, the confirmation height, and (when present) the receiver-side Grin
//! payment proof. [`sign_receipt`] signs it with the server's Nostr identity
//! key (BIP-340 Schnorr over SHA-256 of the canonical JSON, the same signature
//! scheme Nostr events use), producing a [`SignedReceipt`] any party can verify
//! against the server's known public key with [`verify_receipt`].
//!
//! The receipt is a plain serde object, independent of Nostr event framing, so
//! a store backend (Eranos, WooCommerce, ...) can verify it with any BIP-340
//! implementation. It is safe to expose publicly: it reveals only what the
//! payer already told the merchant, and it is self-authenticating.

use nostr_sdk::Keys;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use serde::{Deserialize, Serialize};

/// Current receipt schema version.
pub const RECEIPT_VERSION: u8 = 1;

/// The signed payload. Field order is fixed (serde serializes structs in
/// declaration order with no whitespace), so signer and verifier hash exactly
/// the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Schema version (`1`).
    pub version: u8,
    /// Payment identifier (the Grin slate UUID; also the public status token).
    pub payment_id: String,
    /// Amount in nanogrin.
    pub amount: u64,
    /// Tx kernel excess commitment, hex — the on-chain anchor.
    pub kernel_excess: String,
    /// Block height the kernel confirmed at, if confirmed.
    pub confirmed_height: Option<u64>,
    /// Confirmation depth at issue time, if confirmed.
    pub confirmations: Option<u64>,
    /// The receiver-side Grin payment proof (as its own JSON object), when the
    /// payer requested one. A store can verify this independently.
    pub proof: Option<serde_json::Value>,
    /// Issue time, ISO-8601 UTC.
    pub issued_at: String,
    /// The server identity npub-hex (x-only) this receipt is about. Bound into
    /// the signature so a receipt cannot be replayed under another identity.
    pub server_pubkey: String,
}

/// A [`Receipt`] plus the server's BIP-340 Schnorr signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    /// The signed payload.
    pub receipt: Receipt,
    /// Signature, hex (64 bytes).
    pub sig: String,
}

/// Receipt signing/verification errors.
#[derive(Debug)]
pub enum ReceiptError {
    /// The identity secret key could not be used for signing.
    Key(String),
    /// Canonical serialization failed.
    Serialize(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::Key(m) => write!(f, "receipt key error: {m}"),
            ReceiptError::Serialize(m) => write!(f, "receipt serialize error: {m}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

/// Sign a receipt with the server identity keys. The receipt's `server_pubkey`
/// is overwritten with the signer's x-only key so the object is internally
/// consistent regardless of what the caller passed.
pub fn sign_receipt(keys: &Keys, mut receipt: Receipt) -> Result<SignedReceipt, ReceiptError> {
    let sk = SecretKey::from_byte_array(keys.secret_key().to_secret_bytes())
        .map_err(|e| ReceiptError::Key(format!("bad identity secret key: {e}")))?;
    let keypair = Keypair::from_secret_key(SECP256K1, &sk);
    let (xonly, _parity) = keypair.x_only_public_key();
    receipt.server_pubkey = encode_hex(&xonly.serialize());

    let digest = receipt_digest(&receipt)?;
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&digest, &keypair);
    Ok(SignedReceipt {
        receipt,
        sig: encode_hex(&sig.to_byte_array()),
    })
}

/// Verify a signed receipt's signature against the public key embedded in the
/// receipt (`receipt.server_pubkey`). Returns `false` on any malformed field
/// or signature mismatch. Callers must still check the embedded key is the
/// server they trust (or use [`verify_receipt_from`]).
pub fn verify_receipt(signed: &SignedReceipt) -> bool {
    let Ok(digest) = receipt_digest(&signed.receipt) else {
        return false;
    };
    let Some(pk_bytes) = decode_fixed::<32>(&signed.receipt.server_pubkey) else {
        return false;
    };
    let Some(sig_bytes) = decode_fixed::<64>(&signed.sig) else {
        return false;
    };
    let Ok(pubkey) = XOnlyPublicKey::from_byte_array(pk_bytes) else {
        return false;
    };
    let signature = Signature::from_byte_array(sig_bytes);
    SECP256K1
        .verify_schnorr(&signature, &digest, &pubkey)
        .is_ok()
}

/// Verify a signed receipt AND that it was signed by `expected_pubkey_hex`
/// (the x-only server identity a store trusts out of band).
pub fn verify_receipt_from(signed: &SignedReceipt, expected_pubkey_hex: &str) -> bool {
    signed
        .receipt
        .server_pubkey
        .eq_ignore_ascii_case(expected_pubkey_hex.trim())
        && verify_receipt(signed)
}

/// SHA-256 of the canonical receipt JSON (the signed message).
fn receipt_digest(receipt: &Receipt) -> Result<[u8; 32], ReceiptError> {
    let bytes = serde_json::to_vec(receipt).map_err(|e| ReceiptError::Serialize(e.to_string()))?;
    Ok(sha256::Hash::hash(&bytes).to_byte_array())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn decode_fixed<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let hex = hex.trim();
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Receipt {
        Receipt {
            version: RECEIPT_VERSION,
            payment_id: "b6f7c2a0-1234-5678-9abc-def012345678".into(),
            amount: 2_500_000_000,
            kernel_excess: "09".repeat(33),
            confirmed_height: Some(3_900_000),
            confirmations: Some(11),
            proof: Some(serde_json::json!({
                "amount": 2_500_000_000u64,
                "kernel_excess": "09".repeat(33),
            })),
            issued_at: "2026-07-01T12:00:00Z".into(),
            server_pubkey: String::new(),
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let keys = Keys::generate();
        let signed = sign_receipt(&keys, sample()).unwrap();
        assert!(verify_receipt(&signed));
        // The embedded pubkey is the signer's x-only key.
        assert_eq!(signed.receipt.server_pubkey, keys.public_key().to_hex());
    }

    #[test]
    fn verify_from_matches_expected_key_only() {
        let keys = Keys::generate();
        let signed = sign_receipt(&keys, sample()).unwrap();
        assert!(verify_receipt_from(&signed, &keys.public_key().to_hex()));
        // A different expected key is rejected even though the sig is valid.
        let other = Keys::generate();
        assert!(!verify_receipt_from(&signed, &other.public_key().to_hex()));
    }

    #[test]
    fn tampering_any_field_breaks_verification() {
        let keys = Keys::generate();
        let signed = sign_receipt(&keys, sample()).unwrap();

        let mut t = signed.clone();
        t.receipt.amount += 1;
        assert!(!verify_receipt(&t), "amount tamper must fail");

        let mut t = signed.clone();
        t.receipt.confirmed_height = Some(999_999);
        assert!(!verify_receipt(&t), "height tamper must fail");

        let mut t = signed.clone();
        t.receipt.kernel_excess = "0a".repeat(33);
        assert!(!verify_receipt(&t), "excess tamper must fail");

        let mut t = signed.clone();
        t.receipt.proof = Some(serde_json::json!({"amount": 1}));
        assert!(!verify_receipt(&t), "proof tamper must fail");

        let mut t = signed.clone();
        t.receipt.payment_id = "other".into();
        assert!(!verify_receipt(&t), "id tamper must fail");
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let keys = Keys::generate();
        let mut signed = sign_receipt(&keys, sample()).unwrap();
        // Replace the embedded pubkey with a stranger's: the signature no
        // longer matches the (now different) advertised signer.
        let other = Keys::generate();
        signed.receipt.server_pubkey = other.public_key().to_hex();
        assert!(!verify_receipt(&signed));
    }

    #[test]
    fn malformed_fields_do_not_panic() {
        let keys = Keys::generate();
        let mut signed = sign_receipt(&keys, sample()).unwrap();
        signed.sig = "zz".into();
        assert!(!verify_receipt(&signed));
        signed.sig = String::new();
        assert!(!verify_receipt(&signed));
    }

    #[test]
    fn json_round_trips() {
        let keys = Keys::generate();
        let signed = sign_receipt(&keys, sample()).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, back);
        assert!(verify_receipt(&back));
    }
}
