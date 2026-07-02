//! Grin native payment proof, receiver side.
//!
//! When a payer's S1 slate carries a payment-proof request (a `sender_address`
//! plus our address as the `receiver_address`), upstream `receive_tx` signs
//! `payment_proof_message(amount, kernel_excess, sender_address)` with our
//! ed25519 address key and puts the signature on the returned S2 slate. That
//! receiver signature IS the payment proof the payer keeps ("this recipient
//! acknowledged receiving `amount` bound to this on-chain kernel from me").
//!
//! GoblinPay stores the receiver-side proof and can verify it independently of
//! any DM. Verification is pure crypto (no node, no wallet): reconstruct the
//! canonical proof message and check the receiver signature against the
//! recipient ed25519 address using the SAME `ed25519-dalek` grin-wallet uses.
//! We never hand-roll ed25519; the only logic here is the documented,
//! consensus-stable message serialization (`amount || kernel_excess ||
//! sender_address`, matching upstream `payment_proof_message`).
//!
//! Note this is the RECEIVER half only: it does not (cannot) carry the payer's
//! own sender signature, which the payer adds at finalize and never sends back.
//! Combined with the on-chain kernel confirmation (see [`crate::confirm`]),
//! this is the trustless "we got paid" primitive a store verifies.

use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature, Verifier};
use serde::{Deserialize, Serialize};

/// ed25519 public keys / signatures are fixed length.
const ADDRESS_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const COMMITMENT_LEN: usize = 33;

/// The receiver-side Grin payment proof for one payment (serde; the DB `proof`
/// column stores this as JSON). All byte fields are lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverProof {
    /// Amount in nanogrin (as bound into the signed message).
    pub amount: u64,
    /// Tx kernel excess commitment, hex (33 bytes) — the on-chain anchor.
    pub kernel_excess: String,
    /// Payer's proof address, ed25519 hex (32 bytes). The payer requested the
    /// proof to this identity; it is bound into the signed message.
    pub sender_address: String,
    /// Our proof address, ed25519 hex (32 bytes). The signature verifies
    /// against this key.
    pub recipient_address: String,
    /// Our receiver signature over the proof message, hex (64 bytes).
    pub recipient_sig: String,
}

impl ReceiverProof {
    /// Verify the receiver signature over the canonical proof message. Returns
    /// `false` on any malformed field or signature mismatch (a proof that does
    /// not verify is simply not a valid proof).
    ///
    /// This checks the cryptographic acknowledgement only; on-chain existence
    /// of `kernel_excess` is a separate node read ([`crate::confirm`]).
    pub fn verify(&self) -> bool {
        verify_receiver_proof(self)
    }
}

/// Free-function form of [`ReceiverProof::verify`].
pub fn verify_receiver_proof(proof: &ReceiverProof) -> bool {
    let Some(excess) = decode_fixed::<COMMITMENT_LEN>(&proof.kernel_excess) else {
        return false;
    };
    let Some(sender) = decode_fixed::<ADDRESS_LEN>(&proof.sender_address) else {
        return false;
    };
    let Some(recipient) = decode_fixed::<ADDRESS_LEN>(&proof.recipient_address) else {
        return false;
    };
    let Some(sig_bytes) = decode_fixed::<SIGNATURE_LEN>(&proof.recipient_sig) else {
        return false;
    };

    let Ok(recipient_key) = DalekPublicKey::from_bytes(&recipient) else {
        return false;
    };
    let Ok(signature) = DalekSignature::try_from(&sig_bytes[..]) else {
        return false;
    };

    let msg = proof_message(proof.amount, &excess, &sender);
    recipient_key.verify(&msg, &signature).is_ok()
}

/// Canonical payment-proof message, byte-identical to upstream
/// `libwallet::internal::tx::payment_proof_message` (private there, so
/// reconstructed here): `amount` big-endian u64, then the 33-byte kernel
/// commitment, then the 32-byte sender ed25519 address. Serialization only, no
/// crypto.
fn proof_message(
    amount: u64,
    kernel_excess: &[u8; COMMITMENT_LEN],
    sender_address: &[u8; ADDRESS_LEN],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + COMMITMENT_LEN + ADDRESS_LEN);
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(kernel_excess);
    msg.extend_from_slice(sender_address);
    msg
}

/// Hex-encode bytes (lowercase), for building a proof from slate data.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode exactly `N` bytes of hex, or `None`.
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
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};

    use super::*;

    /// A deterministic ed25519 keypair from a 32-byte seed (no RNG, so no
    /// rand-version coupling); the same library the wallet signs with.
    fn keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_bytes(&[seed; 32]).unwrap();
        let public: PublicKey = (&secret).into();
        Keypair { secret, public }
    }

    /// Build a valid receiver proof exactly as the wallet would: sign the
    /// canonical message with a real ed25519 key, using the same library.
    fn valid_proof() -> (ReceiverProof, Keypair) {
        let amount = 2_500_000_000u64;
        let excess = [0x09u8; COMMITMENT_LEN];
        let sender = [0x11u8; ADDRESS_LEN];

        let recipient = keypair(7);
        let msg = proof_message(amount, &excess, &sender);
        let sig = recipient.sign(&msg);

        let proof = ReceiverProof {
            amount,
            kernel_excess: encode_hex(&excess),
            sender_address: encode_hex(&sender),
            recipient_address: encode_hex(recipient.public.as_bytes()),
            recipient_sig: encode_hex(&sig.to_bytes()),
        };
        (proof, recipient)
    }

    #[test]
    fn valid_receiver_proof_verifies() {
        let (proof, _) = valid_proof();
        assert!(proof.verify());
    }

    #[test]
    fn tampered_amount_is_rejected() {
        let (mut proof, _) = valid_proof();
        proof.amount += 1;
        assert!(!proof.verify(), "a different amount must not verify");
    }

    #[test]
    fn tampered_kernel_excess_is_rejected() {
        let (mut proof, _) = valid_proof();
        // Flip one byte of the excess (still valid hex, right length).
        proof.kernel_excess = encode_hex(&[0x0au8; COMMITMENT_LEN]);
        assert!(!proof.verify());
    }

    #[test]
    fn wrong_recipient_is_rejected() {
        let (mut proof, _) = valid_proof();
        // A different recipient key did not sign this message.
        let other = keypair(9);
        proof.recipient_address = encode_hex(other.public.as_bytes());
        assert!(!proof.verify());
    }

    #[test]
    fn tampered_sender_address_is_rejected() {
        let (mut proof, _) = valid_proof();
        proof.sender_address = encode_hex(&[0x22u8; ADDRESS_LEN]);
        assert!(!proof.verify());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (mut proof, _) = valid_proof();
        let mut sig = decode_fixed::<SIGNATURE_LEN>(&proof.recipient_sig).unwrap();
        sig[0] ^= 0xff;
        proof.recipient_sig = encode_hex(&sig);
        assert!(!proof.verify());
    }

    #[test]
    fn malformed_fields_are_rejected_not_panicked() {
        let (proof, _) = valid_proof();
        for mutate in [
            |p: &mut ReceiverProof| p.kernel_excess = "zz".into(),
            |p: &mut ReceiverProof| p.recipient_address = "".into(),
            |p: &mut ReceiverProof| p.recipient_sig = "00".into(),
            |p: &mut ReceiverProof| p.sender_address = "nothex".into(),
        ] {
            let mut bad = proof.clone();
            mutate(&mut bad);
            assert!(!bad.verify());
        }
    }

    #[test]
    fn json_round_trips() {
        let (proof, _) = valid_proof();
        let json = serde_json::to_string(&proof).unwrap();
        let back: ReceiverProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, back);
        assert!(back.verify());
    }
}
