//! Random identifiers and timestamps.
//!
//! Invoice ids and webhook event ids are random 128-bit values, hex encoded.
//! Checkout tokens are 256-bit and treated as bearer capabilities (the
//! unguessable secret that authorizes `/pay/<token>`), so they get twice the
//! entropy and a URL-safe base64 encoding.

use rand::RngCore;

/// A random 128-bit id, lowercase hex (32 chars). Used for invoice ids,
/// webhook event ids, and user ids.
pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// A random 256-bit checkout token, URL-safe base64 without padding (43
/// chars). This is the bearer capability for the hosted `/pay/<token>` page:
/// unguessable and not enumerable, never a database row number.
pub fn checkout_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64_url_nopad(&bytes)
}

/// Minimal URL-safe base64 (no padding), so the token needs no percent
/// encoding in a path and pulls in no base64 dependency of its own.
fn base64_url_nopad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn ids_are_unique_and_hex() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let id = random_id();
            assert_eq!(id.len(), 32);
            assert!(hex::decode(&id).is_ok());
            assert!(seen.insert(id), "ids must not collide");
        }
    }

    #[test]
    fn tokens_are_unguessable_length_and_url_safe() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let token = checkout_token();
            assert_eq!(token.len(), 43, "256 bits, url-safe base64 no pad");
            assert!(token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
            assert!(seen.insert(token), "tokens must not collide");
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        // Cross-checked against RFC 4648 URL-safe base64 (no padding).
        assert_eq!(base64_url_nopad(b""), "");
        assert_eq!(base64_url_nopad(b"f"), "Zg");
        assert_eq!(base64_url_nopad(b"fo"), "Zm8");
        assert_eq!(base64_url_nopad(b"foo"), "Zm9v");
        assert_eq!(base64_url_nopad(b"foob"), "Zm9vYg");
        assert_eq!(base64_url_nopad(&[0xff, 0xff, 0xff]), "____");
        assert_eq!(base64_url_nopad(&[0xfb, 0xff, 0xbf]), "-_-_");
    }
}
