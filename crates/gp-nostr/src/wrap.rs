//! NIP-59 gift wrap build/unwrap with the NIP-17 backward-compat extension
//! (NIP-44 v3 context binding), all in one place.
//!
//! - **v2** rides nostr-sdk exactly as Goblin ships today: the seal content
//!   is `nip44::encrypt(.., Version::V2)` and the outer wrap goes through
//!   nostr-sdk's own `EventBuilder::gift_wrap_from_seal` (which hardcodes
//!   v2 — the reason v3 needs the manual path below).
//! - **v3** is built manually against the companion `nip44` crate: the seal
//!   (kind 13) encrypts the rumor JSON with context `kind=13, scope=""`, the
//!   wrap (kind 1059) encrypts the seal JSON with `kind=1059, scope=""`, per
//!   the extension spec. Everything else mirrors what nostr-sdk does for v2:
//!   `rumor.ensure_id()`, seal signed by the sender with NO tags, wrap signed
//!   by a fresh ephemeral key with the receiver `p` tag, and `created_at`
//!   fuzzed up to two days into the past on both.
//! - **Decrypt** dispatches per layer on the payload version byte
//!   (`0x02`/`0x03`), so mixed peers interoperate and a v2-only Goblin can
//!   always read us.
//!
//! Negotiation: we advertise `["encryption", "nip44_v3 nip44_v2"]` on our
//! kind 10050; on send we take the FIRST method of the recipient's
//! (best-first) list that we support; no tag means v2 only.

use std::fmt;

use nostr_sdk::nips::nip44 as sdk_nip44;
use nostr_sdk::nips::nip59::RANGE_RANDOM_TIMESTAMP_TWEAK;
use nostr_sdk::{
    Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, Timestamp, UnsignedEvent,
};

/// Tag name on kind 10050 advertising supported encryption methods.
pub const ENCRYPTION_TAG: &str = "encryption";
/// Our capabilities, space separated, best first.
pub const ENCRYPTION_CAPABILITIES: &str = "nip44_v3 nip44_v2";

/// v3 context values fixed by the NIP-17 extension: seals bind `kind=13`,
/// gift wraps bind `kind=1059`, scope is empty for both.
const SEAL_KIND: u32 = 13;
const WRAP_KIND: u32 = 1059;
const EMPTY_SCOPE: &[u8] = b"";

/// Which NIP-44 version to encrypt a seal + wrap with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapVersion {
    V2,
    V3,
}

/// Errors from wrapping or unwrapping.
#[derive(Debug)]
pub enum WrapError {
    /// The outer event is not a kind 1059 gift wrap.
    NotGiftWrap,
    /// The decrypted inner event is not a kind 13 seal.
    NotSeal,
    /// The rumor author does not match the seal signer (NIP-17 requirement).
    SenderMismatch,
    /// Encryption/decryption failure (wrong key, bad MAC, bad context, ...).
    Crypto(String),
    /// Event build/parse/signature failure.
    Event(String),
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WrapError::NotGiftWrap => write!(f, "not a gift wrap event"),
            WrapError::NotSeal => write!(f, "inner event is not a seal"),
            WrapError::SenderMismatch => write!(f, "rumor author differs from seal signer"),
            WrapError::Crypto(m) => write!(f, "wrap crypto error: {m}"),
            WrapError::Event(m) => write!(f, "wrap event error: {m}"),
        }
    }
}

impl std::error::Error for WrapError {}

/// An unwrapped gift: the seal-verified sender and the rumor. Mirrors
/// nostr-sdk's `UnwrappedGift`, produced by the version-dispatching path.
#[derive(Debug, Clone)]
pub struct Unwrapped {
    /// The seal signer (verified signature) — the authenticated sender.
    pub sender: PublicKey,
    /// The unsigned rumor.
    pub rumor: UnsignedEvent,
}

/// Pick the encryption version for a recipient from their kind 10050
/// `encryption` tag value (space separated, best first). The best mutual
/// method wins in THEIR preference order; an absent tag, or a tag with no
/// mutual method, means the mandatory v2 baseline.
pub fn choose_version(recipient_encryption: Option<&str>) -> WrapVersion {
    if let Some(tag) = recipient_encryption {
        for method in tag.split_whitespace() {
            match method {
                "nip44_v3" => return WrapVersion::V3,
                "nip44_v2" => return WrapVersion::V2,
                _ => {}
            }
        }
    }
    WrapVersion::V2
}

/// Read the `encryption` tag value from a kind 10050 event, if present.
pub fn encryption_capability(event: &Event) -> Option<String> {
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.first().map(|s| s.as_str()) == Some(ENCRYPTION_TAG) {
            return parts.get(1).cloned();
        }
    }
    None
}

/// The `encryption` tag we publish on our own kind 10050.
pub fn capability_tag() -> Tag {
    Tag::custom(
        nostr_sdk::TagKind::custom(ENCRYPTION_TAG),
        [ENCRYPTION_CAPABILITIES.to_string()],
    )
}

/// Gift wrap `rumor` from `sender` to `receiver` with the given version.
pub fn gift_wrap(
    sender: &Keys,
    receiver: &PublicKey,
    mut rumor: UnsignedEvent,
    version: WrapVersion,
) -> Result<Event, WrapError> {
    // Fix the rumor id BEFORE encrypting, exactly like nostr-sdk's
    // `make_seal`, so both peers agree on the rumor identity.
    rumor.ensure_id();
    match version {
        WrapVersion::V2 => {
            let content = sdk_nip44::encrypt(
                sender.secret_key(),
                receiver,
                rumor.as_json(),
                sdk_nip44::Version::V2,
            )
            .map_err(|e| WrapError::Crypto(e.to_string()))?;
            let seal = EventBuilder::new(Kind::Seal, content)
                .custom_created_at(Timestamp::tweaked(RANGE_RANDOM_TIMESTAMP_TWEAK))
                .sign_with_keys(sender)
                .map_err(|e| WrapError::Event(e.to_string()))?;
            // The proven nostr-sdk outer wrap (ephemeral key, `p` tag,
            // created_at fuzz — and v2 encryption, which is what we want here).
            EventBuilder::gift_wrap_from_seal(receiver, &seal, [])
                .map_err(|e| WrapError::Event(e.to_string()))
        }
        WrapVersion::V3 => {
            let ck = v3_conversation_key(sender, receiver)?;
            let content =
                nip44::encrypt_v3(&ck, rumor.as_json().as_bytes(), SEAL_KIND, EMPTY_SCOPE)
                    .map_err(|e| WrapError::Crypto(e.to_string()))?;
            let seal = EventBuilder::new(Kind::Seal, content)
                .custom_created_at(Timestamp::tweaked(RANGE_RANDOM_TIMESTAMP_TWEAK))
                .sign_with_keys(sender)
                .map_err(|e| WrapError::Event(e.to_string()))?;

            let ephemeral = Keys::generate();
            let wck = v3_conversation_key(&ephemeral, receiver)?;
            let wrapped =
                nip44::encrypt_v3(&wck, seal.as_json().as_bytes(), WRAP_KIND, EMPTY_SCOPE)
                    .map_err(|e| WrapError::Crypto(e.to_string()))?;
            EventBuilder::new(Kind::GiftWrap, wrapped)
                .tags([Tag::public_key(*receiver)])
                .custom_created_at(Timestamp::tweaked(RANGE_RANDOM_TIMESTAMP_TWEAK))
                .sign_with_keys(&ephemeral)
                .map_err(|e| WrapError::Event(e.to_string()))
        }
    }
}

/// Unwrap a gift wrap addressed to `receiver`, dispatching each layer on its
/// NIP-44 version byte. Verifies the seal signature and the NIP-17
/// author-equals-signer rule; for v3 layers the kind/scope context binding is
/// enforced by the `nip44` crate against the expected values (13/1059, "").
pub fn unwrap_gift_wrap(receiver: &Keys, wrap: &Event) -> Result<Unwrapped, WrapError> {
    if wrap.kind != Kind::GiftWrap {
        return Err(WrapError::NotGiftWrap);
    }
    let seal_json = decrypt_layer(receiver, &wrap.pubkey, &wrap.content, WRAP_KIND)?;
    let seal = Event::from_json(seal_json).map_err(|e| WrapError::Event(e.to_string()))?;
    seal.verify().map_err(|e| WrapError::Event(e.to_string()))?;
    if seal.kind != Kind::Seal {
        return Err(WrapError::NotSeal);
    }
    let rumor_json = decrypt_layer(receiver, &seal.pubkey, &seal.content, SEAL_KIND)?;
    let rumor =
        UnsignedEvent::from_json(rumor_json).map_err(|e| WrapError::Event(e.to_string()))?;
    if rumor.pubkey != seal.pubkey {
        return Err(WrapError::SenderMismatch);
    }
    Ok(Unwrapped {
        sender: seal.pubkey,
        rumor,
    })
}

/// Decrypt one layer, branching on the version byte: `0x02` goes to
/// nostr-sdk's v2, `0x03` to the `nip44` crate with the expected context.
fn decrypt_layer(
    keys: &Keys,
    author: &PublicKey,
    content: &str,
    expected_kind: u32,
) -> Result<String, WrapError> {
    match nip44::payload_version(content).map_err(|e| WrapError::Crypto(e.to_string()))? {
        2 => sdk_nip44::decrypt(keys.secret_key(), author, content)
            .map_err(|e| WrapError::Crypto(e.to_string())),
        3 => {
            let ck = v3_conversation_key(keys, author)?;
            let plain = nip44::decrypt_v3(&ck, content, expected_kind, EMPTY_SCOPE)
                .map_err(|e| WrapError::Crypto(e.to_string()))?;
            String::from_utf8(plain).map_err(|e| WrapError::Crypto(e.to_string()))
        }
        v => Err(WrapError::Crypto(format!("unsupported nip44 version {v}"))),
    }
}

/// The v3 conversation key (raw ECDH x coordinate) between our secret key and
/// a peer's x-only public key. nostr-sdk is on secp256k1 0.29 while the nip44
/// crate speaks 0.31, so the conversion goes through raw bytes.
fn v3_conversation_key(ours: &Keys, theirs: &PublicKey) -> Result<[u8; 32], WrapError> {
    let sk = secp256k1::SecretKey::from_byte_array(ours.secret_key().to_secret_bytes())
        .map_err(|e| WrapError::Crypto(format!("bad secret key: {e}")))?;
    let pk = secp256k1::XOnlyPublicKey::from_byte_array(theirs.to_bytes())
        .map_err(|e| WrapError::Crypto(format!("bad public key: {e}")))?;
    Ok(nip44::get_conversation_key_v3(sk, pk))
}

#[cfg(test)]
mod tests {
    use nostr_sdk::nips::nip59::UnwrappedGift;

    use super::*;

    fn rumor(sender: &Keys, receiver: &PublicKey, text: &str) -> UnsignedEvent {
        EventBuilder::new(Kind::PrivateDirectMessage, text)
            .tags([Tag::public_key(*receiver)])
            .build(sender.public_key())
    }

    fn version_byte(event: &Event) -> u8 {
        nip44::payload_version(&event.content).unwrap()
    }

    #[test]
    fn v3_seal_and_wrap_round_trip() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let r = rumor(&alice, &bob.public_key(), "hello over v3");

        let wrap = gift_wrap(&alice, &bob.public_key(), r.clone(), WrapVersion::V3).unwrap();
        assert_eq!(wrap.kind, Kind::GiftWrap);
        assert_eq!(version_byte(&wrap), 3, "outer layer must be v3");
        // Signed by a fresh ephemeral key, never by Alice.
        assert_ne!(wrap.pubkey, alice.public_key());
        wrap.verify().unwrap();
        // Addressed to Bob via the p tag, timestamp fuzzed into the past.
        assert!(wrap
            .tags
            .iter()
            .any(|t| t.as_slice().get(1).map(|s| s.as_str())
                == Some(bob.public_key().to_hex().as_str())));
        assert!(wrap.created_at <= Timestamp::now());

        let unwrapped = unwrap_gift_wrap(&bob, &wrap).unwrap();
        assert_eq!(unwrapped.sender, alice.public_key());
        assert_eq!(unwrapped.rumor.pubkey, alice.public_key());
        assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);
        assert_eq!(unwrapped.rumor.content, "hello over v3");

        // A stranger cannot open it.
        let mallory = Keys::generate();
        assert!(unwrap_gift_wrap(&mallory, &wrap).is_err());
        // And the sender cannot open their own wrap (it is not wrapped to them).
        assert!(unwrap_gift_wrap(&alice, &wrap).is_err());
    }

    #[test]
    fn v2_interop_with_nostr_sdk_both_directions() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let alice = Keys::generate();
        let bob = Keys::generate();

        // Ours -> stock nostr-sdk (what today's v2-only Goblin runs).
        let r = rumor(&alice, &bob.public_key(), "ours to sdk");
        let wrap = gift_wrap(&alice, &bob.public_key(), r, WrapVersion::V2).unwrap();
        assert_eq!(version_byte(&wrap), 2);
        let gift = rt
            .block_on(UnwrappedGift::from_gift_wrap(&bob, &wrap))
            .unwrap();
        assert_eq!(gift.sender, alice.public_key());
        assert_eq!(gift.rumor.content, "ours to sdk");

        // Stock nostr-sdk -> ours (a v2 Goblin paying us).
        let r = rumor(&alice, &bob.public_key(), "sdk to ours");
        let wrap = rt
            .block_on(EventBuilder::gift_wrap(&alice, &bob.public_key(), r, []))
            .unwrap();
        let unwrapped = unwrap_gift_wrap(&bob, &wrap).unwrap();
        assert_eq!(unwrapped.sender, alice.public_key());
        assert_eq!(unwrapped.rumor.content, "sdk to ours");
    }

    #[test]
    fn unwrap_dispatches_on_version_byte() {
        // The receiver is never told which version arrived — the payload
        // version byte decides, per layer.
        let alice = Keys::generate();
        let bob = Keys::generate();
        for (version, byte) in [(WrapVersion::V2, 2u8), (WrapVersion::V3, 3u8)] {
            let r = rumor(&alice, &bob.public_key(), "dispatch");
            let wrap = gift_wrap(&alice, &bob.public_key(), r, version).unwrap();
            assert_eq!(version_byte(&wrap), byte);
            let unwrapped = unwrap_gift_wrap(&bob, &wrap).unwrap();
            assert_eq!(unwrapped.sender, alice.public_key());
        }
    }

    #[test]
    fn v3_context_binding_is_enforced() {
        // A v3 payload sealed for one context must not open under another:
        // decrypting the WRAP layer content as if it were a SEAL fails on the
        // kind binding even with the right conversation key.
        let alice = Keys::generate();
        let bob = Keys::generate();
        let r = rumor(&alice, &bob.public_key(), "context");
        let wrap = gift_wrap(&alice, &bob.public_key(), r, WrapVersion::V3).unwrap();

        let ck = v3_conversation_key(&bob, &wrap.pubkey).unwrap();
        assert!(nip44::decrypt_v3(&ck, &wrap.content, WRAP_KIND, EMPTY_SCOPE).is_ok());
        assert!(
            nip44::decrypt_v3(&ck, &wrap.content, SEAL_KIND, EMPTY_SCOPE).is_err(),
            "kind binding must reject a cross-context decrypt"
        );
        assert!(
            nip44::decrypt_v3(&ck, &wrap.content, WRAP_KIND, b"other").is_err(),
            "scope binding must reject a cross-context decrypt"
        );
    }

    #[test]
    fn rumor_id_is_fixed_before_encryption() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let r = rumor(&alice, &bob.public_key(), "id check");
        let wrap = gift_wrap(&alice, &bob.public_key(), r.clone(), WrapVersion::V3).unwrap();
        let mut unwrapped = unwrap_gift_wrap(&bob, &wrap).unwrap();
        let mut original = r;
        assert_eq!(unwrapped.rumor.id(), original.id());
    }

    #[test]
    fn chooses_best_mutual_version() {
        assert_eq!(choose_version(None), WrapVersion::V2);
        assert_eq!(choose_version(Some("nip44_v2")), WrapVersion::V2);
        assert_eq!(choose_version(Some("nip44_v3 nip44_v2")), WrapVersion::V3);
        // Their list is best-first: respect a peer that prefers v2.
        assert_eq!(choose_version(Some("nip44_v2 nip44_v3")), WrapVersion::V2);
        // Unknown methods are skipped; nothing mutual falls back to v2.
        assert_eq!(choose_version(Some("mls nip44_v3")), WrapVersion::V3);
        assert_eq!(choose_version(Some("mls")), WrapVersion::V2);
        assert_eq!(choose_version(Some("")), WrapVersion::V2);
    }

    #[test]
    fn reads_capability_from_10050() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::InboxRelays, "")
            .tags([
                Tag::custom(
                    nostr_sdk::TagKind::custom("relay"),
                    ["wss://relay.example".to_string()],
                ),
                capability_tag(),
            ])
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(
            encryption_capability(&event).as_deref(),
            Some(ENCRYPTION_CAPABILITIES)
        );
        assert_eq!(
            choose_version(encryption_capability(&event).as_deref()),
            WrapVersion::V3
        );

        let bare = EventBuilder::new(Kind::InboxRelays, "")
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(encryption_capability(&bare), None);
    }
}
