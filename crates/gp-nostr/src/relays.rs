//! Relay set resolution.
//!
//! GoblinPay runs in one of two relay modes (`GP_RELAY_MODE`, see
//! [`gp_core::config::RelayMode`]):
//!
//! - `bundled` (default): GoblinPay talks to its own co-located relay, the
//!   nostr-rs-relay shipped as the `relay` service in
//!   `deploy/docker-compose.yml`. Its URL is `GP_BUNDLED_RELAY_URL` (default
//!   `ws://127.0.0.1:7777`). Because the resolved set is exactly what the
//!   checkout `nprofile` advertises to payers, a merchant needs no third-party
//!   relay: the payer's Goblin Wallet is told to deliver the gift-wrapped
//!   slatepack to the merchant's own relay. Extra relays listed in `GP_RELAYS`
//!   are appended for redundancy (and advertised alongside the bundled one).
//! - `external`: only the relays listed in `GP_RELAYS` are used (no bundled
//!   relay); config validation requires at least one.
//!
//! The bundled relay is a vendored, unmodified nostr-rs-relay (config only, no
//! fork) rather than a relay written from scratch: it is a small, SQLite-backed
//! Rust relay that fits a single-merchant till, and reusing it keeps the money
//! path off any third-party infrastructure.

use gp_core::config::RelayMode;

/// Maximum relays published in the kind 10050 DM relay list (NIP-17
/// guidance) and read from a payer's list.
pub const MAX_DM_RELAYS: usize = 3;

/// The relay set to listen on, publish to, and advertise in the `nprofile`.
///
/// In `bundled` mode the co-located `bundled_url` comes first (so it heads the
/// advertised kind 10050 / `nprofile` hints), followed by any `configured`
/// redundancy relays, de-duplicated. In `external` mode only the `configured`
/// relays are used.
pub fn resolve(mode: RelayMode, bundled_url: &str, configured: &[String]) -> Vec<String> {
    match mode {
        RelayMode::Bundled => {
            let mut relays = vec![bundled_url.to_string()];
            for relay in configured {
                if !relays.iter().any(|r| r == relay) {
                    relays.push(relay.clone());
                }
            }
            relays
        }
        RelayMode::External => configured.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_leads_with_the_bundled_relay() {
        // No extras: just the bundled relay, so the nprofile advertises it and
        // nothing third-party is involved.
        assert_eq!(
            resolve(RelayMode::Bundled, "ws://127.0.0.1:7777", &[]),
            vec!["ws://127.0.0.1:7777".to_string()]
        );
        // Extras are appended for redundancy; the bundled relay stays first.
        let extras = vec!["wss://relay.damus.io".to_string()];
        assert_eq!(
            resolve(RelayMode::Bundled, "ws://127.0.0.1:7777", &extras),
            vec![
                "ws://127.0.0.1:7777".to_string(),
                "wss://relay.damus.io".to_string(),
            ]
        );
        // A configured relay equal to the bundled one is not added twice.
        let dup = vec![
            "ws://127.0.0.1:7777".to_string(),
            "wss://r.example".to_string(),
        ];
        assert_eq!(
            resolve(RelayMode::Bundled, "ws://127.0.0.1:7777", &dup),
            vec![
                "ws://127.0.0.1:7777".to_string(),
                "wss://r.example".to_string(),
            ]
        );
    }

    #[test]
    fn external_uses_only_configured() {
        let own = vec!["wss://relay.example".to_string()];
        assert_eq!(
            resolve(RelayMode::External, "ws://127.0.0.1:7777", &own),
            own
        );
    }
}
