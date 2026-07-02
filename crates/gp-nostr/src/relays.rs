//! Default relay set and helpers (mirrors `goblin/src/nostr/relays.rs`).

/// Default DM relays: the Goblin relay plus large public relays for
/// redundancy. Used when `GP_RELAYS` is unset (the bundled relay is a later
/// milestone; until then `bundled` mode serves this set too).
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.goblin.st",
    "wss://relay.damus.io",
    "wss://nos.lol",
];

/// Maximum relays published in the kind 10050 DM relay list (NIP-17
/// guidance) and read from a payer's list.
pub const MAX_DM_RELAYS: usize = 3;

/// The relay set to run with: the configured external list, else defaults.
pub fn resolve(configured: &[String]) -> Vec<String> {
    if configured.is_empty() {
        DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
    } else {
        configured.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_defaults_and_overrides() {
        assert_eq!(resolve(&[]), DEFAULT_RELAYS.to_vec());
        let own = vec!["wss://relay.example".to_string()];
        assert_eq!(resolve(&own), own);
    }
}
