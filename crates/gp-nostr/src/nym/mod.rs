//! Nym mixnet transport, ported from Goblin's proven `src/nym` (G14).
//! Every relay websocket rides one in-process smolmix
//! [`Tunnel`](smolmix::Tunnel) over the 5-hop mixnet to an auto-selected IPR
//! exit. Hostnames resolve through the same tunnel ([`dns`], mix-dns), so
//! neither payload nor destination ever touches the clearnet. For a payment
//! server this is default-on: returning the S2 means outbound connections to
//! the payer's relays, which over clearnet would link the merchant identity
//! to a host IP.
//!
//! This tunnel carries ONLY the Nostr gift-wrap layer. The milestone-4
//! node-confirmation reads (wallet -> node get_kernel/get_tip) deliberately do
//! NOT ride it: node traffic is a server concern that goes DIRECT over normal
//! HTTP (owner ruling), exactly like Goblin's own wallet -> node reads never
//! ride the mixnet. Those reads live in `gp-wallet`, which has no Nym linkage,
//! so the direct path is structural. Do not route node reads through here.

pub mod dns;
pub mod nymproc;
pub mod transport;

pub use nymproc::{is_ready, warm_up};
pub use transport::NymWebSocketTransport;
