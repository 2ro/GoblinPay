//! GoblinPay domain core.
//!
//! Holds everything that is not transport or wallet crypto: the runtime
//! configuration (env-first, like goblin-nip05d), the SQLite persistence
//! layer, and (in later milestones) invoices, payments, matching, conversion,
//! and notification traits.

pub mod config;
pub mod db;
pub mod derive;
pub mod endpub;
pub mod ids;
pub mod invoice;
pub mod matching;
pub mod qr;
pub mod rates;
pub mod store;
pub mod webhook;

use subtle::ConstantTimeEq;

/// Constant-time byte-string equality, for comparing bearer tokens and other
/// secrets without leaking a timing side channel.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
