//! gp-server library surface: the pieces the binary shares with the
//! integration tests (the wallet/transport handoff, the checkout renderer, the
//! matching/webhook recorder). The HTTP server itself lives in `main.rs`.

pub mod admin;
pub mod auth;
pub mod checkout;
pub mod directory;
pub mod foreign;
pub mod health;
pub mod ingest;
pub mod invoices;
pub mod payments;
pub mod ratelimit;
pub mod record;
pub mod security;
pub mod setup;
pub mod tor;
pub mod webhookd;
