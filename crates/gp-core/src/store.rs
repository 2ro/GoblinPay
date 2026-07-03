//! The store-connector seam.
//!
//! Every store integration (the built-in generic REST connector, the shipped
//! WooCommerce and Medusa plugins under `connectors/`, and the future pop-up
//! Nostr store) drives GoblinPay through one uniform contract:
//! a create-invoice request in, a hosted checkout + signed webhook out. This
//! trait keeps that mapping in one place so the core never grows per-store
//! branches: a connector only decides how a store's order becomes invoice
//! parameters and where its payment webhooks go.

use crate::config::MatchMode;
use crate::invoice::{AmountSpec, NewInvoice};

/// A store's request to create an invoice, uniform across connectors.
#[derive(Debug, Clone)]
pub struct CreateInvoiceRequest {
    /// The store's order reference (also the memo/subject match key).
    pub order_ref: Option<String>,
    /// The amount, exact Grin or a fiat quote.
    pub amount: AmountSpec,
    /// A human memo for the checkout page.
    pub memo: Option<String>,
    /// Per-invoice matching-mode override; `None` uses the global default.
    pub match_mode: Option<MatchMode>,
    /// Expiry in seconds from now; `None` for no expiry.
    pub expiry_secs: Option<i64>,
}

/// The uniform connector contract. Implementors translate a store request into
/// invoice parameters and advertise where payment webhooks should be sent.
pub trait StoreConnector: Send + Sync {
    /// Stable connector id (e.g. `rest`, `woocommerce`, `medusa`).
    fn id(&self) -> &str;

    /// Map a store request into invoice-creation parameters. The default is
    /// the identity mapping; a connector overrides only to impose its own
    /// policy (a forced matching mode, a default expiry, and so on).
    fn new_invoice(&self, req: CreateInvoiceRequest) -> NewInvoice {
        NewInvoice {
            order_ref: req.order_ref,
            amount: req.amount,
            memo: req.memo,
            match_mode: req.match_mode,
            expiry_secs: req.expiry_secs,
        }
    }

    /// The webhook endpoint payment events for this store are delivered to, if
    /// it consumes webhooks.
    fn webhook_url(&self) -> Option<&str> {
        None
    }
}

/// The built-in generic REST connector: the identity request mapping plus the
/// operator's configured webhook endpoint. WooCommerce and Medusa speak this
/// same REST + webhook contract, so server-side they reuse it unchanged.
pub struct RestConnector {
    webhook_url: Option<String>,
}

impl RestConnector {
    pub fn new(webhook_url: Option<String>) -> RestConnector {
        RestConnector { webhook_url }
    }
}

impl StoreConnector for RestConnector {
    fn id(&self) -> &str {
        "rest"
    }

    fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_connector_maps_request_identically() {
        let conn = RestConnector::new(Some("https://store.example/hook".into()));
        assert_eq!(conn.id(), "rest");
        assert_eq!(conn.webhook_url(), Some("https://store.example/hook"));
        let req = CreateInvoiceRequest {
            order_ref: Some("order-9".into()),
            amount: AmountSpec::Grin(42),
            memo: Some("m".into()),
            match_mode: Some(MatchMode::Derived),
            expiry_secs: Some(600),
        };
        let inv = conn.new_invoice(req);
        assert_eq!(inv.order_ref.as_deref(), Some("order-9"));
        assert_eq!(inv.match_mode, Some(MatchMode::Derived));
        assert_eq!(inv.expiry_secs, Some(600));
    }
}
