-- Milestone 5: hosted checkout and order matching. Extends the invoice stub
-- with the checkout bearer token, the recipient identity (public key only:
-- per-invoice derived child keys are recomputed statelessly, never stored),
-- the optional fiat quote (the Grin conversion is a later milestone), the
-- per-invoice matching-mode override, and the paid-linkage back to a payment.

ALTER TABLE invoice ADD COLUMN token TEXT;
ALTER TABLE invoice ADD COLUMN memo TEXT;
-- x-only pubkey hex: the server master key for memo/amount invoices, or a
-- per-invoice derived child for derived mode.
ALTER TABLE invoice ADD COLUMN recipient_pubkey TEXT;
-- Fiat quote (decimal string + ISO code); expected_amount stays NULL until the
-- conversion milestone fills the Grin amount.
ALTER TABLE invoice ADD COLUMN fiat_amount TEXT;
ALTER TABLE invoice ADD COLUMN fiat_currency TEXT;
-- Per-invoice matching-mode override; NULL means the global GP_MATCH_MODE.
ALTER TABLE invoice ADD COLUMN match_mode TEXT;
ALTER TABLE invoice ADD COLUMN paid_payment_id TEXT;
ALTER TABLE invoice ADD COLUMN paid_at TEXT;

CREATE UNIQUE INDEX idx_invoice_token ON invoice (token);
CREATE INDEX idx_invoice_recipient ON invoice (recipient_pubkey);
CREATE INDEX idx_invoice_ref ON invoice (ref);

-- Link a received payment back to the invoice and tenant user it satisfied
-- (both optional: a bare payment with no invoice still records), and record
-- which of our identities received it so the reply can be re-sent from the
-- right key on reconcile.
ALTER TABLE payment ADD COLUMN invoice_id TEXT;
ALTER TABLE payment ADD COLUMN user_id TEXT;
ALTER TABLE payment ADD COLUMN recipient TEXT;
CREATE INDEX idx_payment_user ON payment (user_id);
