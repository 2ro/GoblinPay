-- grin1 payment rail: the native Grin invoice flow (receiver-initiated) as the
-- primary "pay with any Grin wallet" path, plus the plain-send fallback.
--
-- On a grin1-rail invoice the till wallet issues an invoice slate (I1) at
-- creation; the payer imports the armored I1, pays it (producing an I2), and
-- returns the I2 to the Tor foreign endpoint, which finalizes + posts. The
-- returning I2 is matched back to this invoice by its slate id.
--
--   rail       payment rail marker: NULL (legacy / Nostr-only) or 'grin1'.
--   slate_id   the issued I1 slate UUID (invoice flow); the settlement key a
--              returning finalize is matched on. NULL for non-grin1 invoices.
--   slatepack  the armored I1 invoice slatepack the pay page renders (text +
--              QR). Contains no secret: it is the invoice the payer gets anyway.
ALTER TABLE invoice ADD COLUMN rail TEXT;
ALTER TABLE invoice ADD COLUMN slate_id TEXT;
ALTER TABLE invoice ADD COLUMN slatepack TEXT;

CREATE INDEX idx_invoice_slate ON invoice (slate_id);
