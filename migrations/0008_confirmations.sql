-- Confirmation depth as a first-class part of the invoice lifecycle (house
-- standard: a payment is only *final* after GP_CONFIRMATIONS on-chain
-- confirmations, default 10).
--
-- The invoice status flow gains a terminal `confirmed` state after `paid`:
--   open -> paid (a received payment matched it, unchanged)
--        -> confirmed (its kernel reached GP_CONFIRMATIONS confirmations)
-- `paid` remains a real, backward-compatible state; `confirmed` is additive.
--
--   payment.confirmations  the live confirmation depth of the payment's kernel,
--                          refreshed every confirmation-poll pass (tip - height
--                          + 1). 0 until the kernel lands. The invoice's
--                          exposed `confirmations` is read from the payment that
--                          paid it.
--   invoice.confirmed_at   ISO-8601 UTC time the invoice crossed the threshold
--                          (paid -> confirmed), NULL until then.
ALTER TABLE payment ADD COLUMN confirmations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invoice ADD COLUMN confirmed_at TEXT;
