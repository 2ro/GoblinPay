-- Milestone 7: conversion rates. A fiat invoice is now priced into Grin at
-- creation by the configurable price oracle (gp-core::rates), so its
-- expected_amount is filled (it was NULL through milestone 5) and the invoice
-- participates in amount-matching. The locked quote is recorded alongside the
-- fiat amount/currency already stored: the rate used (fiat per GRIN, decimal
-- string) and the source it came from (e.g. `coingecko`). The lock window is
-- the invoice's existing `expiry` column (quoted_at is its `created_at`), so
-- an amount-match past expiry re-quotes rather than honouring a stale rate.

ALTER TABLE invoice ADD COLUMN quote_rate TEXT;
ALTER TABLE invoice ADD COLUMN quote_source TEXT;
