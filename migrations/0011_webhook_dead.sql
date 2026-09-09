-- H2a: make an abandoned webhook delivery visible instead of silent.
--
-- A delivery that burns through `webhook::MAX_ATTEMPTS` (12) simply stopped
-- matching the `due` query: nothing on the dashboard, in /health or in the log
-- said the store had never been told about a payment. `dead_at` timestamps the
-- moment it gave up, so the admin surface can list it, /health can count it,
-- and `POST /admin/webhooks/{id}/redrive` can put it back in the queue.

ALTER TABLE webhook_delivery ADD COLUMN dead_at TEXT;

-- Backfill: rows that exhausted their attempts before this migration are just
-- as dead and just as invisible, so date them from their last attempt. The
-- literal 12 is `webhook::MAX_ATTEMPTS` at the time of writing; it is a
-- one-shot backfill, not a live rule, so it does not track later changes.
UPDATE webhook_delivery
   SET dead_at = updated_at
 WHERE delivered = 0 AND attempts >= 12;

CREATE INDEX idx_webhook_dead ON webhook_delivery (dead_at);
