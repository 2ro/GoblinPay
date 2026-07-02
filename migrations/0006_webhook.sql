-- Milestone 6: HTTP webhook deliveries, persisted for idempotent retry with
-- backoff. The body is the exact signed JSON (the HMAC is recomputed from it
-- and the configured secret at send time). id is the event id, which is also
-- the idempotency key the receiver dedupes on.

CREATE TABLE webhook_delivery (
    id TEXT PRIMARY KEY,
    payment_id TEXT,
    event_type TEXT NOT NULL,
    url TEXT NOT NULL,
    body TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    delivered INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_webhook_pending ON webhook_delivery (delivered, next_attempt_at);
