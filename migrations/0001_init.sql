-- Initial schema. Kept minimal per the plan (~3 tables total; the optional
-- webhook_delivery table arrives with the notifications milestone).

-- One row per received payment. Timestamps are ISO-8601 TEXT (UTC).
CREATE TABLE payment (
    id TEXT PRIMARY KEY,
    amount INTEGER NOT NULL,
    payer TEXT,
    slate_id TEXT,
    kernel TEXT,
    proof TEXT,
    status TEXT NOT NULL,
    confirmed_height INTEGER,
    created_at TEXT NOT NULL
);

-- Optional order matching: only populated when payments map to invoices.
CREATE TABLE invoice (
    id TEXT PRIMARY KEY,
    ref TEXT,
    expected_amount INTEGER,
    expiry TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
