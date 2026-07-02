-- Milestone 5b: per-user endpubs (multi-tenant receiving). Store ONLY the
-- assignment and the rotation clock, never a private key: every endpub is a
-- stateless child of the server nsec keyed by (user_id, epoch), recomputed on
-- demand. All funds still land in the one Grin wallet; the endpub only decides
-- which user an incoming payment credits.

CREATE TABLE user (
    id TEXT PRIMARY KEY,
    -- Per-user rotation override in seconds; NULL = global default, 0 = off.
    rotate_interval INTEGER,
    -- Current (highest) endpub epoch.
    epoch INTEGER NOT NULL DEFAULT 0,
    last_rotated_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- One row per (user, epoch). pubkey is the derived x-only hex (public, never a
-- secret). The overlap window keeps the last N epochs watched so a payment to
-- a just-rotated endpub still lands.
CREATE TABLE endpub_assignment (
    user_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    pubkey TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, epoch),
    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE INDEX idx_endpub_pubkey ON endpub_assignment (pubkey);
