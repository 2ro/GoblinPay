-- Milestone 4: on-chain confirmation + payment proof.
--
-- The `kernel`, `proof`, and `confirmed_height` columns already exist from
-- 0001 (reserved there for exactly this milestone); this migration only adds
-- the confirmation timestamp and an index for the confirmation poll.
--
-- Column use as of M4:
--   kernel            hex of the tx kernel excess commitment (33 bytes), set
--                     at receive time (gp-wallet computes it via the upstream
--                     Slate::calc_excess). The confirmation poll queries the
--                     node's get_kernel with this excess.
--   proof             JSON blob of the receiver-side Grin payment proof
--                     (amount, kernel excess, sender + recipient ed25519
--                     addresses, receiver signature), only when the payer's S1
--                     requested a proof. NULL otherwise.
--   confirmed_height  block height the kernel landed at (NULL until confirmed).
--   confirmed_at      ISO-8601 UTC time GoblinPay observed the kernel on chain.
--
-- Status transitions: received -> replied (S2 dispatched) -> confirmed (kernel
-- on chain). Confirmation is independent of the reply leg: a payer can finalize
-- and post from a cached S2, so the poll advances any payment with a kernel
-- excess, whether or not its S2 reply has been re-observed as delivered.
ALTER TABLE payment ADD COLUMN confirmed_at TEXT;

-- The poll scans not-yet-confirmed payments that carry a kernel excess.
CREATE INDEX idx_payment_pending_confirm ON payment (status) WHERE kernel IS NOT NULL;
