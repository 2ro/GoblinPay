-- Milestone 3: persist the S2 reply armor so a crash between receive_tx and
-- the reply dispatch is recoverable. The ingest service re-sends any payment
-- still in status 'received' at boot (mirrors Goblin's reconcile loop).
-- The armor contains no secrets: it is the reply slatepack the payer gets
-- anyway; transport privacy is the NIP-44 gift wrap.
ALTER TABLE payment ADD COLUMN s2_armor TEXT;
