# The reference till: how the maintained deployment is laid out

GoblinPay is self-hostable and this repo does not assume any particular host.
This page documents one real, running till, the maintained reference
deployment, so that "how is this actually run" has a concrete answer and so
that anyone debugging a report from it knows what the box looks like.

It holds **no secrets**: no tokens, no seed, no password, no hostnames. Every
path below is a location, not a value. The reference till is bare metal with
systemd, not the compose stack (`deploy/docker-compose.yml` remains the
container path; see its own header for the trade-offs it carries).

## Layout

| Thing | Where |
|---|---|
| Unit | `goblin-pay.service` |
| Install root | `/opt/goblin/goblinpay/` |
| Binary | `/opt/goblin/goblinpay/gp-server` |
| Env file | `/opt/goblin/goblinpay/goblinpay.env` |
| Sealed credential | `/opt/goblin/goblinpay/secrets/` |
| Managed state (SQLite db, wallet files, encrypted seed) | `/opt/goblin/goblinpay/data/` |
| Listen address | loopback, port `8192` |
| Build workspace | `/opt/goblin/gpbuild/GoblinPay/` |

The unit name and the install root both differ from the shipped
`deploy/gp-server.service`, which uses `gp-server.service`,
`/usr/local/bin/gp-server`, `/etc/goblinpay.env` and a `StateDirectory` under
`/var/lib/goblinpay`. Neither layout is more correct than the other; the
shipped unit is the clean-room default, and the reference till keeps
everything under one `/opt/goblin/` tree alongside the other Goblin services on
the same host. If you are reading a path from an ops note and it does not match
the repo, that is why.

Port `8192` is loopback only. A reverse proxy in front of it terminates TLS and
is the only thing that reaches the till, which is the same posture
`GP_BIND=127.0.0.1:8080` describes in the README.

## The wallet password

The till runs **unattended, encrypted at rest**: a `systemd-creds encrypt`
ciphertext blob under `secrets/`, read by a `LoadCredentialEncrypted=` drop-in
rather than the base unit's plaintext `LoadCredential=` line. systemd decrypts
it into the tmpfs credentials directory at each start, so the password exists
in plaintext only in the memory of the running process. This is the drop-in
`gp-server setup` writes by default; see *Restart mode* in the README and the
precedence note in `deploy/gp-server.service` for how the env file and the unit
interact.

The honest trade-off is unchanged and worth restating: whoever fully controls
the running host can have systemd decrypt the credential too. The till is
treated as a small hot wallet, holding a working balance and swept regularly.

## The build workspace

`/opt/goblin/gpbuild/GoblinPay/` is a **stripped** copy of this repo used to
build the deployed binary on the host. It omits `crates/gp-goblin-sender`,
the test-only crate whose path dependencies point into the sibling `goblin`
checkout, so the build needs no out-of-repo tree at all. `nip44` has come from
crates.io since 0.3.2, so it is not a sibling checkout either; `../goblin` is
now the only out-of-repo tree the full workspace ever wants.

The consequence for testing, which matters when someone says "tests pass on the
box": dropping that crate takes **7 tests** out of the run. They are the
fixture tests that drive the `gp-goblin-sender` binary as a subprocess to make
a real Goblin-side slatepack:

| Test | File |
|---|---|
| `manual_slatepack_post_round_trips_and_records_payment` | `crates/gp-server/tests/checkout_e2e.rs` |
| `goblin_pays_over_v2_gift_wrap_and_finalizes_the_reply` | `crates/gp-server/tests/nostr_ingest_e2e.rs` |
| `goblin_pays_over_v3_gift_wrap_and_finalizes_the_reply` | `crates/gp-server/tests/nostr_ingest_e2e.rs` |
| `goblin_sends_plain_armor_gp_wallet_receives_goblin_finalizes` | `crates/gp-wallet/tests/goblin_roundtrip.rs` |
| `goblin_sends_encrypted_to_gp_wallet_address_and_finalizes` | `crates/gp-wallet/tests/goblin_roundtrip.rs` |
| `payer_requests_proof_receiver_produces_and_verifies_it` | `crates/gp-wallet/tests/proof_roundtrip.rs` |
| `payer_without_proof_request_yields_no_proof` | `crates/gp-wallet/tests/proof_roundtrip.rs` |

Without the crate in the workspace these do not skip, they **fail**, with
`package ID specification 'gp-goblin-sender' did not match any packages`. So a
green run in the stripped workspace is a green run of everything except the
Goblin-side round trip, and the round trip has to be proved somewhere that has
the `goblin` checkout: a full `./ci.sh` on a machine laid out like the
development tree.

## Rollback

Deploys keep the previous binary next to the new one:

```
# before replacing it
cp /opt/goblin/goblinpay/gp-server /opt/goblin/goblinpay/gp-server.bak

# to roll back
cp /opt/goblin/goblinpay/gp-server.bak /opt/goblin/goblinpay/gp-server
systemctl restart goblin-pay
```

The database, the wallet files and the encrypted seed under `data/` are not
touched by a binary swap, so a rollback is a restart, not a restore. A release
that ships a migration is the exception: migrations move forward only, so check
`migrations/` before rolling back across one.
