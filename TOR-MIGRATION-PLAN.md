# GoblinPay's part of the Nym → Tor migration

**Status:** Planning document only — no code or config changed by this document.
**Date:** 2026-07-04
**Scope:** What, if anything, GoblinPay needs to do as Goblin moves its Nostr transport off the Nym mixnet and onto Tor. The overall decision and the wallet-side work are covered in `goblin/docs/PRIVACY-TRANSPORT-REDESIGN.md` — that document is the source of truth for *why* this move is happening; this one is about GoblinPay specifically.

The short version, up front: GoblinPay is already in the state this migration is trying to reach. There is no fire here, and most of what follows is either "nothing to do" or "housekeeping, whenever it's convenient."

---

## The framing, carried through

The wallet plan puts it this way: **Tor hides the user's IP from the relay; the relay + protocol hide everything else.** That framing is worth restating here because it explains why GoblinPay's part of this story is small. GoblinPay is receive-only infrastructure, not the party whose IP privacy is actually at stake in a payment — that's the paying customer, and their privacy rides on their own Goblin Wallet, not on anything GoblinPay does. And the "protocol hides everything else" half of that sentence — NIP-44 encryption inside a NIP-59 gift-wrap — was never Nym's job to begin with, and nothing about this migration touches it.

---

## Phase 0 / where we stand today: nothing is broken, nothing is urgent

GoblinPay has had its own in-process Nym mixnet client since it was built — a direct port of the wallet's, living at `crates/gp-nostr/src/nym/` — gated behind an environment variable, `GP_NYM`, in `/opt/goblin/goblinpay/goblinpay.env` on us-east.

**`GP_NYM` is already set to `off` in production, and has been for more than a day.** That was confirmed on a live check of the running server. Practically, this means GoblinPay is not caught up in the mixnet's death at all: it is already reaching its relays over clearnet, today, in production, live, taking real payments — which is exactly the end state this whole migration is aiming for. There's no incident to respond to and no clock running out.

It's worth being precise about what "off" actually means at runtime, because it's a clean switch rather than a degraded state. Reading `crates/gp-nostr/src/service.rs`: when the config's `opts.nym` is false, the code takes a genuinely separate branch — it builds a plain Nostr client with no Nym transport wired in at all (no tunnel start, no warm-up wait, no dial attempt), and logs a calm, expected line on every boot: `GP_NYM=off — this server's relay traffic goes CLEARNET (supported: the payer's wallet still provides sender privacy; the payload stays gift-wrapped)`. That's not a fallback after something failed; it's an intentional, supported posture the code was written to handle. The surrounding comments in the codebase say as much directly: `GP_NYM=off` is "a supported production posture, not just a debugging switch."

One thing worth flagging so it doesn't read as a discrepancy: the *default* baked into the code, if the environment variable were ever unset, is still `on` (`crates/gp-core/src/config.rs`, and `deploy/.env.example` ships `GP_NYM=on` as its template default). Production has explicitly overridden that default to `off`. That override predates this plan — whoever set it made the right call already, presumably as GoblinPay was riding out the mixnet's earlier flakiness. This document doesn't need to change that decision; it just needs to catch up the paperwork and, eventually, the code, to match it.

---

## What doesn't change: encryption and payer privacy are someone else's job

Two things that are easy to lump in with "the Nym migration" but are actually untouched by any of it:

**Content encryption.** Every payment that arrives as a Nostr message is sealed with NIP-44 inside a NIP-59 gift-wrap (kind 1059), exactly as it is today. That's a property of the message format, not of the pipe it travels through. Nothing about the wallet moving from Nym to Tor, and nothing about GoblinPay's own `GP_NYM` setting, has ever touched this.

**Payer privacy.** The privacy a paying customer actually gets — their IP hidden from the relay, and the timing-privacy work the wallet plan describes — comes entirely from the *customer's* own Goblin Wallet and whatever transport it uses. That was true when the wallet used Nym and stays true once it uses Tor. GoblinPay's `GP_NYM` setting never had anything to do with it: that switch only ever controlled whether *GoblinPay's own server* hid its own IP from the relay it talks to — a much narrower, much lower-stakes thing. So the wallet's move to Tor improves the customer's privacy on its own, with no required change on GoblinPay's side at all.

Worth stating here too, since it's easy to forget when talking about "the Nostr path": GoblinPay also accepts payment by having the customer paste a slatepack (`grin1`) directly into the checkout page, with no Goblin Wallet and no Nostr involved. That path is plain HTTPS from end to end and has never gone anywhere near Nym, and won't go anywhere near Tor either. It's structurally outside this entire migration.

---

## Cleanup phase: retiring the ported Nym client (do this once the wallet's Tor build is out and settled)

This is not urgent — it's housekeeping to schedule after the wallet's own Tor migration has shipped and had some time to prove itself, so GoblinPay isn't left as the one place still carrying old ported code for no live reason.

GoblinPay's copy of the Nym client lives at `crates/gp-nostr/src/nym/`: four files (`mod.rs`, `transport.rs`, `nymproc.rs`, `dns.rs`) totaling 599 lines, ported from the wallet's own `src/nym`. It's linked in-process through a path dependency on `smolmix` (`crates/gp-nostr/Cargo.toml`, pinned to a specific revision of the sibling `nym` checkout), plus `hickory-proto`, which is only in the dependency graph to give `nym/dns.rs` its mix-DNS wire codec — nothing else in `gp-nostr` calls it.

Because `GP_NYM` is already off in production, deleting all of this is **pure subtraction**: the code path that remains after the deletion is the exact code path already running live today, so there's no behavior to migrate and no new path to prove out — just less code to carry. The concrete list:

- Delete `crates/gp-nostr/src/nym/` in full (all four files, 599 lines).
- Remove the `smolmix` and `hickory-proto` dependency declarations from `crates/gp-nostr/Cargo.toml`, along with the comment block explaining the pinned revision.
- Remove the `GP_NYM` (and the debug-only `GP_NYM_IPR` exit-pin override) config plumbing from `crates/gp-core/src/config.rs`, and the `opts.nym` if/else branch in `crates/gp-nostr/src/service.rs`. After this, GoblinPay simply always builds the plain clearnet client — again, exactly what it already does.
- Trim the *nym-specific slice* of the build plumbing. This needs one careful distinction, because the Dockerfile and compose file currently vendor two sibling trees together, and only one of them is going away:
  - `deploy/Dockerfile` vendors both `nip44/` and `nym/` as sibling checkouts (see its header comment and the `COPY nip44` / `COPY nym` lines). Only the `nym` half is Nym-related — `nip44` is the unrelated NIP-44 v3 companion crate and isn't part of this migration. So: drop the `COPY nym ./nym` line and the parts of the header comment naming `nym` as a required sibling, but **keep** the `nip44` vendoring and the workspace-parent build context that supports it.
  - `deploy/docker-compose.yml` justifies its `context: ../..` build context (instead of building from the repo root) by pointing at both `nip44/` and `nym/` as sibling trees the Dockerfile needs. That context has to stay for `nip44`'s sake regardless of this cleanup — only its comment's mention of `nym/` should come out.
  - `deploy/install.sh` has the same "build prerequisite" comment naming both sibling trees; trim the `nym/` mention, keep the `nip44/` one.
  - `.gitea/workflows/ci.yml` and `.github/workflows/ci.yml` (both at line 52) gate the full CI test run on three sibling checkouts being present: `../nip44`, `../nym/smolmix/core`, and `../goblin`. Drop the `nym` leg of that check; keep the other two.

End state: a smaller dependency tree, one fewer pinned external-repo revision to track, and — because production has already been running without it — no behavior change to test for beyond "GoblinPay still boots and still moves money."

---

## Optional parity phase: hiding GoblinPay's own server-to-relay hop

If there's ever a reason to go further, GoblinPay could dial its co-located relay over that relay's `.onion` address — the same onion service the wallet will be pinning and dialing — instead of reaching it over clearnet. That would restore the one thing `GP_NYM` used to provide: hiding GoblinPay's own server IP from the relay it talks to.

This is genuinely optional, not a recommended follow-on. The relays it would apply to — `relay.floonet.dev`, and `nrelay.us-ea.st` once its container is running again — are co-located on the same box as GoblinPay itself. Reaching them is already close to a localhost hop, so there's very little real exposure left to close. Worth doing only if it falls out cheaply once those relays' onion services exist for the wallet's sake anyway — not worth its own dedicated effort.

---

## A decision for the owner: trim the relay list?

GoblinPay currently runs in `external` relay mode with three relays configured: `relay.floonet.dev` and `nrelay.us-ea.st`, both co-located on the same box as GoblinPay (the latter's backend container is currently crashed — a separate, pre-existing infra issue, addressed below, not part of this migration), and `relay.damus.io`, a genuine public third-party relay.

Because `relay.damus.io` is a real external party, it sees GoblinPay's server IP on every connection, in the clear — and the optional onion-dialing above wouldn't change that, since damus.io isn't one of the co-located relays it would apply to. Trimming `GP_RELAYS` down to the co-located relay(s) only, done alongside the cleanup phase, would remove that exposure entirely.

The tradeoff, stated plainly: fewer relays means less redundant reach if a co-located relay goes down — which is exactly the situation with `nrelay.us-ea.st` right now, and with only `relay.floonet.dev` left in that scenario, GoblinPay's inbox would have no relay left to fall back on. Weighed against that is one fewer third party watching the server's connection metadata. This is a real reliability-versus-exposure call, and it belongs to the owner — this plan is flagging it, not making it.

---

## Copy fixes

Three connector-facing strings currently describe a payment as traveling "over Nostr (optionally over the Nym mixnet)":

- `connectors/woocommerce/goblinpay-woocommerce.php:5` (the plugin's `Description:` header)
- `connectors/woocommerce/README.md:6`
- `connectors/medusa/README.md:6`

Worth reading these carefully before editing them, because the parenthetical describes the *payer's* wallet transport (the customer's Goblin Wallet choosing how to reach the relay) — GoblinPay has no say in that hop at all. So once the wallet ships Tor, the honest fix isn't a find-and-replace of "Nym" with "Tor" as if it were GoblinPay's own setting — it's rewording to make clear this is about the payer's wallet, something like "(the payer's wallet may route this over Tor)," or simply dropping the parenthetical if it reads as clutter in a merchant-facing doc.

Two more mentions turned up while confirming these file details, both describing GoblinPay's *own* transport rather than the payer's, and both outside the three files above: the root `README.md` has a paragraph (around line 44) explaining that "by default all relay traffic rides an in-process Nym mixnet tunnel," and a `GP_NYM` row in its configuration table (around line 84). `deploy/.env.example`'s `GP_NYM=on` line and its surrounding comment describe the same thing. These three shouldn't be reworded to say "Tor" — GoblinPay isn't gaining a Tor transport of its own, it's simply losing the Nym one it had — so they should be rewritten or deleted as part of the cleanup phase above, alongside the code they describe, rather than treated as a standalone copy pass now.

Net: the three connector-doc fixes are a small, low-risk, copy-only change that can land anytime, independent of everything else here. The `README.md` / `.env.example` mentions should wait and land together with the cleanup phase, since they document code that phase removes.

---

## Risks and notes

- **This is a live store.** GoblinPay is processing real payments into the cryptodrip WooCommerce store. Even though the cleanup phase is pure subtraction of already-unused code, build and test it off-prod first (a branch build, or at minimum a staging run of `gp-server`) before it lands on us-east.
- **The slatepack (`grin1`) path must keep working exactly as it does today.** It's structurally untouched by everything in this plan (it never used Nostr), but "nothing should have changed" is worth a deliberate regression check after the cleanup phase rather than an assumption.
- **`nrelay.us-ea.st`'s crashed backend container is a separate, pre-existing issue.** It's mentioned here only because it happens to be one of the three relays in GoblinPay's list. Fixing it is out of scope for this plan and should be handled on its own.
- **None of this is time-pressured.** The thing that made the wallet's migration urgent — Nym's free-bandwidth grant expiring on a schedule and the paid replacement requiring a token the project won't hold — doesn't apply here, because `GP_NYM` is already off. Sequence the cleanup phase whenever convenient, ideally after the wallet's Tor build has shipped and proven itself.

---

## Bottom line

GoblinPay doesn't need to do anything today. `GP_NYM=off` is already the stable, running posture in production and has been for a while — GoblinPay's server traffic already goes over clearnet to its relays, which is exactly where it would end up even if every step below were finished tomorrow. What's left is housekeeping: delete the 599-line ported Nym client and its dependencies once the dust settles, fix three doc strings that describe the *payer's* transport (not GoblinPay's), and let the owner weigh in on whether `relay.damus.io` stays in the relay list. The things that actually matter for a customer's privacy — the gift-wrap encryption, and the customer's own wallet's transport — were never GoblinPay's to change in the first place.
