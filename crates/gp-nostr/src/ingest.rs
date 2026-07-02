//! The guarded ingest pipeline: what to do with an incoming gift wrap.
//! Mirrors the shape of `goblin/src/nostr/ingest.rs` (a pure, unit-tested
//! `decide()` plus dedupe and rate limiting around it), simplified for a
//! receive-only payment server:
//!
//! - The accept policy is fixed to **auto-receive everyone** — a public till
//!   takes payments from strangers by design.
//! - Only Standard1 sends are processed, and that invariant is enforced by
//!   the WALLET (`gp_wallet::receive_slatepack` rejects everything else), so
//!   the policy here reasons about the message, not slate internals.
//! - There is no finalize/post path, no payment requests, no contacts: a
//!   reply-to-us (S2) or an invoice would target a sender wallet we do not
//!   have. They drop.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use log::{info, warn};
use nostr_sdk::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, UnsignedEvent};

use crate::{
    protocol, unix_time, IncomingContext, KeyDirectory, MasterDirectory, ReceiveError,
    SlatepackReceiver,
};

/// Rate limit for incoming wraps per sender (events/hour). A payment server
/// has no contact book, so everyone gets Goblin's unknown-sender budget.
const RATE_PER_SENDER_PER_HOUR: usize = 10;
/// Global ceiling on gift-wrap decrypt attempts per minute across ALL
/// senders (Goblin's fresh-keypair-spam bound: the per-sender limit only
/// applies after the expensive decrypt reveals the sender).
const GLOBAL_UNWRAP_PER_MIN: usize = 120;
/// Cap on remembered rate-limiter senders before pruning.
const RATE_MAP_CAP: usize = 10_000;

/// What the pipeline should do with a validated incoming message.
/// Pure policy — unit tested, no side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestDecision {
    /// A fresh payment message: receive it and reply S2 automatically.
    AutoReceive,
    /// Drop silently (reason for logging only).
    Drop(&'static str),
}

/// Inputs for the policy decision.
pub struct IngestContext<'a> {
    /// Seal-verified sender public key, hex.
    pub sender: &'a str,
    /// The sender is ourselves (wrap-to-self copy).
    pub is_self: bool,
    /// The rumor is a kind 14 DM within the size cap.
    pub rumor_is_dm: bool,
    /// The rumor content carries exactly one slatepack armor block.
    pub has_slatepack: bool,
    /// This wrap/rumor was already processed.
    pub duplicate: bool,
}

/// Pure policy function (auto-receive everyone, mirroring Goblin's shape).
pub fn decide(ctx: &IngestContext) -> IngestDecision {
    if ctx.duplicate {
        return IngestDecision::Drop("already processed");
    }
    if ctx.is_self {
        return IngestDecision::Drop("own message");
    }
    if !ctx.rumor_is_dm {
        return IngestDecision::Drop("not a kind 14 DM");
    }
    if !ctx.has_slatepack {
        return IngestDecision::Drop("no slatepack payload");
    }
    IngestDecision::AutoReceive
}

/// A reply ready to be encrypted and dispatched: the identity it is sent FROM
/// (the master key, or the derived child the payer addressed), the payer, and
/// the unsigned kind-14 rumor carrying the S2 armor. Version choice + gift
/// wrapping happen at the send site (they depend on the payer's advertised
/// 10050).
#[derive(Debug, Clone)]
pub struct PendingReply {
    pub from: Keys,
    pub payer: PublicKey,
    pub rumor: UnsignedEvent,
}

/// Outcome of handling one gift wrap event.
#[derive(Debug)]
pub enum IngestOutcome {
    /// A payment was received; dispatch the reply. Boxed: the reply carries a
    /// full key pair, far larger than the other (unit/string) variants.
    Received {
        slate_id: String,
        amount: u64,
        reply: Box<PendingReply>,
    },
    /// Dropped permanently (marked processed).
    Dropped(&'static str),
    /// Rate limited — NOT marked processed, a legitimate burst retries later.
    RateLimited,
    /// Transient receive failure — NOT marked processed, the next catch-up
    /// retries (an incoming payment is never silently lost on a hiccup).
    Failed(String),
}

/// The ingest state machine: dedupe, rate limits, unwrap, policy, handoff.
pub struct Ingest<R> {
    keys: Keys,
    receiver: R,
    /// Resolves an incoming wrap's `p` tag to the identity we hold for it
    /// (master, or a per-invoice / per-user derived child).
    directory: Arc<dyn KeyDirectory>,
    /// Processed markers: wrap ids, rumor ids, `slate:<id>` markers.
    seen: Mutex<HashSet<String>>,
    /// Per-sender sliding-window rate state (unix seconds of accepted events;
    /// the `"\0global"` key carries the global unwrap ceiling).
    rate: Mutex<HashMap<String, Vec<i64>>>,
}

impl<R: SlatepackReceiver> Ingest<R> {
    /// Ingest for the single master identity (the milestone-3 default).
    pub fn new(keys: Keys, receiver: R) -> Ingest<R> {
        let directory = Arc::new(MasterDirectory(keys.clone()));
        Ingest::with_directory(keys, receiver, directory)
    }

    /// Ingest with a multi-identity directory (master + derived children), so a
    /// payment to a per-invoice or per-user endpub unwraps and its reply is
    /// signed by that same identity.
    pub fn with_directory(keys: Keys, receiver: R, directory: Arc<dyn KeyDirectory>) -> Ingest<R> {
        Ingest {
            keys,
            receiver,
            directory,
            seen: Mutex::new(HashSet::new()),
            rate: Mutex::new(HashMap::new()),
        }
    }

    /// The wallet-handoff seam (for reconcile + status updates).
    pub fn receiver(&self) -> &R {
        &self.receiver
    }

    /// The identities we watch (for the relay subscription filter).
    pub fn watched(&self) -> Vec<PublicKey> {
        self.directory.watched()
    }

    /// Resolve a recipient pubkey (hex) to the keys we hold, for reconcile.
    pub fn resolve(&self, recipient_hex: &str) -> Option<Keys> {
        self.directory.resolve(recipient_hex)
    }

    /// Build the S2 reply rumor from `from` to `payer` (also used by
    /// reconcile). The rumor author is the identity that received the payment,
    /// so the payer's wallet associates the reply with what it paid.
    pub fn build_reply(&self, from: Keys, payer: PublicKey, s2_armor: &str) -> PendingReply {
        let mut tags = protocol::build_rumor_tags(None);
        tags.push(Tag::public_key(payer));
        let rumor = EventBuilder::new(
            Kind::PrivateDirectMessage,
            protocol::build_payment_content(s2_armor),
        )
        .tags(tags)
        .build(from.public_key());
        PendingReply { from, payer, rumor }
    }

    /// Full guarded pipeline for one incoming gift wrap event, mirroring
    /// Goblin's `handle_wrap` step for step (minus contacts/requests).
    pub async fn handle_wrap(&self, event: &Event) -> IngestOutcome {
        // 0. Only gift wraps.
        if event.kind != Kind::GiftWrap {
            return IngestOutcome::Dropped("not a gift wrap");
        }
        let wrap_id = event.id.to_hex();
        // 1. Cheap size cap before any crypto.
        if event.content.len() > protocol::MAX_WRAP_CONTENT {
            self.mark(&wrap_id);
            return IngestOutcome::Dropped("oversized wrap");
        }
        // 2. Wrap-level dedupe.
        if self.is_seen(&wrap_id) {
            return IngestOutcome::Dropped("already processed");
        }
        // 2.5 Global decrypt ceiling (fresh-keypair spam bound). Not marked
        // processed — a genuine backlog re-attempts once the window reopens.
        if !self.allow_global_unwrap() {
            return IngestOutcome::RateLimited;
        }
        // 2.7 Resolve WHICH of our identities this wrap addresses, from its
        //     public `p` tag (how relays route NIP-59), then unwrap with that
        //     key. The master identity, a per-invoice derived child, or a
        //     per-user endpub all resolve here; anything else is not for us.
        let recipient_hex = event.tags.iter().find_map(|t| {
            let parts = t.as_slice();
            if parts.first().map(|s| s.as_str()) == Some("p") {
                parts.get(1).cloned()
            } else {
                None
            }
        });
        let recipient_keys = match recipient_hex
            .as_deref()
            .and_then(|h| self.directory.resolve(h))
        {
            Some(keys) => keys,
            None => {
                self.mark(&wrap_id);
                return IngestOutcome::Dropped("not a watched identity");
            }
        };
        let recipient_hex = recipient_keys.public_key().to_hex();
        // 3. Unwrap (version-dispatching; seal signature verified, rumor
        //    author must equal the seal signer — enforced inside).
        let unwrapped = match crate::wrap::unwrap_gift_wrap(&recipient_keys, event) {
            Ok(u) => u,
            Err(_) => {
                self.mark(&wrap_id);
                return IngestOutcome::Dropped("unwrap failed");
            }
        };
        let sender_hex = unwrapped.sender.to_hex();
        let mut rumor = unwrapped.rumor;
        let rumor_id = rumor.id().to_hex();
        // 4. Policy over the message shape.
        let armor = protocol::extract_slatepack(&rumor.content);
        let decision = decide(&IngestContext {
            sender: &sender_hex,
            is_self: unwrapped.sender == self.keys.public_key(),
            rumor_is_dm: rumor.kind == Kind::PrivateDirectMessage
                && rumor.content.len() <= protocol::MAX_RUMOR_CONTENT,
            has_slatepack: armor.is_some(),
            duplicate: self.is_seen(&rumor_id),
        });
        let reason = match decision {
            IngestDecision::AutoReceive => None,
            IngestDecision::Drop(reason) => Some(reason),
        };
        if let Some(reason) = reason {
            self.mark(&wrap_id);
            self.mark(&rumor_id);
            return IngestOutcome::Dropped(reason);
        }
        // 5. Rate limit per sender. Deliberately NOT marked processed:
        //    legitimate bursts can retry later (Goblin's rule).
        if !self.allow_sender(&sender_hex) {
            warn!("ingest: rate limited sender {}…", &sender_hex[..8]);
            return IngestOutcome::RateLimited;
        }
        // 6. Hand the armor to the wallet (parse, S1-only check, receive_tx,
        //    persist, match to an invoice/user — all enforced on the wallet
        //    + core side). The memo (subject tag) and the receiving identity
        //    are what the matching layer keys off.
        let armor = armor.expect("checked by decide");
        let memo = protocol::extract_subject(&rumor.tags);
        let ctx = IncomingContext {
            payer_hex: &sender_hex,
            recipient_hex: &recipient_hex,
            memo: memo.as_deref(),
        };
        match self.receiver.receive(&armor, &ctx).await {
            Ok(payment) => {
                // Durable: commit dedupe markers before the reply leg, so a
                // crash there cannot re-trigger a second receive on catch-up
                // (grin's TransactionAlreadyReceived also backstops this).
                self.mark(&wrap_id);
                self.mark(&rumor_id);
                self.mark(&format!("slate:{}", payment.slate_id));
                info!(
                    "ingest: received slate {} ({} nanogrin) from {}…",
                    payment.slate_id,
                    payment.amount,
                    &sender_hex[..8]
                );
                let reply = self.build_reply(recipient_keys, unwrapped.sender, &payment.s2_armor);
                IngestOutcome::Received {
                    slate_id: payment.slate_id,
                    amount: payment.amount,
                    reply: Box::new(reply),
                }
            }
            Err(ReceiveError::Duplicate) => {
                self.mark(&wrap_id);
                self.mark(&rumor_id);
                IngestOutcome::Dropped("slate already received")
            }
            Err(ReceiveError::Rejected(m)) => {
                self.mark(&wrap_id);
                self.mark(&rumor_id);
                warn!("ingest: rejected slatepack from {}…: {m}", &sender_hex[..8]);
                IngestOutcome::Dropped("invalid slatepack")
            }
            // Transient: leave UNMARKED so the next catch-up retries.
            Err(ReceiveError::Failed(m)) => IngestOutcome::Failed(m),
        }
    }

    fn is_seen(&self, key: &str) -> bool {
        self.seen.lock().expect("seen lock").contains(key)
    }

    fn mark(&self, key: &str) {
        self.seen.lock().expect("seen lock").insert(key.to_string());
    }

    /// Sliding-window per-sender rate limiter (Goblin's `allow_sender`).
    fn allow_sender(&self, sender: &str) -> bool {
        let now = unix_time();
        let mut rate = self.rate.lock().expect("rate lock");
        let hits = rate.entry(sender.to_string()).or_default();
        hits.retain(|t| now - *t < 3600);
        if hits.len() >= RATE_PER_SENDER_PER_HOUR {
            return false;
        }
        hits.push(now);
        if rate.len() > RATE_MAP_CAP {
            rate.retain(|_, v| v.iter().any(|t| now - *t < 3600));
        }
        true
    }

    /// Global unwrap ceiling (Goblin's `allow_global_unwrap`).
    fn allow_global_unwrap(&self) -> bool {
        let now = unix_time();
        let mut rate = self.rate.lock().expect("rate lock");
        let hits = rate.entry("\0global".to_string()).or_default();
        hits.retain(|t| now - *t < 60);
        if hits.len() >= GLOBAL_UNWRAP_PER_MIN {
            return false;
        }
        hits.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use nostr_sdk::EventBuilder;

    use super::*;
    use crate::{ReceivedPayment, UnrepliedPayment};

    const ALICE: &str = "91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05";

    fn ctx<'a>(sender: &'a str) -> IngestContext<'a> {
        IngestContext {
            sender,
            is_self: false,
            rumor_is_dm: true,
            has_slatepack: true,
            duplicate: false,
        }
    }

    #[test]
    fn fresh_payment_auto_receives_from_anyone() {
        assert_eq!(decide(&ctx(ALICE)), IngestDecision::AutoReceive);
    }

    #[test]
    fn duplicates_own_messages_and_junk_drop() {
        let mut c = ctx(ALICE);
        c.duplicate = true;
        assert!(matches!(decide(&c), IngestDecision::Drop(_)));

        let mut c = ctx(ALICE);
        c.is_self = true;
        assert!(matches!(decide(&c), IngestDecision::Drop(_)));

        let mut c = ctx(ALICE);
        c.rumor_is_dm = false;
        assert!(matches!(decide(&c), IngestDecision::Drop(_)));

        let mut c = ctx(ALICE);
        c.has_slatepack = false;
        assert!(matches!(decide(&c), IngestDecision::Drop(_)));
    }

    /// A directory over an explicit set of identities, for the derived-key test.
    struct MultiDirectory(Vec<Keys>);

    impl KeyDirectory for MultiDirectory {
        fn resolve(&self, recipient_hex: &str) -> Option<Keys> {
            self.0
                .iter()
                .find(|k| k.public_key().to_hex() == recipient_hex)
                .cloned()
        }

        fn watched(&self) -> Vec<PublicKey> {
            self.0.iter().map(|k| k.public_key()).collect()
        }
    }

    /// Scripted stand-in for the wallet handoff. Captures the last context so
    /// tests can assert the recipient identity and memo were threaded through.
    struct StubReceiver {
        outcomes: StdMutex<Vec<Result<ReceivedPayment, ReceiveError>>>,
        calls: StdMutex<usize>,
        last_recipient: StdMutex<Option<String>>,
        last_memo: StdMutex<Option<String>>,
    }

    impl StubReceiver {
        fn new(outcomes: Vec<Result<ReceivedPayment, ReceiveError>>) -> StubReceiver {
            StubReceiver {
                outcomes: StdMutex::new(outcomes),
                calls: StdMutex::new(0),
                last_recipient: StdMutex::new(None),
                last_memo: StdMutex::new(None),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl SlatepackReceiver for StubReceiver {
        async fn receive(
            &self,
            _s1_armor: &str,
            ctx: &IncomingContext<'_>,
        ) -> Result<ReceivedPayment, ReceiveError> {
            *self.calls.lock().unwrap() += 1;
            *self.last_recipient.lock().unwrap() = Some(ctx.recipient_hex.to_string());
            *self.last_memo.lock().unwrap() = ctx.memo.map(|m| m.to_string());
            self.outcomes.lock().unwrap().remove(0)
        }

        async fn mark_replied(&self, _slate_id: &str) {}

        async fn unreplied(&self) -> Vec<UnrepliedPayment> {
            vec![]
        }
    }

    const PACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
        pcXQhyRkHbyKHZg GN75o7uWoT3dkib. ENDSLATEPACK.";

    fn payment_wrap(payer: &Keys, server: &Keys, version: crate::wrap::WrapVersion) -> Event {
        payment_wrap_noted(payer, server, version, "test")
    }

    /// Like [`payment_wrap`] but with a distinct note, so rumors built within
    /// the same second (same content, seconds-resolution `created_at`) do not
    /// collide on the rumor id — distinct real payments always differ by
    /// their slatepack.
    fn payment_wrap_noted(
        payer: &Keys,
        server: &Keys,
        version: crate::wrap::WrapVersion,
        note: &str,
    ) -> Event {
        let mut tags = protocol::build_rumor_tags(Some(note));
        tags.push(Tag::public_key(server.public_key()));
        let rumor = EventBuilder::new(
            Kind::PrivateDirectMessage,
            protocol::build_payment_content(PACK),
        )
        .tags(tags)
        .build(payer.public_key());
        crate::wrap::gift_wrap(payer, &server.public_key(), rumor, version).unwrap()
    }

    #[tokio::test]
    async fn pipeline_receives_replies_and_dedupes() {
        let payer = Keys::generate();
        let server = Keys::generate();
        let ingest = Ingest::new(
            server.clone(),
            StubReceiver::new(vec![Ok(ReceivedPayment {
                slate_id: "slate-1".into(),
                amount: 42,
                s2_armor: "BEGINSLATEPACK. reply. ENDSLATEPACK.".into(),
            })]),
        );
        let wrap = payment_wrap(&payer, &server, crate::wrap::WrapVersion::V3);

        let outcome = ingest.handle_wrap(&wrap).await;
        let reply = match outcome {
            IngestOutcome::Received {
                slate_id,
                amount,
                reply,
            } => {
                assert_eq!(slate_id, "slate-1");
                assert_eq!(amount, 42);
                reply
            }
            other => panic!("expected Received, got {other:?}"),
        };
        assert_eq!(reply.payer, payer.public_key());
        assert_eq!(reply.rumor.kind, Kind::PrivateDirectMessage);
        assert!(protocol::extract_slatepack(&reply.rumor.content).is_some());

        // The same wrap again drops without another wallet call.
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Dropped(_)
        ));
        assert_eq!(ingest.receiver().calls(), 1);
    }

    #[tokio::test]
    async fn transient_failure_is_retryable_permanent_rejection_is_not() {
        let payer = Keys::generate();
        let server = Keys::generate();
        let ingest = Ingest::new(
            server.clone(),
            StubReceiver::new(vec![
                Err(ReceiveError::Failed("wallet hiccup".into())),
                Ok(ReceivedPayment {
                    slate_id: "slate-2".into(),
                    amount: 7,
                    s2_armor: "BEGINSLATEPACK. r. ENDSLATEPACK.".into(),
                }),
            ]),
        );
        let wrap = payment_wrap(&payer, &server, crate::wrap::WrapVersion::V2);

        // Transient failure leaves the wrap unmarked...
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Failed(_)
        ));
        // ...so the catch-up retry succeeds.
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Received { .. }
        ));

        // A rejected slatepack is a permanent drop.
        let ingest = Ingest::new(
            server.clone(),
            StubReceiver::new(vec![Err(ReceiveError::Rejected("not S1".into()))]),
        );
        let wrap = payment_wrap(&payer, &server, crate::wrap::WrapVersion::V2);
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Dropped(_)
        ));
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Dropped("already processed")
        ));
        assert_eq!(ingest.receiver().calls(), 1);
    }

    #[tokio::test]
    async fn non_payment_messages_never_reach_the_wallet() {
        let payer = Keys::generate();
        let server = Keys::generate();
        let ingest = Ingest::new(server.clone(), StubReceiver::new(vec![]));

        // A DM without a slatepack.
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "just chatting")
            .tags([Tag::public_key(server.public_key())])
            .build(payer.public_key());
        let wrap = crate::wrap::gift_wrap(
            &payer,
            &server.public_key(),
            rumor,
            crate::wrap::WrapVersion::V2,
        )
        .unwrap();
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Dropped("no slatepack payload")
        ));

        // A non-gift-wrap event.
        let plain = EventBuilder::new(Kind::TextNote, "hello")
            .sign_with_keys(&payer)
            .unwrap();
        assert!(matches!(
            ingest.handle_wrap(&plain).await,
            IngestOutcome::Dropped("not a gift wrap")
        ));

        // A wrap addressed to someone else: its `p` tag resolves to no
        // identity we watch, so it drops before any decrypt attempt.
        let other = Keys::generate();
        let wrap = payment_wrap(&payer, &other, crate::wrap::WrapVersion::V3);
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::Dropped("not a watched identity")
        ));
        assert_eq!(ingest.receiver().calls(), 0);
    }

    #[tokio::test]
    async fn per_sender_rate_limit_kicks_in() {
        let payer = Keys::generate();
        let server = Keys::generate();
        let outcomes = (0..RATE_PER_SENDER_PER_HOUR)
            .map(|i| {
                Ok(ReceivedPayment {
                    slate_id: format!("slate-{i}"),
                    amount: 1,
                    s2_armor: "BEGINSLATEPACK. r. ENDSLATEPACK.".into(),
                })
            })
            .collect();
        let ingest = Ingest::new(server.clone(), StubReceiver::new(outcomes));

        for i in 0..RATE_PER_SENDER_PER_HOUR {
            let wrap = payment_wrap_noted(
                &payer,
                &server,
                crate::wrap::WrapVersion::V2,
                &format!("payment {i}"),
            );
            assert!(matches!(
                ingest.handle_wrap(&wrap).await,
                IngestOutcome::Received { .. }
            ));
        }
        // One more within the hour: rate limited, wallet untouched.
        let wrap = payment_wrap_noted(
            &payer,
            &server,
            crate::wrap::WrapVersion::V2,
            "one too many",
        );
        assert!(matches!(
            ingest.handle_wrap(&wrap).await,
            IngestOutcome::RateLimited
        ));
        assert_eq!(ingest.receiver().calls(), RATE_PER_SENDER_PER_HOUR);
    }

    #[tokio::test]
    async fn derived_identity_is_resolved_and_reply_signed_from_it() {
        // A payment addressed to a derived child (not the master) unwraps via
        // the directory, threads the recipient + memo to the wallet handoff,
        // and its reply is signed FROM the derived identity the payer paid.
        let payer = Keys::generate();
        let master = Keys::generate();
        let derived = Keys::generate(); // stands in for a per-invoice child
        let directory = Arc::new(MultiDirectory(vec![master.clone(), derived.clone()]));
        let ingest = Ingest::with_directory(
            master.clone(),
            StubReceiver::new(vec![Ok(ReceivedPayment {
                slate_id: "slate-x".into(),
                amount: 5,
                s2_armor: "BEGINSLATEPACK. r. ENDSLATEPACK.".into(),
            })]),
            directory,
        );

        // Payer wraps to the DERIVED key with an order memo.
        let mut tags = protocol::build_rumor_tags(Some("order-99"));
        tags.push(Tag::public_key(derived.public_key()));
        let rumor = EventBuilder::new(
            Kind::PrivateDirectMessage,
            protocol::build_payment_content(PACK),
        )
        .tags(tags)
        .build(payer.public_key());
        let wrap = crate::wrap::gift_wrap(
            &payer,
            &derived.public_key(),
            rumor,
            crate::wrap::WrapVersion::V3,
        )
        .unwrap();

        let reply = match ingest.handle_wrap(&wrap).await {
            IngestOutcome::Received { reply, .. } => reply,
            other => panic!("expected Received, got {other:?}"),
        };
        // The reply comes FROM the derived identity, TO the payer.
        assert_eq!(reply.from.public_key(), derived.public_key());
        assert_eq!(reply.payer, payer.public_key());
        // The wallet handoff saw the derived recipient and the memo.
        assert_eq!(
            ingest.receiver().last_recipient.lock().unwrap().as_deref(),
            Some(derived.public_key().to_hex().as_str())
        );
        assert_eq!(
            ingest.receiver().last_memo.lock().unwrap().as_deref(),
            Some("order-99")
        );
    }
}
