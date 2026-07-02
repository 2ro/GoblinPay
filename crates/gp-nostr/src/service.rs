//! The daemon service loop, adapted from `goblin/src/nostr/client.rs`
//! (`run_service`): connect the relay pool over the in-process Nym mixnet,
//! publish the kind 10050 inbox (with the NIP-17 `encryption` capability
//! tag) and its kind 10002 mirror, catch up on missed gift wraps, subscribe
//! live, and for every received payment dispatch the S2 reply to the payer's
//! advertised relays (their 10050; our own set as the fallback), encrypted
//! with the best mutual NIP-44 version.
//!
//! No UI, no contacts, no relay-pool gist (G10 is pending): the relay set is
//! configuration plus defaults.

use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use nostr_sdk::{
    Client, Event, EventBuilder, Filter, Keys, Kind, PublicKey, RelayPoolNotification, RelayUrl,
    Tag, TagKind, Timestamp,
};

use crate::ingest::{Ingest, IngestOutcome, PendingReply};
use crate::nym::NymWebSocketTransport;
use crate::relays::MAX_DM_RELAYS;
use crate::unix_time;
use crate::wrap;
use crate::{KeyDirectory, MasterDirectory, SlatepackReceiver};

/// Subscription look-back window: gift wrap timestamps are randomized up to
/// 2 days into the past (NIP-59), use 3 (Goblin's constant). Cross-restart
/// dedupe is the wallet's already-received guard plus the payment table.
const LOOKBACK_SECS: i64 = 3 * 86_400;
/// Catch-up fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Send dispatch timeout.
const SEND_TIMEOUT: Duration = Duration::from_secs(40);
/// How long to wait for the mixnet tunnel before dialing relays anyway.
const NYM_WARM_WAIT: Duration = Duration::from_secs(30);

/// Service configuration (already resolved from the environment).
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    /// Relay set to listen on and publish to.
    pub relays: Vec<String>,
    /// Route everything over the Nym mixnet (default on; clearnet is a
    /// debugging escape hatch only).
    pub nym: bool,
    /// Optional NIP-17 payment DMs (milestone 6, all off by default).
    pub notify: NotifyOptions,
}

/// Optional payment-notification DMs (milestone 6). Both are off by default.
#[derive(Debug, Clone, Default)]
pub struct NotifyOptions {
    /// Merchant public key for the confirmed-payment DM.
    pub merchant: Option<PublicKey>,
    /// Send the merchant a NIP-17 DM on a received payment.
    pub merchant_dm: bool,
    /// Send the payer a NIP-17 receipt DM.
    pub payer_receipt: bool,
}

/// Merchant DM text for a received payment.
pub fn merchant_dm_text(amount: u64, slate_id: &str) -> String {
    format!(
        "[GoblinPay] Received {} GRIN (slate {}).",
        gp_core::webhook::nanogrin_to_grin(amount),
        slate_id
    )
}

/// Payer receipt DM text.
pub fn payer_receipt_text(amount: u64) -> String {
    format!(
        "[GoblinPay] Payment of {} GRIN received. Thank you.",
        gp_core::webhook::nanogrin_to_grin(amount)
    )
}

/// Start the ingest service on its own thread with its own tokio runtime
/// (mirrors Goblin's service thread; keeps relay I/O off the HTTP runtime).
/// Watches the master identity only.
pub fn spawn<R>(keys: Keys, opts: ServiceOptions, receiver: R) -> std::thread::JoinHandle<()>
where
    R: SlatepackReceiver + 'static,
{
    let directory: Arc<dyn KeyDirectory> = Arc::new(MasterDirectory(keys.clone()));
    spawn_with_directory(keys, opts, receiver, directory)
}

/// Like [`spawn`] but with a multi-identity directory (master + per-invoice and
/// per-user derived children), so payments to any watched endpub are received
/// and replied from the right identity.
pub fn spawn_with_directory<R>(
    keys: Keys,
    opts: ServiceOptions,
    receiver: R,
    directory: Arc<dyn KeyDirectory>,
) -> std::thread::JoinHandle<()>
where
    R: SlatepackReceiver + 'static,
{
    std::thread::Builder::new()
        .name("gp-nostr".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build gp-nostr runtime");
            rt.block_on(run(keys, opts, receiver, directory));
        })
        .expect("spawn gp-nostr thread")
}

/// The service loop. Runs until the process exits (a payment server has no
/// reason to stop listening).
pub async fn run<R: SlatepackReceiver>(
    keys: Keys,
    opts: ServiceOptions,
    receiver: R,
    directory: Arc<dyn KeyDirectory>,
) {
    let client = if opts.nym {
        // Wait for the in-process Nym mixnet tunnel before any network work:
        // dialing before it is up drops every relay into the pool's
        // backing-off reconnect (Goblin's wallet-open ordering lesson).
        crate::nym::warm_up();
        let waited = std::time::Instant::now();
        while !crate::nym::is_ready() && waited.elapsed() < NYM_WARM_WAIT {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if crate::nym::is_ready() {
            info!(
                "nostr: Nym tunnel ready after ~{}ms",
                waited.elapsed().as_millis()
            );
        } else {
            warn!("nostr: Nym tunnel still warming; relays will retry through it");
        }
        Client::builder()
            .websocket_transport(NymWebSocketTransport)
            .build()
    } else {
        warn!("nostr: GP_NYM=off — relay traffic goes CLEARNET (debugging only)");
        Client::builder().build()
    };

    let ingest = Ingest::with_directory(keys.clone(), receiver, directory);
    let npub_prefix: String = keys.public_key().to_hex().chars().take(8).collect();
    info!(
        "nostr: starting service for {npub_prefix}… with {} relay(s)",
        opts.relays.len()
    );
    for relay in &opts.relays {
        if let Err(e) = client.add_relay(relay.clone()).await {
            warn!("nostr: add relay failed: {e}");
        }
    }
    client.connect().await;

    // Publish the replaceable identity events: kind 10050 DM relays with the
    // encryption capability tag, plus the kind 10002 (NIP-65) mirror. No
    // kind 0 — the till is anonymous by design.
    publish_inbox(&client, &keys, &opts.relays).await;

    // Re-dispatch stored replies that never verifiably left (crash between
    // receive_tx and the reply send) before processing anything new.
    reconcile(&client, &ingest, &opts.relays).await;

    // Catch-up + live subscription for gift wraps addressed to any identity we
    // watch: the master, plus per-invoice (matching mode 2) and per-user (5b)
    // derived children the directory currently holds. Targeted at our OWN
    // advertised set only (a pool-wide subscription would leak the listener
    // filter to relays added later for reply fan-out). The watched set is
    // snapshotted here; rotation refreshes it on the next service restart or
    // re-subscribe (a live refresh tick is the multi-tenant follow-up).
    let since = (unix_time() - LOOKBACK_SECS).max(0) as u64;
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkeys(ingest.watched())
        .since(Timestamp::from_secs(since));
    match client
        .fetch_events_from(&opts.relays, filter.clone(), FETCH_TIMEOUT)
        .await
    {
        Ok(events) => {
            info!("nostr: catch-up fetched {} wrap(s)", events.len());
            for event in events.into_iter() {
                handle(&client, &ingest, &keys, &opts.notify, &event, &opts.relays).await;
            }
        }
        Err(e) => warn!("nostr: catch-up fetch failed: {e}"),
    }
    if let Err(e) = client.subscribe_to(&opts.relays, filter, None).await {
        error!("nostr: subscribe failed: {e}");
    }

    let mut notifications = client.notifications();
    loop {
        match notifications.recv().await {
            Ok(RelayPoolNotification::Event { event, .. }) => {
                handle(&client, &ingest, &keys, &opts.notify, &event, &opts.relays).await;
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!("nostr: notifications lagged by {n}");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    error!("nostr: notification stream closed; service stopped");
}

/// Handle one incoming event end to end: ingest, dispatch the reply, then
/// (if configured) send the optional merchant / payer NIP-17 DMs.
async fn handle<R: SlatepackReceiver>(
    client: &Client,
    ingest: &Ingest<R>,
    keys: &Keys,
    notify: &NotifyOptions,
    event: &Event,
    own_relays: &[String],
) {
    match ingest.handle_wrap(event).await {
        IngestOutcome::Received {
            slate_id,
            amount,
            reply,
        } => {
            // Optional notifications (M6): merchant DM from the server identity,
            // payer receipt from the identity that received. Best effort; a
            // failed DM never affects the money or the reply.
            if notify.merchant_dm {
                if let Some(merchant) = &notify.merchant {
                    send_dm(
                        client,
                        keys,
                        merchant,
                        merchant_dm_text(amount, &slate_id),
                        own_relays,
                    )
                    .await;
                }
            }
            if notify.payer_receipt {
                send_dm(
                    client,
                    &reply.from,
                    &reply.payer,
                    payer_receipt_text(amount),
                    own_relays,
                )
                .await;
            }
            if deliver_reply(client, &reply, own_relays).await {
                ingest.receiver().mark_replied(&slate_id).await;
            } else {
                // Left in status 'received': the boot-time reconcile (or a
                // restart) re-sends it. The payment itself is safe in the
                // wallet either way.
                warn!("nostr: S2 reply dispatch failed for slate {slate_id}, will reconcile");
            }
        }
        IngestOutcome::Dropped(reason) => {
            info!("nostr: dropped wrap {}…: {reason}", &event.id.to_hex()[..8]);
        }
        IngestOutcome::RateLimited => {}
        IngestOutcome::Failed(e) => {
            error!("nostr: receive failed (will retry on catch-up): {e}");
        }
    }
}

/// Gift wrap and publish one S2 reply, FROM the identity that received the
/// payment (master or the derived child the payer addressed). Targets the
/// payer's advertised 10050 relays when discoverable, else our own set
/// (Goblin's send-target fallback); the encryption version is the best mutual
/// method from the same 10050 (absent = v2). Returns true when a relay
/// accepted the event.
async fn deliver_reply(client: &Client, reply: &PendingReply, own_relays: &[String]) -> bool {
    let (mut targets, encryption) = recipient_hints(client, &reply.payer, own_relays).await;
    if targets.is_empty() {
        // NIP-17 pragmatic fallback: the wrap reached us through a shared
        // relay, so our own set is the best remaining route.
        targets = own_relays.to_vec();
    }
    let version = wrap::choose_version(encryption.as_deref());
    let event = match wrap::gift_wrap(&reply.from, &reply.payer, reply.rumor.clone(), version) {
        Ok(event) => event,
        Err(e) => {
            error!("nostr: reply wrap failed: {e}");
            return false;
        }
    };
    // Dial any target relays we don't already hold (the payer's relays may
    // differ from ours), then publish to exactly that set.
    connect_relays(client, &targets).await;
    match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&targets, &event)).await {
        Ok(Ok(output)) => {
            info!(
                "nostr: S2 reply {}… published ({:?}, {} relay(s) ok)",
                &output.val.to_hex()[..8],
                version,
                output.success.len()
            );
            !output.success.is_empty()
        }
        Ok(Err(e)) => {
            warn!("nostr: reply publish failed: {e}");
            false
        }
        Err(_) => {
            warn!("nostr: reply publish timed out");
            false
        }
    }
}

/// Send a plain NIP-17 DM `from` an identity `to` a recipient (the optional
/// M6 merchant/payer notifications). Version is negotiated from the
/// recipient's 10050 like a reply; best effort, errors are logged only.
async fn send_dm(
    client: &Client,
    from: &Keys,
    to: &PublicKey,
    content: String,
    own_relays: &[String],
) {
    let rumor = EventBuilder::new(Kind::PrivateDirectMessage, content)
        .tags([Tag::public_key(*to)])
        .build(from.public_key());
    let (mut targets, encryption) = recipient_hints(client, to, own_relays).await;
    if targets.is_empty() {
        targets = own_relays.to_vec();
    }
    let version = wrap::choose_version(encryption.as_deref());
    let event = match wrap::gift_wrap(from, to, rumor, version) {
        Ok(event) => event,
        Err(e) => {
            warn!("nostr: notify DM wrap failed: {e}");
            return;
        }
    };
    connect_relays(client, &targets).await;
    match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&targets, &event)).await {
        Ok(Ok(_)) => info!("nostr: notify DM sent to {}…", &to.to_hex()[..8]),
        Ok(Err(e)) => warn!("nostr: notify DM send failed: {e}"),
        Err(_) => warn!("nostr: notify DM send timed out"),
    }
}

/// Fetch the payer's kind 10050: their advertised DM relays (capped) and the
/// `encryption` capability tag. Queried from our own relay set — most Goblin
/// peers share the Goblin relay; the discovery-indexer fan-out arrives with
/// the G10 relay-strategy work.
async fn recipient_hints(
    client: &Client,
    payer: &PublicKey,
    own_relays: &[String],
) -> (Vec<String>, Option<String>) {
    let filter = Filter::new()
        .kind(Kind::InboxRelays)
        .author(*payer)
        .limit(1);
    let events = match client
        .fetch_events_from(own_relays, filter, FETCH_TIMEOUT)
        .await
    {
        Ok(events) => events,
        Err(e) => {
            warn!("nostr: 10050 lookup failed: {e}");
            return (vec![], None);
        }
    };
    let Some(event) = events.first() else {
        return (vec![], None);
    };
    let mut relays = vec![];
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        if parts.first().map(|s| s.as_str()) == Some("relay") {
            if let Some(url) = parts.get(1) {
                if relays.len() < MAX_DM_RELAYS {
                    relays.push(url.trim_end_matches('/').to_string());
                }
            }
        }
    }
    (relays, wrap::encryption_capability(event))
}

/// Publish the kind 10050 inbox (relay tags + encryption capability) and the
/// kind 10002 mirror, signed once, to the advertised set.
async fn publish_inbox(client: &Client, keys: &Keys, relays: &[String]) {
    let advertised: Vec<String> = relays.iter().take(MAX_DM_RELAYS).cloned().collect();
    let mut dm_tags: Vec<Tag> = advertised
        .iter()
        .map(|r| Tag::custom(TagKind::custom("relay"), [r.clone()]))
        .collect();
    // The NIP-17 extension: ["encryption", "nip44_v3 nip44_v2"], best first.
    dm_tags.push(wrap::capability_tag());

    let builders = vec![
        EventBuilder::new(Kind::InboxRelays, "").tags(dm_tags),
        // The NIP-65 list mirrors the same set, unmarked (read + write).
        EventBuilder::relay_list(
            advertised
                .iter()
                .filter_map(|r| RelayUrl::parse(r).ok())
                .map(|u| (u, None)),
        ),
    ];
    for builder in builders {
        match builder.sign_with_keys(keys) {
            Ok(event) => {
                if let Err(e) = client.send_event_to(&advertised, &event).await {
                    warn!("nostr: publish kind {} failed: {e}", event.kind);
                }
            }
            Err(e) => warn!("nostr: identity event signing failed: {e}"),
        }
    }
}

/// Re-dispatch stored S2 replies that never verifiably left (Goblin's
/// reconcile, narrowed to the one message type a till sends).
async fn reconcile<R: SlatepackReceiver>(
    client: &Client,
    ingest: &Ingest<R>,
    own_relays: &[String],
) {
    for pending in ingest.receiver().unreplied().await {
        let Ok(payer) = PublicKey::from_hex(&pending.payer_hex) else {
            warn!(
                "nostr: reconcile skipped slate {} (bad payer key)",
                pending.slate_id
            );
            continue;
        };
        // Rebuild the identity that received it, so the re-dispatched reply is
        // signed by the same key (master or the derived child) the payer paid.
        let Some(from) = ingest.resolve(&pending.recipient_hex) else {
            warn!(
                "nostr: reconcile skipped slate {} (unwatched recipient)",
                pending.slate_id
            );
            continue;
        };
        info!(
            "nostr: reconcile re-dispatch S2 for slate {}",
            pending.slate_id
        );
        let reply = ingest.build_reply(from, payer, &pending.s2_armor);
        if deliver_reply(client, &reply, own_relays).await {
            ingest.receiver().mark_replied(&pending.slate_id).await;
        }
    }
}

/// Add + dial every relay in `urls` so a targeted send reaches relays we
/// don't already hold (Goblin's `connect_relays`: idempotent add, short
/// bounded dial, concurrent so one dead relay doesn't stall the rest).
async fn connect_relays(client: &Client, urls: &[String]) {
    let dials = urls.iter().map(|url| {
        let url = url.clone();
        async move {
            let _ = client.add_relay(&url).await;
            // Short cap: a reachable relay connects in ~2-4s over the mixnet;
            // one dead relay in the list must not stall the whole send.
            let _ = client.try_connect_relay(&url, Duration::from_secs(6)).await;
        }
    });
    async_wsocket::futures_util::future::join_all(dials).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_dm_text() {
        assert_eq!(
            merchant_dm_text(2_500_000_000, "slate-1"),
            "[GoblinPay] Received 2.5 GRIN (slate slate-1)."
        );
        assert_eq!(
            payer_receipt_text(1_000_000_000),
            "[GoblinPay] Payment of 1 GRIN received. Thank you."
        );
    }
}
