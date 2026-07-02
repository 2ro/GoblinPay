//! mix-dns: hostname resolution THROUGH the mixnet (ported from
//! `goblin/src/nym/dns.rs`). `Tunnel::tcp_connect` takes a `SocketAddr`, so
//! DNS is our responsibility — and it MUST ride the tunnel: a clearnet lookup
//! would leak exactly which relays the server contacts, defeating the mixnet.
//! Raw A-record queries go as UDP datagrams over
//! [`smolmix::Tunnel::udp_socket`] to public resolvers addressed BY IP.
//! Responses land in a TTL-respecting in-memory cache. IPv4-only, like the
//! Goblin original.
//!
//! Wire codec: hickory-proto — already in the dependency graph via
//! nym-http-api-client, so no vendored encode/parse is needed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use log::{debug, warn};
use smolmix::Tunnel;

/// Public resolvers the tunnel queries, by IP (no bootstrap chicken-and-egg):
/// Cloudflare primary, Quad9 fallback. The exit gateway only ever sees a DNS
/// packet to a public resolver, never who asked.
const RESOLVERS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
];

/// Per-resolver answer wait. The mixnet adds multi-second round trips.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// TTL floor/ceiling for the cache: don't hammer resolvers for zero-TTL
/// records, don't trust a stale record for more than an hour.
const TTL_FLOOR_SECS: u32 = 60;
const TTL_CEILING_SECS: u32 = 3600;

/// Cached answer for one host: addresses plus their expiry.
type CachedAnswer = (Vec<Ipv4Addr>, Instant);

/// host → cached answer.
static CACHE: LazyLock<RwLock<HashMap<String, CachedAnswer>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Resolve `host` to a socket address for `tcp_connect`, entirely over the
/// mixnet. IP-literal hosts skip DNS; cached answers are honored until their
/// (clamped) TTL lapses. Returns `None` when every resolver fails.
pub async fn resolve(tunnel: &Tunnel, host: &str, port: u16) -> Option<SocketAddr> {
    // IP literals (v4 or v6) need no lookup at all.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    if let Some(ip) = cached(host) {
        return Some(SocketAddr::new(IpAddr::V4(ip), port));
    }
    for resolver in RESOLVERS {
        match query_a(tunnel, host, resolver).await {
            Some((ips, ttl)) if !ips.is_empty() => {
                let ttl = ttl.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS);
                debug!(
                    "mix-dns: resolved {host} -> {} (ttl {ttl}s, via {resolver}, {} record(s))",
                    ips[0],
                    ips.len()
                );
                let expiry = Instant::now() + Duration::from_secs(ttl as u64);
                CACHE
                    .write()
                    .expect("dns cache lock")
                    .insert(host.to_string(), (ips.clone(), expiry));
                return Some(SocketAddr::new(IpAddr::V4(ips[0]), port));
            }
            _ => {
                warn!("mix-dns: no answer for {host} from {resolver}, trying next resolver");
            }
        }
    }
    warn!("mix-dns: resolution failed for {host} (all resolvers)");
    None
}

/// A cached, unexpired address for `host`.
fn cached(host: &str) -> Option<Ipv4Addr> {
    let cache = CACHE.read().expect("dns cache lock");
    let (ips, expiry) = cache.get(host)?;
    if Instant::now() < *expiry {
        ips.first().copied()
    } else {
        None
    }
}

/// Cheap end-to-end liveness probe: one uncached A query for a stable name
/// against the primary resolver. Used by the tunnel keepalive/watchdog — it
/// exercises the full path (mixnet → IPR exit → internet and back) and, as a
/// side effect, keeps the gateway connection and IPR session from idling out.
pub async fn probe(tunnel: &Tunnel) -> bool {
    query_a(tunnel, "example.com", RESOLVERS[0]).await.is_some()
}

/// One A query/response round trip over the tunnel against `resolver`.
async fn query_a(
    tunnel: &Tunnel,
    host: &str,
    resolver: SocketAddr,
) -> Option<(Vec<Ipv4Addr>, u32)> {
    let udp = match tunnel.udp_socket().await {
        Ok(s) => s,
        Err(e) => {
            warn!("mix-dns: udp socket failed: {e}");
            return None;
        }
    };
    let id = rand::random::<u16>();
    let query = encode_query(id, host)?;
    if let Err(e) = udp.send_to(&query, resolver).await {
        warn!("mix-dns: send to {resolver} failed: {e}");
        return None;
    }
    let mut buf = vec![0u8; 1500];
    let (n, from) = match tokio::time::timeout(QUERY_TIMEOUT, udp.recv_from(&mut buf)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!("mix-dns: recv from {resolver} failed: {e}");
            return None;
        }
        Err(_) => {
            warn!("mix-dns: query to {resolver} timed out");
            return None;
        }
    };
    if from != resolver {
        warn!("mix-dns: dropping answer from unexpected source {from}");
        return None;
    }
    parse_response(id, &buf[..n])
}

/// Encode a recursive A query for `host` with transaction id `id`.
fn encode_query(id: u16, host: &str) -> Option<Vec<u8>> {
    let name = Name::from_ascii(host).ok()?;
    let mut msg = Message::query();
    msg.metadata.id = id;
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, RecordType::A));
    msg.to_vec().ok()
}

/// Parse a response to transaction `id`: all A records in the answer section
/// plus the smallest TTL among them. `None` on id mismatch, non-response,
/// error rcode or no A records (CNAMEs and other types are skipped).
fn parse_response(id: u16, raw: &[u8]) -> Option<(Vec<Ipv4Addr>, u32)> {
    let msg = Message::from_vec(raw).ok()?;
    if msg.metadata.id != id
        || msg.metadata.message_type != MessageType::Response
        || msg.metadata.response_code != ResponseCode::NoError
    {
        return None;
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for record in &msg.answers {
        if let RData::A(a) = record.data {
            ips.push(a.0);
            ttl = ttl.min(record.ttl);
        }
    }
    if ips.is_empty() {
        None
    } else {
        Some((ips, ttl))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Query for `example.com` A/IN, id 0x1234, RD set — the canonical fixture
    /// (same bytes smolmix's own docs use).
    const QUERY_FIXTURE: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                                   \x07example\x03com\x00\x00\x01\x00\x01";

    /// Response to `QUERY_FIXTURE`: flags 0x8180 (QR, RD, RA, NOERROR), one
    /// question, two answers — a CNAME (ttl 3600, rdata = compression pointer
    /// back to the qname) that must be skipped, then an A record for
    /// 93.184.216.34 with ttl 300.
    const RESPONSE_FIXTURE: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\
                                      \x07example\x03com\x00\x00\x01\x00\x01\
                                      \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\x00\x02\xc0\x0c\
                                      \xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22";

    #[test]
    fn encode_query_matches_fixture() {
        let bytes = encode_query(0x1234, "example.com").unwrap();
        assert_eq!(bytes, QUERY_FIXTURE);
    }

    #[test]
    fn parse_response_extracts_a_records_and_min_ttl() {
        let (ips, ttl) = parse_response(0x1234, RESPONSE_FIXTURE).unwrap();
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        // The CNAME's larger ttl (3600) must not win: only A records count.
        assert_eq!(ttl, 300);
    }

    #[test]
    fn parse_response_rejects_wrong_id() {
        assert!(parse_response(0x5678, RESPONSE_FIXTURE).is_none());
    }

    #[test]
    fn parse_response_rejects_query_and_garbage() {
        // A query (QR=0) is not an answer.
        assert!(parse_response(0x1234, QUERY_FIXTURE).is_none());
        // Truncated/garbage input parses to nothing.
        assert!(parse_response(0x1234, &RESPONSE_FIXTURE[..7]).is_none());
        assert!(parse_response(0x1234, b"\x00").is_none());
    }

    #[test]
    fn parse_response_rejects_error_rcode() {
        // Same fixture with rcode NXDOMAIN (flags 0x8183) and no answers.
        let nx: &[u8] = b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00\
                          \x07example\x03com\x00\x00\x01\x00\x01";
        assert!(parse_response(0x1234, nx).is_none());
    }

    #[test]
    fn ttl_clamp_bounds() {
        assert_eq!(5u32.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS), 60);
        assert_eq!(999_999u32.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS), 3600);
        assert_eq!(300u32.clamp(TTL_FLOOR_SECS, TTL_CEILING_SECS), 300);
    }
}
