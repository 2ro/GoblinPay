//! A per-client-IP token bucket for the two unauthenticated-or-cheap write
//! routes: the manual slatepack paste (`POST /pay/{token}/slatepack`) and
//! invoice creation (`POST /invoice`).
//!
//! In-process and in-memory on purpose: a till is one process, the limits are
//! coarse (tens per minute), and a shared store would be a new dependency and a
//! new failure mode on the money path. The map is bounded and pruned, so a
//! spray of forged client addresses costs bounded memory.
//!
//! Reads are never limited. `GET /pay/{token}/status` in particular is polled
//! by the pay page's own meta refresh, and limiting it would break checkout.
//!
//! ## Which address is the client
//!
//! A till runs behind a reverse proxy, so the peer address is the proxy. The
//! key is, in order: the RIGHTMOST `X-Forwarded-For` entry, then `X-Real-IP`,
//! then the peer address.
//!
//! Rightmost, not leftmost. Both shipped front ends put the address they
//! themselves observed at the end: Caddy replaces the header outright for an
//! untrusted client, and nginx's usual `$proxy_add_x_forwarded_for` appends to
//! whatever arrived. Anything to the LEFT of that is client-supplied and
//! forgeable, and the leftmost entry is exactly what actix's
//! `realip_remote_addr` returns, so the header is read here instead.
//!
//! `X-Real-IP` is only the fallback: nginx sets it from `$remote_addr` and it
//! is trustworthy there, but Caddy does not manage it at all (it sets only the
//! `X-Forwarded-*` family), so a client-sent one passes straight through and
//! must never outrank the header Caddy does control.
//!
//! Loopback is exempt, but only when the request arrived with no forwarding
//! header at all, so a forged `X-Forwarded-For: 127.0.0.1` buys no exemption.
//! The residual caveat is inherent: a client that reaches the till DIRECTLY can
//! forge the whole header, so the till must stay behind its proxy (it binds
//! loopback by default).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::Method;
use actix_web::middleware::Next;
use actix_web::{web, Error, HttpResponse};
use gp_core::config::Config;

/// The window the configured allowance refills over.
const WINDOW: Duration = Duration::from_secs(60);
/// Cap on tracked addresses. Reached only under a forged-address spray; the
/// prune below drops idle buckets first.
const MAX_TRACKED: usize = 10_000;
/// Body of the throttled response. Plain text: the paste route is a form post
/// from a browser and the invoice route is a JSON API, so neither content type
/// is a good fit for both.
const TOO_MANY: &str = "too many requests; slow down and try again in a minute";

/// Which allowance a request draws on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `POST /pay/{token}/slatepack`.
    Paste,
    /// `POST /invoice`.
    Invoice,
}

/// One address's remaining allowance.
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// The shared limiter. Registered once (outside the `HttpServer` factory) so
/// every worker draws on the same buckets.
pub struct RateLimiter {
    paste: u32,
    invoice: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// Build from the operator's configured per-minute allowances (0 = off).
    pub fn new(paste: u32, invoice: u32) -> Self {
        RateLimiter {
            paste,
            invoice,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Build from the runtime config.
    pub fn from_config(cfg: &Config) -> Self {
        RateLimiter::new(cfg.rate_limit_paste, cfg.rate_limit_invoice)
    }

    /// The configured allowance for a route, per minute.
    fn limit(&self, route: Route) -> u32 {
        match route {
            Route::Paste => self.paste,
            Route::Invoice => self.invoice,
        }
    }

    /// Spend one token for `key` on `route`. `true` means the request may
    /// proceed. A limit of 0 always allows.
    pub fn allow(&self, route: Route, key: &str) -> bool {
        let limit = self.limit(route);
        if limit == 0 {
            return true;
        }
        let capacity = f64::from(limit);
        let now = Instant::now();
        let Ok(mut buckets) = self.buckets.lock() else {
            // A poisoned lock must not take the payment surface down.
            return true;
        };
        if buckets.len() >= MAX_TRACKED {
            buckets.retain(|_, b| now.duration_since(b.last) < WINDOW);
            if buckets.len() >= MAX_TRACKED {
                buckets.clear();
            }
        }
        // One bucket per (route, address): a busy checkout must not starve the
        // paste allowance or the other way round.
        let bucket = buckets.entry(format!("{route:?}|{key}")).or_insert(Bucket {
            tokens: capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * capacity / WINDOW.as_secs_f64()).min(capacity);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Which allowance (if any) a request draws on. Matched on the exact route
/// shapes registered in `invoices::configure` and `checkout::configure`.
fn route_for(method: &Method, path: &str) -> Option<Route> {
    if method != Method::POST {
        return None;
    }
    if path == "/invoice" {
        return Some(Route::Invoice);
    }
    let mut segments = path.strip_prefix('/').unwrap_or(path).split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some("pay"), Some(token), Some("slatepack"), None) if !token.is_empty() => {
            Some(Route::Paste)
        }
        _ => None,
    }
}

/// The address to key on, and whether the request came through a proxy (which
/// is what decides the loopback exemption).
fn client_key(req: &ServiceRequest) -> (String, bool) {
    let headers = req.headers();
    let forwarded_for = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let real_ip = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    let proxied = forwarded_for.is_some()
        || real_ip.is_some()
        || headers.contains_key(actix_web::http::header::FORWARDED);

    if let Some(addr) =
        forwarded_for.and_then(|v| v.rsplit(',').map(str::trim).find(|s| !s.is_empty()))
    {
        return (addr.to_string(), proxied);
    }
    if let Some(addr) = real_ip.map(str::trim).filter(|s| !s.is_empty()) {
        return (addr.to_string(), proxied);
    }
    let info = req.connection_info();
    let addr = info.realip_remote_addr().unwrap_or("unknown").to_string();
    (addr, proxied)
}

/// Is this address exempt? Only a direct loopback caller (an operator's own
/// curl, the test harness), never one that merely claims to be loopback.
fn exempt(key: &str, proxied: bool) -> bool {
    !proxied && key.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Middleware: spend a token on the two limited routes, 429 when the bucket is
/// empty. Every other request passes straight through. With no `RateLimiter`
/// registered (an isolated test app) nothing is limited.
pub async fn enforce(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let throttled = match route_for(req.method(), req.path()) {
        None => false,
        Some(route) => match req.app_data::<web::Data<RateLimiter>>() {
            None => false,
            Some(limiter) => {
                let (key, proxied) = client_key(&req);
                !exempt(&key, proxied) && !limiter.allow(route, &key)
            }
        },
    };
    if throttled {
        let res = HttpResponse::TooManyRequests()
            .content_type("text/plain; charset=utf-8")
            .body(TOO_MANY);
        return Ok(req.into_response(res).map_into_right_body());
    }
    Ok(next.call(req).await?.map_into_left_body())
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::*;

    #[test]
    fn only_the_two_write_routes_are_limited() {
        let post = Method::POST;
        assert_eq!(route_for(&post, "/invoice"), Some(Route::Invoice));
        assert_eq!(route_for(&post, "/pay/abc/slatepack"), Some(Route::Paste));
        // Reads, the status poll the pay page depends on, and everything else.
        assert_eq!(route_for(&Method::GET, "/invoice"), None);
        assert_eq!(route_for(&Method::GET, "/pay/abc/slatepack"), None);
        assert_eq!(route_for(&post, "/pay/abc/status"), None);
        assert_eq!(route_for(&post, "/pay/abc"), None);
        assert_eq!(route_for(&post, "/invoice/abc"), None);
        assert_eq!(route_for(&post, "/pay//slatepack"), None);
        assert_eq!(route_for(&post, "/pay/abc/slatepack/extra"), None);
    }

    #[test]
    fn a_burst_over_the_limit_is_refused_then_refills() {
        let limiter = RateLimiter::new(3, 3);
        for i in 0..3 {
            assert!(limiter.allow(Route::Paste, "198.51.100.7"), "call {i}");
        }
        assert!(
            !limiter.allow(Route::Paste, "198.51.100.7"),
            "the fourth call in the window is refused"
        );
        // Per address.
        assert!(limiter.allow(Route::Paste, "198.51.100.8"));
        // Per route: a spent paste allowance does not close the invoice API.
        assert!(limiter.allow(Route::Invoice, "198.51.100.7"));
    }

    #[test]
    fn a_zero_limit_disables_the_route() {
        let limiter = RateLimiter::new(0, 1);
        for _ in 0..100 {
            assert!(limiter.allow(Route::Paste, "198.51.100.7"));
        }
        assert!(limiter.allow(Route::Invoice, "198.51.100.7"));
        assert!(!limiter.allow(Route::Invoice, "198.51.100.7"));
    }

    #[test]
    fn loopback_is_exempt_but_a_forged_forwarded_header_is_not() {
        assert!(exempt("127.0.0.1", false));
        assert!(exempt("::1", false));
        assert!(!exempt("198.51.100.7", false));
        // Claiming to be loopback through a proxy header earns nothing.
        assert!(!exempt("127.0.0.1", true));
    }

    #[test]
    fn client_key_takes_the_rightmost_forwarded_entry_then_real_ip_then_peer() {
        // The proxy appended the true client last; everything to its left is
        // client-supplied, so a forged prefix changes nothing.
        let req = TestRequest::default()
            .peer_addr("10.0.0.9:5000".parse().unwrap())
            .insert_header(("x-forwarded-for", "127.0.0.1, 8.8.8.8, 203.0.113.6"))
            .to_srv_request();
        assert_eq!(client_key(&req), ("203.0.113.6".to_string(), true));

        // A client-sent X-Real-IP passes straight through Caddy, so it must
        // never outrank the header the proxy actually controls.
        let req = TestRequest::default()
            .peer_addr("10.0.0.9:5000".parse().unwrap())
            .insert_header(("x-real-ip", "198.51.100.1"))
            .insert_header(("x-forwarded-for", "203.0.113.6"))
            .to_srv_request();
        assert_eq!(client_key(&req), ("203.0.113.6".to_string(), true));

        // With no X-Forwarded-For, nginx's X-Real-IP is the client.
        let req = TestRequest::default()
            .peer_addr("10.0.0.9:5000".parse().unwrap())
            .insert_header(("x-real-ip", "203.0.113.5"))
            .to_srv_request();
        assert_eq!(client_key(&req), ("203.0.113.5".to_string(), true));

        // Direct, unproxied: the peer address, and not marked proxied, so the
        // loopback exemption can apply.
        let req = TestRequest::default()
            .peer_addr("127.0.0.1:5000".parse().unwrap())
            .to_srv_request();
        assert_eq!(client_key(&req), ("127.0.0.1".to_string(), false));
    }
}
