//! HTTP hardening for the public surface: the constant security headers, the
//! per-route framing policy, and the explicit request-payload limits.
//!
//! Framing is the one header that cannot be constant. Every page except the
//! hosted checkout is `X-Frame-Options: DENY`, but a store may legitimately
//! want to frame `/pay/<token>` (the WooCommerce "embed" checkout experience is
//! the shape this is for), so pay routes instead send
//! `Content-Security-Policy: frame-ancestors 'self' <GP_EMBED_ORIGINS...>`.
//! With `GP_EMBED_ORIGINS` unset that is `'self'` only. Note that this
//! TIGHTENS the pay page: it carried no framing header before, so any origin
//! could frame it. Neither shipped connector frames it (the WooCommerce
//! "embed" experience renders the QR inline on the order-received page), but a
//! merchant who does frame it cross-origin must set `GP_EMBED_ORIGINS`.
//!
//! Only `frame-ancestors` is sent. A fuller CSP would have to enumerate image
//! sources, and `GP_QR_LOGO` can point the checkout QR at any operator-chosen
//! external image, so a stricter policy would silently break a configured till.

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{
    HeaderValue, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use actix_web::middleware::{DefaultHeaders, Next};
use actix_web::{web, Error};
use gp_core::config::Config;

/// Maximum accepted request body, all extractors, in bytes.
///
/// The biggest thing a payer ever posts is one armored slatepack (a few kB),
/// and a connector's invoice JSON is a few hundred bytes, so 64 kB is generous
/// for every real request while bounding what one connection can buffer.
pub const PAYLOAD_LIMIT: usize = 64 * 1024;

/// The headers that are the same on every response.
///
/// `DefaultHeaders` adds a header only when the handler did not set one, so a
/// route that needs its own value keeps it.
pub fn default_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .add((REFERRER_POLICY, "no-referrer"))
}

/// The explicit body limits for the three extractors the server uses. Returned
/// together so `main` and its tests cannot drift apart on the numbers.
pub fn payload_limits() -> (web::JsonConfig, web::FormConfig, web::PayloadConfig) {
    (
        web::JsonConfig::default().limit(PAYLOAD_LIMIT),
        web::FormConfig::default().limit(PAYLOAD_LIMIT),
        web::PayloadConfig::default().limit(PAYLOAD_LIMIT),
    )
}

/// Is this the hosted checkout (the one framable surface)?
pub fn is_pay_path(path: &str) -> bool {
    path == "/pay" || path.starts_with("/pay/")
}

/// The `frame-ancestors` source list: always `'self'`, plus any operator
/// allow-listed origins. `GP_EMBED_ORIGINS` is validated at config load, so the
/// values are safe to concatenate here.
pub fn frame_ancestors(embed_origins: &[String]) -> String {
    let mut value = String::from("frame-ancestors 'self'");
    for origin in embed_origins {
        value.push(' ');
        value.push_str(origin);
    }
    value
}

/// Framing policy middleware: `frame-ancestors` on the pay page, a flat
/// `X-Frame-Options: DENY` everywhere else.
///
/// The two are deliberately not both sent on a pay route: browsers that honour
/// `frame-ancestors` ignore `X-Frame-Options`, but the ones that do not would
/// see a bare DENY and break the very embed the allow-list is there to permit.
pub async fn frame_policy(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let pay = is_pay_path(req.path());
    // Read the config before the request is consumed; a missing one (an
    // isolated test app) falls back to the `'self'`-only default.
    let csp = pay.then(|| match req.app_data::<web::Data<Config>>() {
        Some(cfg) => frame_ancestors(&cfg.embed_origins),
        None => frame_ancestors(&[]),
    });

    let mut res = next.call(req).await?;
    match csp {
        Some(value) => {
            if let Ok(value) = HeaderValue::from_str(&value) {
                res.headers_mut().insert(CONTENT_SECURITY_POLICY, value);
            }
        }
        None => {
            res.headers_mut()
                .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pay_paths_are_the_only_framable_ones() {
        assert!(is_pay_path("/pay/abc123"));
        assert!(is_pay_path("/pay/abc123/status"));
        assert!(is_pay_path("/pay"));
        assert!(!is_pay_path("/"));
        assert!(!is_pay_path("/invoice"));
        assert!(
            !is_pay_path("/payments"),
            "prefix match must not over-reach"
        );
    }

    #[test]
    fn frame_ancestors_defaults_to_self_only() {
        assert_eq!(frame_ancestors(&[]), "frame-ancestors 'self'");
        assert_eq!(
            frame_ancestors(&[
                "https://myshop.com".to_string(),
                "https://shop2.example".to_string(),
            ]),
            "frame-ancestors 'self' https://myshop.com https://shop2.example"
        );
    }
}
