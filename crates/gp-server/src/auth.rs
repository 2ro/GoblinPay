//! Bearer-token authorization for the write and admin surfaces.
//!
//! Two independent tokens: `GP_API_TOKEN` gates the connector/create-invoice
//! API, `GP_ADMIN_TOKEN` gates the admin dashboard and endpub/webhook
//! management. A route whose token is unset is closed (401), never open. The
//! public-by-token surfaces (`/pay/<token>`, payment status) carry their own
//! unguessable capability and do not use these.

use actix_web::HttpRequest;

/// The bearer token from the `Authorization: Bearer <token>` header, if any.
pub fn bearer(req: &HttpRequest) -> Option<String> {
    let value = req.headers().get("Authorization")?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

/// Is the request authorized against `expected`? An unset expected token
/// (feature not configured) is always unauthorized. The comparison is
/// constant time.
pub fn authorized(req: &HttpRequest, expected: Option<&str>) -> bool {
    match (expected, bearer(req)) {
        (Some(exp), Some(got)) => gp_core::ct_eq(got.as_bytes(), exp.as_bytes()),
        _ => false,
    }
}
