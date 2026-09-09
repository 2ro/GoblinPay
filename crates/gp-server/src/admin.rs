//! The authenticated admin surface (`GP_ADMIN_TOKEN`): a zero-JS dashboard
//! plus the JSON management API for per-user endpubs (milestone 5b) and webhook
//! deliveries. Everything here is server-rendered or plain JSON, no build step.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use askama::Template;
use gp_core::config::Config;
use gp_core::endpub;
use gp_core::webhook::nanogrin_to_grin;
use gp_nostr::{Keys, PublicKey};
use log::error;
use serde::Deserialize;
use sqlx::SqlitePool;

use crate::auth::authorized;
use crate::payments::ReceiptSigner;

/// Register the admin routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/admin", web::get().to(dashboard))
        .route("/admin/payments", web::get().to(list_payments))
        .route("/admin/users", web::get().to(list_users))
        .route("/admin/users", web::post().to(create_user))
        .route("/admin/users/{id}", web::get().to(get_user))
        .route("/admin/users/{id}/rotate", web::post().to(rotate_user))
        .route(
            "/admin/users/{id}/rotate-interval",
            web::post().to(set_rotate_interval),
        )
        .route("/admin/webhooks", web::get().to(list_webhooks))
        .route(
            "/admin/webhooks/{id}/redrive",
            web::post().to(redrive_webhook),
        );
}

fn deny() -> HttpResponse {
    HttpResponse::Unauthorized().json(serde_json::json!({"error": "unauthorized"}))
}

fn is_admin(req: &HttpRequest, cfg: &Config) -> bool {
    authorized(req, cfg.admin_token.as_ref().map(|s| s.reveal()))
}

fn master_secret(keys: &Keys) -> [u8; 32] {
    keys.secret_key().to_secret_bytes()
}

/// npub for an x-only pubkey hex (or empty on parse failure).
fn npub_of_hex(hex: &str) -> String {
    PublicKey::from_hex(hex)
        .map(gp_nostr::npub_of)
        .unwrap_or_default()
}

// ----- dashboard (HTML) -----

struct PaymentRow {
    slate_id: String,
    amount_grin: String,
    status: String,
    invoice_id: String,
    user_id: String,
    created_at: String,
}

struct BalanceRow {
    user_id: String,
    npub: String,
    epoch: i64,
    balance_grin: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminPage {
    /// Mount path prefix for root-relative asset links (see the checkout page).
    base: String,
    payments: Vec<PaymentRow>,
    balances: Vec<BalanceRow>,
    node_url: String,
    match_mode: String,
    ingest: bool,
    relay_count: usize,
    webhook_configured: bool,
    pending_webhooks: i64,
    /// Deliveries that gave up: a store was never told about a payment.
    dead_webhooks: i64,
    rotate_interval: i64,
    overlap_epochs: i64,
}

async fn dashboard(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return HttpResponse::Unauthorized().body("unauthorized");
    }
    let payments = recent_payment_rows(pool.get_ref()).await;
    let balances = balance_rows(pool.get_ref()).await;
    // Pending = still being retried. Dead-lettered ones are counted separately:
    // they are not "in progress", they are waiting for a human.
    let pending_webhooks: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_delivery WHERE delivered = 0 AND dead_at IS NULL",
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);
    let dead_webhooks = gp_core::webhook::dead_count(pool.get_ref())
        .await
        .unwrap_or(0);
    let page = AdminPage {
        base: gp_core::setup::base_path(&cfg.public_url),
        payments,
        balances,
        node_url: cfg.node_url.clone(),
        match_mode: format!("{:?}", cfg.match_mode).to_lowercase(),
        ingest: cfg.ingest,
        relay_count: gp_nostr::relays::resolve(cfg.relay_mode, &cfg.bundled_relay_url, &cfg.relays)
            .len(),
        webhook_configured: cfg.webhook_url.is_some(),
        pending_webhooks,
        dead_webhooks,
        rotate_interval: cfg.endpub_rotate_interval,
        overlap_epochs: cfg.endpub_overlap_epochs,
    };
    match page.render() {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        Err(e) => {
            error!("admin render: {e}");
            HttpResponse::InternalServerError().body("template error")
        }
    }
}

async fn recent_payment_rows(pool: &SqlitePool) -> Vec<PaymentRow> {
    #[allow(clippy::type_complexity)] // a flat sqlx row tuple, mapped immediately below
    let rows: Vec<(String, i64, String, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT slate_id, amount, status, invoice_id, user_id, created_at FROM payment \
         ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    rows.into_iter()
        .map(
            |(slate_id, amount, status, invoice_id, user_id, created_at)| PaymentRow {
                slate_id,
                amount_grin: nanogrin_to_grin(amount as u64),
                status,
                invoice_id: invoice_id.unwrap_or_default(),
                user_id: user_id.unwrap_or_default(),
                created_at,
            },
        )
        .collect()
}

async fn balance_rows(pool: &SqlitePool) -> Vec<BalanceRow> {
    endpub::list_with_balances(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|b| BalanceRow {
            user_id: b.user_id,
            npub: npub_of_hex(&b.endpub),
            epoch: b.epoch,
            balance_grin: nanogrin_to_grin(b.balance.max(0) as u64),
        })
        .collect()
}

// ----- JSON API -----

async fn list_payments(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    #[allow(clippy::type_complexity)] // a flat sqlx row tuple, mapped immediately below
    let rows: Vec<(
        String,
        i64,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT slate_id, amount, payer, status, invoice_id, user_id, created_at \
             FROM payment ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();
    let list: Vec<_> = rows
        .into_iter()
        .map(
            |(id, amount, payer, status, invoice_id, user_id, created_at)| {
                serde_json::json!({
                    "payment_id": id, "amount": amount, "payer": payer, "status": status,
                    "invoice_id": invoice_id, "user_id": user_id, "created_at": created_at,
                })
            },
        )
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "payments": list }))
}

#[derive(Deserialize)]
struct CreateUserBody {
    user_id: Option<String>,
    rotate_interval: Option<i64>,
}

fn endpub_json(cfg: &Config, user_id: &str, epoch: i64, pubkey: &str) -> serde_json::Value {
    let relays = gp_nostr::relays::resolve(cfg.relay_mode, &cfg.bundled_relay_url, &cfg.relays);
    let (npub, nprofile, qr) = match PublicKey::from_hex(pubkey) {
        Ok(pk) => (
            gp_nostr::npub_of(pk),
            gp_nostr::nprofile(pk, &relays),
            gp_core::qr::svg(&gp_nostr::nprofile(pk, &relays), cfg.qr_logo()).unwrap_or_default(),
        ),
        Err(_) => (String::new(), String::new(), String::new()),
    };
    serde_json::json!({
        "user_id": user_id, "epoch": epoch, "pubkey": pubkey,
        "npub": npub, "nprofile": nprofile, "qr_svg": qr,
    })
}

async fn create_user(
    req: HttpRequest,
    body: web::Json<CreateUserBody>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
    signer: web::Data<ReceiptSigner>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    let Some(keys) = signer.0.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error": "server identity not loaded"}));
    };
    let sk = master_secret(keys);
    let body = body.into_inner();
    match endpub::create_user(pool.get_ref(), &sk, body.user_id, body.rotate_interval).await {
        Ok((user, ep)) => {
            HttpResponse::Ok().json(endpub_json(cfg.get_ref(), &user.id, ep.epoch, &ep.pubkey))
        }
        Err(e) => {
            error!("create user: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

async fn list_users(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    let balances = endpub::list_with_balances(pool.get_ref())
        .await
        .unwrap_or_default();
    let list: Vec<_> = balances
        .into_iter()
        .map(|b| {
            serde_json::json!({
                "user_id": b.user_id, "epoch": b.epoch,
                "endpub": b.endpub, "npub": npub_of_hex(&b.endpub), "balance": b.balance,
            })
        })
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "users": list }))
}

async fn get_user(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    let id = path.into_inner();
    match endpub::current_endpub(pool.get_ref(), &id).await {
        Ok(Some(ep)) => {
            HttpResponse::Ok().json(endpub_json(cfg.get_ref(), &id, ep.epoch, &ep.pubkey))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
        Err(e) => {
            error!("get user: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

async fn rotate_user(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
    signer: web::Data<ReceiptSigner>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    let Some(keys) = signer.0.as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({"error": "server identity not loaded"}));
    };
    let sk = master_secret(keys);
    let id = path.into_inner();
    match endpub::rotate(pool.get_ref(), &sk, &id).await {
        Ok(ep) => HttpResponse::Ok().json(endpub_json(cfg.get_ref(), &id, ep.epoch, &ep.pubkey)),
        Err(e) => {
            error!("rotate user: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

#[derive(Deserialize)]
struct RotateIntervalBody {
    /// New interval in seconds; null clears the per-user override.
    interval: Option<i64>,
}

async fn set_rotate_interval(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<RotateIntervalBody>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    let id = path.into_inner();
    match endpub::set_rotate_interval(pool.get_ref(), &id, body.into_inner().interval).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"user_id": id, "updated": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "user not found"})),
        Err(e) => {
            error!("set rotate interval: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

async fn list_webhooks(
    req: HttpRequest,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    #[allow(clippy::type_complexity)] // a flat sqlx row tuple, mapped immediately below
    let rows: Vec<(
        String,
        Option<String>,
        String,
        i64,
        i64,
        String,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, payment_id, event_type, attempts, delivered, next_attempt_at, last_error, \
                dead_at \
             FROM webhook_delivery ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();
    let list: Vec<_> = rows
        .into_iter()
        .map(
            |(
                id,
                payment_id,
                event_type,
                attempts,
                delivered,
                next_attempt_at,
                last_error,
                dead_at,
            )| {
                serde_json::json!({
                    "event_id": id, "payment_id": payment_id, "event_type": event_type,
                    "attempts": attempts, "delivered": delivered == 1,
                    "next_attempt_at": next_attempt_at, "last_error": last_error,
                    // Gave up: no further retry until an operator re-drives it.
                    "dead": dead_at.is_some(), "dead_at": dead_at,
                })
            },
        )
        .collect();
    HttpResponse::Ok().json(serde_json::json!({ "deliveries": list }))
}

/// `POST /admin/webhooks/{id}/redrive`: put a delivery that gave up back in the
/// queue (attempts reset, dead flag cleared, due now). The body is unchanged, so
/// the receiver still dedupes on the same event id.
async fn redrive_webhook(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<SqlitePool>,
    cfg: web::Data<Config>,
) -> impl Responder {
    if !is_admin(&req, cfg.get_ref()) {
        return deny();
    }
    let id = path.into_inner();
    match gp_core::webhook::redrive(pool.get_ref(), &id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"event_id": id, "redriven": true})),
        Ok(false) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "delivery not found"}))
        }
        Err(e) => {
            error!("redrive webhook: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "internal"}))
        }
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{test, App};
    use gp_core::config::Secret;
    use gp_core::webhook;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    const TOKEN: &str = "gpadm_testtoken";

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory sqlite");
        gp_core::db::MIGRATOR.run(&pool).await.expect("migrate");
        pool
    }

    fn admin_config() -> Config {
        Config {
            admin_token: Some(Secret::new(TOKEN.into())),
            ..Config::default()
        }
    }

    /// A dead-lettered delivery must be visible in the listing and re-drivable
    /// through the admin API, and the re-drive must stay behind the token.
    #[actix_web::test]
    async fn dead_deliveries_are_listed_and_redrivable_by_an_admin() {
        let pool = test_pool().await;
        let payload = webhook::WebhookPayload::received(
            "slate-a".into(),
            1_000_000_000,
            None,
            None,
            Some("order-a".into()),
            None,
        );
        let id = webhook::enqueue(&pool, "https://store.example/hook", &payload)
            .await
            .unwrap();
        for _ in 0..webhook::MAX_ATTEMPTS {
            webhook::mark_failed(&pool, &id, "connection refused")
                .await
                .unwrap();
        }

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(web::Data::new(admin_config()))
                .configure(configure),
        )
        .await;

        // The listing flags it.
        let req = test::TestRequest::get()
            .uri("/admin/webhooks")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let row = &body["deliveries"][0];
        assert_eq!(row["event_id"], id.as_str());
        assert_eq!(row["dead"], true);
        assert!(row["dead_at"].is_string());

        // No token: the re-drive is refused and the delivery stays dead.
        let req = test::TestRequest::post()
            .uri(&format!("/admin/webhooks/{id}/redrive"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 401);
        assert_eq!(webhook::dead_count(&pool).await.unwrap(), 1);

        // With the token it goes back in the queue.
        let req = test::TestRequest::post()
            .uri(&format!("/admin/webhooks/{id}/redrive"))
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["redriven"], true);
        assert_eq!(webhook::dead_count(&pool).await.unwrap(), 0);
        assert_eq!(webhook::due(&pool, 10).await.unwrap().len(), 1);

        // An unknown id is a 404, not a silent success.
        let req = test::TestRequest::post()
            .uri("/admin/webhooks/no-such-id/redrive")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 404);
    }
}
