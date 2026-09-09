//! The unauthenticated `/health` endpoint: what a monitor, a load balancer or
//! an operator polls to see whether the till is actually working, not merely
//! listening.
//!
//! `status` and `version` are the fixed contract (an uptime check keys off
//! `status == "ok"`); everything else is additive and appears only when the
//! server has the data. Nothing here is a secret: no tokens, no URLs, no payer
//! identities, just counts.

use actix_web::{web, HttpResponse, Responder};
use gp_core::webhook;
use sqlx::SqlitePool;

/// `GET /health`.
///
/// The pool is optional so the route can be mounted in isolation (the route
/// table tests build an `App` with no app data at all); in the running server
/// it is always present, and `webhooks_dead` is then always reported.
pub async fn health(pool: Option<web::Data<SqlitePool>>) -> impl Responder {
    let mut body = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    });
    if let Some(pool) = pool.as_ref() {
        // Webhook deliveries that gave up. Non-zero means a store was never
        // told about a payment and an operator has to re-drive it.
        let dead = webhook::dead_count(pool.get_ref()).await.unwrap_or(0);
        body["webhooks_dead"] = serde_json::json!(dead);
    }
    HttpResponse::Ok().json(body)
}

#[cfg(test)]
mod tests {
    use actix_web::{test, App};
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    /// A migrated in-memory database on one shared connection.
    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory sqlite");
        gp_core::db::MIGRATOR.run(&pool).await.expect("migrate");
        pool
    }

    #[actix_web::test]
    async fn health_reports_the_dead_webhook_count() {
        let pool = test_pool().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/health", web::get().to(health)),
        )
        .await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["webhooks_dead"], 0, "a healthy till has none");

        // Enqueue one and burn its attempts: the counter has to move, or a dead
        // delivery is invisible to monitoring again.
        let payload = webhook::WebhookPayload::received(
            "slate-h".into(),
            1_000_000_000,
            None,
            None,
            None,
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

        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok", "a dead webhook is not an outage");
        assert_eq!(body["webhooks_dead"], 1);
    }

    #[actix_web::test]
    async fn health_without_a_pool_keeps_the_fixed_contract() {
        let app = test::init_service(App::new().route("/health", web::get().to(health))).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert!(body.get("webhooks_dead").is_none());
    }
}
