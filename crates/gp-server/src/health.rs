//! The unauthenticated `/health` endpoint: what a monitor, a load balancer or
//! an operator polls to see whether the till is actually working, not merely
//! listening.
//!
//! `status` and `version` are the fixed contract (an uptime check keys off
//! `status == "ok"`); everything else is additive and appears only when the
//! server has the data. Nothing here is a secret: no tokens, no URLs, no payer
//! identities, just counts.

use std::sync::Arc;

use actix_web::{web, HttpResponse, Responder};
use gp_core::webhook;
use gp_nostr::service::RelayHealth;
use sqlx::SqlitePool;

/// The non-database inputs `/health` reports on.
#[derive(Debug, Clone, Default)]
pub struct HealthState {
    /// The ingest service's relay connectivity snapshot. `None` when ingest is
    /// off (`GP_INGEST=off`): there is no relay set to be healthy or not.
    relays: Option<Arc<RelayHealth>>,
}

impl HealthState {
    /// Build the state from the running ingest service's snapshot (or `None`
    /// when ingest is disabled).
    pub fn new(relays: Option<Arc<RelayHealth>>) -> HealthState {
        HealthState { relays }
    }
}

/// `GET /health`.
///
/// `status` and `version` are the fixed contract. The pool and the state are
/// optional so the route can be mounted in isolation (the route-table tests
/// build an `App` with no app data at all); in the running server the pool is
/// always present, so `webhooks_dead` is always reported.
pub async fn health(
    pool: Option<web::Data<SqlitePool>>,
    state: Option<web::Data<HealthState>>,
) -> impl Responder {
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
    // Relay connectivity, once the ingest service has taken a reading.
    // `connected: 0` with a non-zero `configured` means the till is up but
    // cannot receive a payment over Nostr, which nothing else surfaces.
    if let Some((configured, connected)) = state
        .as_ref()
        .and_then(|s| s.relays.as_ref())
        .and_then(|h| h.snapshot())
    {
        body["relays"] = serde_json::json!({
            "configured": configured,
            "connected": connected,
        });
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
        assert!(body.get("relays").is_none());
    }

    /// Relay connectivity appears once the ingest service has taken a reading,
    /// and an all-down relay set is reported rather than hidden.
    #[actix_web::test]
    async fn health_reports_relay_connectivity_when_ingest_is_running() {
        let relays = Arc::new(RelayHealth::new());
        let state = HealthState::new(Some(Arc::clone(&relays)));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/health", web::get().to(health)),
        )
        .await;

        // Before the service's first tick there is no reading to report.
        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert!(body.get("relays").is_none(), "no fabricated boot reading");

        relays.set(3, 2);
        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["relays"]["configured"], 3);
        assert_eq!(body["relays"]["connected"], 2);
        assert_eq!(body["status"], "ok");

        // All down: still `ok` (the HTTP surface works), but visibly 0 of 3.
        relays.set(3, 0);
        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok", "status semantics are unchanged");
        assert_eq!(body["relays"]["connected"], 0);
    }

    /// Ingest off: no relay set exists, so nothing is claimed about one.
    #[actix_web::test]
    async fn health_omits_relays_when_ingest_is_off() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(HealthState::new(None)))
                .route("/health", web::get().to(health)),
        )
        .await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(body["status"], "ok");
        assert!(body.get("relays").is_none());
    }
}
