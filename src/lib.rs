pub mod config;
pub mod db;
pub mod handlers;
pub mod relay;
pub mod security;
pub mod server;
pub mod telemetry;

use axum::{
    routing::get,
    Router,
    middleware::{self, Next},
    response::Response,
    http::{HeaderMap, StatusCode},
    extract::State,
};
use tower_http::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use std::sync::Arc;
use std::time::Duration;

use crate::config::ServerConfig;
use crate::db::redis::RedisManager;
use crate::server::registry::Registry;
use crate::relay::MessageRelay;
use crate::handlers::identity::IdentityHandler;
use crate::handlers::health::HealthHandler;
use crate::telemetry::metrics::Metrics;

pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub registry: Arc<Registry>,
    pub redis: Arc<RedisManager>,
    pub relay: Arc<MessageRelay>,
    pub identity: Arc<IdentityHandler>,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthHandler>,
}

pub async fn app(config: Arc<ServerConfig>, redis: Arc<RedisManager>) -> anyhow::Result<Router> {
    let metrics = Metrics::new();
    let registry = Arc::new(Registry::new());
    let relay = Arc::new(MessageRelay::new(registry.clone(), redis.clone(), config.clone(), metrics.clone()));
    let identity_handler = Arc::new(IdentityHandler::new(redis.clone(), registry.clone(), config.clone()));
    let health_handler = Arc::new(HealthHandler::new(config.clone(), registry.clone(), metrics.clone(), redis.clone()));

    let state = Arc::new(AppState {
        config: config.clone(),
        registry: registry.clone(),
        redis: redis.clone(),
        relay: relay.clone(),
        identity: identity_handler.clone(),
        metrics: metrics.clone(),
        health: health_handler.clone(),
    });

    let app = Router::new()
        .route("/health", get(|State(s): State<Arc<AppState>>| async move { s.health.handle_health().await }))
        .route("/stats", get(|State(s): State<Arc<AppState>>, headers: HeaderMap| async move { s.health.handle_stats(&headers).await }))
        .route("/metrics", get(|State(s): State<Arc<AppState>>, headers: HeaderMap| async move { s.health.handle_metrics(&headers).await }))
        .route("/ws", get(server::ws::ws_handler))
        .layer(
            ServiceBuilder::new()
                .layer(tower::limit::ConcurrencyLimitLayer::new(config.max_global_connections))
                .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(5)))
                .layer(middleware::from_fn(security_headers_middleware))
        )
        .with_state(state);

    Ok(app)
}

async fn security_headers_middleware(req: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
    response
}
