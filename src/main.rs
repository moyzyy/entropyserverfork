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
use std::net::SocketAddr;
use std::time::Duration;
use crate::config::ServerConfig;
use crate::db::redis::RedisManager;
use crate::server::registry::Registry;
use crate::relay::MessageRelay;
use crate::handlers::identity::IdentityHandler;
use crate::handlers::health::HealthHandler;
use crate::telemetry::metrics::Metrics;
use tracing::info;

mod config;
mod db;
mod handlers;
mod relay;
mod security;
mod server;
mod telemetry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Arc::new(ServerConfig::load());
    
    let metrics = Metrics::new();
    let registry = Arc::new(Registry::new());
    let redis = RedisManager::new(config.clone()).await?;
    let relay = Arc::new(MessageRelay::new(registry.clone(), redis.clone(), config.clone(), metrics.clone()));
    let identity_handler = Arc::new(IdentityHandler::new(redis.clone(), registry.clone(), config.clone()));
    let health_handler = Arc::new(HealthHandler::new(config.clone(), registry.clone(), metrics.clone()));

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

    let addr: SocketAddr = format!("{}:{}", config.address, config.port).parse().expect("Invalid address");
    info!("Entropy Server v0.1.0 starting on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // IP-BLIND: We no longer need to extract connection info. 
    // This removes the final dependency on network origin from the request lifecycle.
    axum::serve(listener, app.into_make_service()).await?;
    
    Ok(())
}

pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub registry: Arc<Registry>,
    pub redis: Arc<RedisManager>,
    pub relay: Arc<MessageRelay>,
    pub identity: Arc<IdentityHandler>,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthHandler>,
}


async fn security_headers_middleware(req: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
    response
}
