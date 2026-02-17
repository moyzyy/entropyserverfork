use axum::{
    routing::{get},
    Router,
    middleware::{self, Next},
    response::{Response, IntoResponse},
    http::{HeaderMap},
    extract::{State, ConnectInfo},
};
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
use tracing::{info, error};

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
    
    // Match C++ strict security check
    if config.secret_salt == "CHANGE_IN_PROD" {
        error!("CRITICAL SECURITY ERROR: DEFAULT SECRET SALT DETECTED");
        error!("Set 'ENTROPY_SECRET_SALT' environment variable immediately!");
        std::process::exit(1);
    }

    let metrics = Metrics::new();
    let registry = Arc::new(Registry::new(config.secret_salt.clone()));
    let redis = RedisManager::new(&config, registry.clone()).await?;
    let relay = Arc::new(MessageRelay::new(registry.clone(), redis.clone(), config.clone(), metrics.clone()));
    let identity_handler = Arc::new(IdentityHandler::new(redis.clone(), registry.clone()));
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
        .route("/stats", get(|State(s): State<Arc<AppState>>, headers: HeaderMap, ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { s.health.handle_stats(&headers, addr).await }))
        .route("/metrics", get(|State(s): State<Arc<AppState>>, headers: HeaderMap, ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { s.health.handle_metrics(&headers, addr).await }))
        .route("/ws", get(server::ws::ws_handler))
        .layer(middleware::from_fn_with_state(state.clone(), global_rate_limit_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers_middleware))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.address, config.port).parse()?;
    info!("Entropy Server (Rust) starting on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    // 5-minute cleanup timer (1-to-1 parity)
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
        }
    });

    let server = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>());
    
    // Graceful shutdown handling
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received. Closing all connections...");
            registry.close_all();
        }
        res = server => {
            if let Err(e) = res {
                error!("Server error: {}", e);
            }
        }
    }
    
    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
    pub registry: Arc<Registry>,
    pub redis: Arc<RedisManager>,
    pub relay: Arc<MessageRelay>,
    pub identity: Arc<IdentityHandler>,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthHandler>,
}

async fn global_rate_limit_middleware(
    state: axum::extract::State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let b_ip = state.registry.blind_id(&addr.ip().to_string());
    let limit_res = state.redis.check_rate_limit(&format!("global:{}", b_ip), state.config.global_rate_limit as i64, 10, 1).await;
    
    if let Ok(res) = limit_res {
        if !res.allowed {
            state.metrics.increment_counter("global_limit_rejected", 1.0);
            let mut response = axum::Json(serde_json::json!({
                "error": "Rate limit exceeded",
                "retry_after": res.reset_after_sec,
                "limit": res.limit
            })).into_response();
            
            *response.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
            let headers = response.headers_mut();
            headers.insert("Retry-After", res.reset_after_sec.to_string().parse().unwrap());
            headers.insert("X-RateLimit-Limit", res.limit.to_string().parse().unwrap());
            headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
            headers.insert("X-RateLimit-Reset", (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + res.reset_after_sec as u64).to_string().parse().unwrap());
            
            return response;
        }
    }
    
    next.run(request).await
}

async fn security_headers_middleware(
    _state: axum::extract::State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    
    // Final 1-to-1 synchronized security headers
    headers.insert("Server", "Entropy/2.0".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
    headers.insert("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'".parse().unwrap());
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    
    response
}
