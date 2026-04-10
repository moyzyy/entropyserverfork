use entropy_rs::{app, config::ServerConfig, db::redis::RedisManager, server::registry::Registry, telemetry::metrics::Metrics};
use std::sync::Arc;
use tokio::sync::mpsc;
use entropy_rs::relay::QueuedMessage;

async fn setup() -> (Arc<ServerConfig>, Arc<RedisManager>, Arc<Registry>, Arc<Metrics>) {
    let config = Arc::new(ServerConfig::test_default());
    let metrics = Metrics::new();
    let redis = RedisManager::new(config.clone(), metrics.clone()).await.unwrap();
    let registry = Arc::new(Registry::new());
    (config, redis, registry, metrics)
}

#[tokio::test]
async fn test_infra_health_and_stats() {
    let (config, redis, _registry, metrics) = setup().await;
    let router = app(config.clone(), redis.clone(), metrics.clone()).await.unwrap();
    
    use tower::ServiceExt;
    use axum::http::{Request, StatusCode};

    // Health check
    let response = router.clone().oneshot(Request::builder().uri("/health").body(axum::body::Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Stats unauthorized
    let response = router.clone().oneshot(Request::builder().uri("/stats").body(axum::body::Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_infra_registry_displacement() {
    let (_config, _redis, registry, _metrics) = setup().await;
    let user = "consistent_id";
    
    let (tx1, _rx1) = mpsc::unbounded_channel::<QueuedMessage>();
    let (tx2, _rx2) = mpsc::unbounded_channel::<QueuedMessage>();
    
    // User connects first time
    registry.add_connection(user.to_string(), tx1);
    
    // User connects second time (displaces first)
    let old = registry.add_connection(user.to_string(), tx2);
    assert!(old.is_some(), "Registry should have returned the old sender for displacement");
}
