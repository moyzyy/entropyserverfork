use entropy_rs::{app, config::ServerConfig, db::redis::RedisManager, security::validator::InputValidator};
use std::sync::Arc;
use tokio_tungstenite::connect_async;
use futures::StreamExt;
use std::time::Duration;

async fn setup() -> (Arc<ServerConfig>, Arc<RedisManager>) {
    let config = Arc::new(ServerConfig::test_default());
    let redis = RedisManager::new(config.clone()).await.unwrap();
    (config, redis)
}

#[tokio::test]
async fn test_vulnerability_binary_parsing_panics() {
    let (_config, _redis, _registry, relay) = setup_relay().await;
    // Regression: Ensure the server doesn't panic on under-sized binary frames
    relay.relay_binary("target", &[0x02], "sender").await;
    relay.relay_binary("target", &[0x02, 1, 2, 3], "sender").await;
}

#[tokio::test]
async fn test_vulnerability_json_nesting_bomb() {
    let config = ServerConfig::test_default();
    let mut bomb = "1".to_string();
    for _ in 0..100 { bomb = format!("[{}]", bomb); }
    assert!(!InputValidator::pre_scan_depth(&bomb, config.max_json_depth));
}

#[tokio::test]
async fn test_mechanic_jailing_escalation() {
    let (_config, redis) = setup().await;
    let user_id = "test_jail_user";
    let key = format!("limit:relay:uid:{}", user_id);
    
    // Manually jail the user
    let _ = redis.penalize_uid(user_id, 300).await;
    
    // Rate limit check should now reflect the jail
    let res = redis.check_rate_limit(&key, 10, 60, 1).await.unwrap();
    assert!(res.is_jailed);
}

#[tokio::test]
async fn test_handshake_slowloris_timeout() {
    let mut config = ServerConfig::test_default();
    config.handshake_timeout_sec = 1;
    let config = Arc::new(config);
    let redis = RedisManager::new(config.clone()).await.unwrap();
    
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app(config, redis).await.unwrap()).await.unwrap();
    });
    
    let ws_url = format!("ws://{}/ws", local_addr);
    let (mut ws, _) = connect_async(ws_url).await.unwrap();
    
    // Silence... wait for drop
    let result = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
    assert!(result.is_ok()); // Should have timed out and closed
    server_handle.abort();
}

async fn setup_relay() -> (Arc<ServerConfig>, Arc<RedisManager>, Arc<entropy_rs::server::registry::Registry>, Arc<entropy_rs::relay::MessageRelay>) {
    let config = Arc::new(ServerConfig::test_default());
    let redis = RedisManager::new(config.clone()).await.unwrap();
    let registry = Arc::new(entropy_rs::server::registry::Registry::new());
    let relay = Arc::new(entropy_rs::relay::MessageRelay::new(registry.clone(), redis.clone(), config.clone(), entropy_rs::telemetry::metrics::Metrics::new()));
    (config, redis, registry, relay)
}
