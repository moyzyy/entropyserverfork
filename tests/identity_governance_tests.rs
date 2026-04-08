use entropy_rs::{config::ServerConfig, db::redis::RedisManager, handlers::identity::IdentityHandler, server::registry::Registry};
use std::sync::Arc;
use sha2::{Digest, Sha256};
use ed25519_dalek::{SigningKey, Signer};
use serde_json::json;

async fn setup() -> (Arc<ServerConfig>, Arc<RedisManager>, IdentityHandler) {
    let config = Arc::new(ServerConfig::test_default());
    let redis = RedisManager::new(config.clone()).await.unwrap();
    let registry = Arc::new(Registry::new());
    let handler = IdentityHandler::new(redis.clone(), registry, config.clone());
    (config, redis, handler)
}

#[tokio::test]
async fn test_race_nickname_simultaneous_registration() {
    let (_config, _redis, handler) = setup().await;
    let nickname = format!("race_nick_{}", rand::random::<u32>());
    let handler = Arc::new(handler);
    
    let mut tasks = Vec::new();
    for i in 0..10 {
        let h = handler.clone();
        let nick = nickname.clone();
        tasks.push(tokio::spawn(async move {
            let seed = [i as u8; 32];
            let sk = SigningKey::from_bytes(&seed);
            let pk = sk.verifying_key();
            let id_hash = hex::encode(Sha256::digest(pk.as_bytes()));
            let payload = format!("NICKNAME_REGISTER:{}", nick);
            let sig = sk.sign(payload.as_bytes());
            
            h.handle_nickname_register(&json!({
                "nickname": nick,
                "identity_hash": id_hash,
                "public_key": hex::encode(pk.as_bytes()),
                "signature": hex::encode(sig.to_bytes())
            })).await
        }));
    }
    
    let mut successes = 0;
    for t in tasks {
        let res = t.await.unwrap();
        if res["status"] == "success" { successes += 1; }
    }
    assert_eq!(successes, 1, "Nickname atomic lock failed - multiple users claimed same nick");
}

#[tokio::test]
async fn test_governance_identity_mismatch_rejection() {
    let (_config, _redis, handler) = setup().await;
    // Public key X does not match Identity Hash Y
    let res = handler.handle_nickname_register(&json!({
        "nickname": "liar",
        "identity_hash": "deadbeef".repeat(8),
        "public_key": "00".repeat(32),
        "signature": "00".repeat(64)
    })).await;
    
    assert!(res["error"].as_str().unwrap().contains("Identity mismatch"));
}
