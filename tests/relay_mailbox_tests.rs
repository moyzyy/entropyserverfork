use entropy_rs::{config::ServerConfig, db::redis::RedisManager, relay::MessageRelay, server::registry::Registry, telemetry::metrics::Metrics};
use std::sync::Arc;
use tokio::sync::mpsc;
use entropy_rs::relay::QueuedMessage;

async fn setup() -> (Arc<ServerConfig>, Arc<RedisManager>, Arc<Registry>, Arc<MessageRelay>) {
    let mut config = ServerConfig::test_default();
    config.max_offline_messages = 3;
    config.max_offline_messages_per_sender = 2;
    let config = Arc::new(config);
    let redis = RedisManager::new(config.clone()).await.unwrap();
    let registry = Arc::new(Registry::new());
    let relay = Arc::new(MessageRelay::new(registry.clone(), redis.clone(), config.clone(), Metrics::new()));
    (config, redis, registry, relay)
}

#[tokio::test]
async fn test_mailbox_quota_enforcement() {
    let (_config, redis, registry, relay) = setup().await;
    let recipient = "victim";
    let sender = "spammer";
    let _ = redis.nuclear_burn(recipient).await;
    
    // Sender gets 2 messages (quota reached)
    relay.relay_binary(recipient, &[0x01, 0,0,0,1, 0,0,0,0, 0,0,0,1], sender).await;
    relay.relay_binary(recipient, &[0x01, 0,0,0,2, 0,0,0,0, 0,0,0,1], sender).await;
    assert_eq!(redis.get_offline_count(recipient).await.unwrap(), 2);
    
    // 3rd message should trigger quota error
    let (tx, mut rx) = mpsc::unbounded_channel::<QueuedMessage>();
    registry.add_connection(sender.to_string(), tx);
    relay.relay_binary(recipient, &[0x01, 0,0,0,3, 0,0,0,0, 0,0,0,1], sender).await;
    
    let msg = rx.recv().await.unwrap();
    assert!(format!("{:?}", msg).contains("sender_quota_exceeded"));
}

#[tokio::test]
async fn test_protocol_multitasking_interleaved_fragments() {
    let (_config, redis, registry, relay) = setup().await;
    let target = "target";
    let _ = redis.nuclear_burn(target).await;
    
    // Binary reassembly tracking test
    let sender = "sender";
    let (tx, mut rx) = mpsc::unbounded_channel::<QueuedMessage>();
    registry.add_connection(sender.to_string(), tx);
    
    // Target must be online for relay_success (otherwise it goes to offline media drop)
    let (target_tx, _target_rx) = mpsc::unbounded_channel::<QueuedMessage>();
    registry.add_connection(target.to_string(), target_tx);
    
    // Fragment A1, B1, A2, B2
    let mut a1 = vec![0x02, 0,0,0,100, 0,0,0,0, 0,0,0,2]; a1.extend(b"A1");
    let mut b1 = vec![0x02, 0,0,0,200, 0,0,0,0, 0,0,0,2]; b1.extend(b"B1");
    let mut a2 = vec![0x02, 0,0,0,100, 0,0,0,1, 0,0,0,2]; a2.extend(b"A2");
    
    relay.relay_binary(target, &a1, sender).await;
    relay.relay_binary(target, &b1, sender).await;
    relay.relay_binary(target, &a2, sender).await;
    
    // Check for relay_success for transfer 100
    let msg = rx.recv().await.unwrap();
    assert!(format!("{:?}", msg).contains("relay_success") && format!("{:?}", msg).contains("100"));
}
