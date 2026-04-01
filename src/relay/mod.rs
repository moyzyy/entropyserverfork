use std::sync::Arc;
use serde_json::{json, Value};
use crate::config::ServerConfig;
use crate::db::redis::RedisManager;
use crate::server::registry::{Registry};
use crate::security::noise::TrafficNormalizer;
use crate::telemetry::metrics::Metrics;

pub struct MessageRelay {
    registry: Arc<Registry>,
    redis: Arc<RedisManager>,
    config: Arc<ServerConfig>,
}

#[derive(Debug, Default)]
pub struct RoutingInfo {
    pub msg_type: String,
    pub to: String,
    pub valid: bool,
}

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub msg: axum::extract::ws::Message,
}

impl MessageRelay {
    pub fn new(
        registry: Arc<Registry>,
        redis: Arc<RedisManager>,
        config: Arc<ServerConfig>,
        _metrics: Arc<Metrics>,
    ) -> Self {
        Self { registry, redis, config }
    }

    pub fn extract_routing(&self, message_json: &str) -> RoutingInfo {
        let val: Value = match serde_json::from_str(message_json) {
            Ok(v) => v,
            Err(_) => return RoutingInfo::default(),
        };

        let msg_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
        let to = val.get("target_hash")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        RoutingInfo {
            msg_type,
            to,
            valid: true,
        }
    }

    pub async fn relay_message(&self, message_raw: &str, sender_hash: &str) {
        // Universal Binary Framing requirement
        let routing = self.extract_routing(message_raw);
        if !routing.valid || routing.to.is_empty() { return; }

        if let Some(recipient_tx) = self.registry.get_connection(&routing.to) {
            let mut response = json!({ 
                "type": "text_msg", 
                "sender": sender_hash, 
                "payload": message_raw 
            });
            let mut response_str = serde_json::to_string(&response).unwrap();
            TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
            let _ = recipient_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Text(response_str.into()),
            });
        }
    }

    pub async fn relay_binary(&self, target_hash: &str, data: &[u8], sender_hash: &str) {
        if data.len() + sender_hash.len() > self.config.max_message_size { return; }
        if data.is_empty() { return; }

        let frame_type = data[0];
        tracing::debug!("relay_binary: from={} to={} size={} type={:02x}", sender_hash, target_hash, data.len(), frame_type);
        
        let mut payload = Vec::with_capacity(64 + data.len());
        let sender_padded = format!("{: <64}", sender_hash);
        payload.extend_from_slice(sender_padded.as_bytes());
        payload.extend_from_slice(data);
        
        TrafficNormalizer::pad_binary(&mut payload, self.config.pacing.packet_size);
        if payload.len() > self.config.pacing.packet_size {
            payload.truncate(self.config.pacing.packet_size);
        }

        if let Some(recipient_tx) = self.registry.get_connection(target_hash) {
            let msg = QueuedMessage {
                msg: axum::extract::ws::Message::Binary(payload.into()),
            };
            
            if recipient_tx.send(msg).is_ok() {
                let index = u32::from_be_bytes(data[5..9].try_into().unwrap_or([0;4]));
                let total = u32::from_be_bytes(data[9..13].try_into().unwrap_or([1;4]));
                
                if index + 1 >= total {
                    if let Some(sender_tx) = self.registry.get_connection(sender_hash) {
                        let mut response = json!({ "type": "relay_success", "status": "relayed" });
                        let mut response_str = serde_json::to_string(&response).unwrap();
                        TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
                        let _ = sender_tx.send(QueuedMessage {
                            msg: axum::extract::ws::Message::Text(response_str.into()),
                        });
                    }
                }
            }
        } else {
            // Recipient Offline: Store in Redis mailbox
            let current_count = self.redis.get_offline_count(target_hash).await.unwrap_or(0);
            if current_count >= self.config.max_offline_messages as u64 {
                self.notify_error_direct(sender_hash, Some(target_hash), "storage_full", "Recipient offline storage is full").await;
                return;
            }

            let _ = self.redis.publish_message(target_hash, &payload).await;
            let _ = self.redis.store_offline_message(target_hash, &payload, self.config.max_offline_messages).await;
            
            if let Some(sender_tx) = self.registry.get_connection(sender_hash) {
                let mut response = json!({
                    "type": "delivery_status",
                    "target": target_hash,
                    "status": "relayed"
                });
                let mut response_str = serde_json::to_string(&response).unwrap();
                TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
                let _ = sender_tx.send(QueuedMessage {
                    msg: axum::extract::ws::Message::Text(response_str.into()),
                });
            }
        }
    }

    async fn notify_error_direct(&self, sender_hash: &str, target_hash: Option<&str>, reason: &str, message: &str) {
        if let Some(sender_tx) = self.registry.get_connection(sender_hash) {
            let mut response = json!({
                "type": "delivery_error",
                "reason": reason,
                "message": message,
                "target": target_hash
            });
            let mut response_str = serde_json::to_string(&response).unwrap();
            TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
            let _ = sender_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Text(response_str.into()),
            });
        }
    }

    pub async fn relay_volatile(&self, target_hash: &str, data: &[u8], sender_hash: &str) {
        let mut payload = Vec::with_capacity(64 + data.len());
        let sender_padded = format!("{: <64}", sender_hash);
        payload.extend_from_slice(sender_padded.as_bytes());
        payload.extend_from_slice(data);
        TrafficNormalizer::pad_binary(&mut payload, self.config.pacing.packet_size);
        if let Some(recipient_tx) = self.registry.get_connection(target_hash) {
            let _ = recipient_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Binary(payload.into()),
            });
        }
    }

    pub async fn deliver_pending(&self, identity_hash: &str, tx: tokio::sync::mpsc::UnboundedSender<QueuedMessage>) {
        if let Ok(messages) = self.redis.get_offline_messages(identity_hash).await {
            for data in messages {
                let _ = tx.send(QueuedMessage {
                    msg: axum::extract::ws::Message::Binary(data.into()),
                });
            }
        }
    }
}
