use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::{json, Value};
use crate::config::ServerConfig;
use crate::db::redis::RedisManager;
use crate::server::registry::{Registry, MessageSender};
use crate::security::noise::TrafficNormalizer;
use crate::telemetry::metrics::Metrics;


pub struct MessageRelay {
    registry: Arc<Registry>,
    redis: Arc<RedisManager>,
    config: Arc<ServerConfig>,
    metrics: Arc<Metrics>,
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
        metrics: Arc<Metrics>,
    ) -> Self {
        Self { registry, redis, config, metrics }
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

    pub async fn relay_message(&self, _message_json: &str, _sender_id: &str) {
        // DISCONTINUED: All protocol-level traffic (including pings/dummies) 
        // must use relay_binary with Universal Binary Framing.
    }

    pub async fn relay_binary(&self, target_blinded: &str, data: &[u8], sender_id: &str, sender_blinded: &str) {
        if data.len() + sender_id.len() > self.config.max_message_size { return; }
        if data.is_empty() { return; }

        let frame_type = data[0];
        tracing::debug!("relay_binary: from={} to={} size={} type={:02x}", sender_id, target_blinded, data.len(), frame_type);
        
        // Padded payload for delivery
        let mut payload = Vec::with_capacity(64 + data.len());
        let sender_padded = format!("{: <64}", sender_id);
        payload.extend_from_slice(sender_padded.as_bytes());
        payload.extend_from_slice(data);
        TrafficNormalizer::pad_binary(&mut payload);

        if let Some(recipient_tx) = self.registry.get_connection(target_blinded) {
            let msg = QueuedMessage {
                msg: axum::extract::ws::Message::Binary(payload.into()),
            };
            
            if recipient_tx.send(msg).is_ok() {
                if let Some(sender_tx) = self.registry.get_connection(sender_blinded) {
                    let mut response = json!({ "type": "relay_success", "status": "relayed" });
                    TrafficNormalizer::pad_json(&mut response);
                    let _ = sender_tx.send(QueuedMessage {
                        msg: axum::extract::ws::Message::Text(serde_json::to_string(&response).unwrap().into()),
                    });
                }
            }
        } else {
            // RECIPIENT OFFLINE
            
            // 1. Media Restriction (Online Only)
            if frame_type == 0x02 {
                self.notify_error_blinded(sender_blinded, Some(target_blinded), "media_offline", "Media can only be sent to online recipients").await;
                return;
            }

            // 2. Storage Limit Check
            let current_count = self.redis.get_offline_count(target_blinded).await.unwrap_or(0);
            if current_count >= self.config.max_offline_messages as u64 {
                self.notify_error_blinded(sender_blinded, Some(target_blinded), "storage_full", "Recipient offline storage is full (200 msg limit)").await;
                return;
            }

            // 3. Accept for Offline Storage
            let _ = self.redis.publish_message(target_blinded, &payload).await;
            let _ = self.redis.store_offline_message(target_blinded, &payload, self.config.max_offline_messages).await;
            
            if let Some(sender_tx) = self.registry.get_connection(sender_blinded) {
                let mut response = json!({
                    "type": "delivery_status",
                    "target": target_blinded,
                    "status": "relayed"
                });
                TrafficNormalizer::pad_json(&mut response);
                let _ = sender_tx.send(QueuedMessage {
                    msg: axum::extract::ws::Message::Text(serde_json::to_string(&response).unwrap().into()),
                });
            }
        }
    }

    async fn notify_error_blinded(&self, sender_blinded: &str, target_blinded: Option<&str>, reason: &str, message: &str) {
        if let Some(sender_tx) = self.registry.get_connection(sender_blinded) {
            let mut response = json!({
                "type": "delivery_error",
                "reason": reason,
                "message": message,
                "target": target_blinded
            });
            TrafficNormalizer::pad_json(&mut response);
            let _ = sender_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Text(serde_json::to_string(&response).unwrap().into()),
            });
        }
    }

    pub async fn relay_volatile(&self, target_blinded: &str, data: &[u8], _sender_id: &str, sender_blinded: &str) {
        tracing::debug!("relay_volatile: from={} to={} size={}", sender_blinded, target_blinded, data.len());

        let mut payload = Vec::with_capacity(64 + data.len());
        let sender_padded = format!("{: <64}", _sender_id);
        payload.extend_from_slice(sender_padded.as_bytes());
        payload.extend_from_slice(data);

        TrafficNormalizer::pad_binary(&mut payload);

        if let Some(recipient_tx) = self.registry.get_connection(target_blinded) {
            let _ = recipient_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Binary(payload.into()),
            });
        } else {
            // Relaying volatile over Redis as raw binary for cross-instance delivery
            let _ = self.redis.publish_message(target_blinded, &payload).await;
        }
    }



    pub async fn handle_dummy(&self, sender_tx: MessageSender) {
        let mut ack = json!({
            "type": "dummy_ack",
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        });
        TrafficNormalizer::pad_json(&mut ack);
        let ack_str = serde_json::to_string(&ack).unwrap();
        
        let _ = sender_tx.send(QueuedMessage {
            msg: axum::extract::ws::Message::Text(ack_str.into()),
        });
    }

    pub async fn deliver_pending(&self, recipient_blinded: &str, recipient_tx: MessageSender) {
        let messages = self.redis.retrieve_offline_messages(recipient_blinded).await.unwrap_or_default();
        if messages.is_empty() { return; }

        let _pacing_interval_ms = 10;
        for (_i, msg_raw) in messages.into_iter().enumerate() {
            // In Universal Binary Framing, we deliver raw frames directly to standard binary handler.
            // Pacing is handled by the 10ms heartbeat in the destination's WebSocket loop.
            let _ = recipient_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Binary(msg_raw.into()),
            });
        }
    }
}
