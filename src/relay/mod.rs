use std::sync::Arc;
use serde_json::json;
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

    pub async fn relay_binary(&self, target_hash: &str, data: &[u8], sender_hash: &str) {
        if data.len() + sender_hash.len() > self.config.max_message_size { return; }
        if data.is_empty() { return; }

        let frame_type = data[0];
        
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
                msg: axum::extract::ws::Message::Binary(payload),
            };
            
            if recipient_tx.send(msg).is_ok() {
                let transfer_id = u32::from_be_bytes(data[1..5].try_into().unwrap_or([0;4]));
                let index = u32::from_be_bytes(data[5..9].try_into().unwrap_or([0;4]));
                let total = u32::from_be_bytes(data[9..13].try_into().unwrap_or([1;4]));
                
                if index + 1 >= total {
                    if let Some(sender_tx) = self.registry.get_connection(sender_hash) {
                        let response = json!({ "type": "relay_success", "status": "relayed", "transfer_id": transfer_id });
                        let mut response_str = serde_json::to_string(&response).unwrap();
                        TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
                        let _ = sender_tx.send(QueuedMessage {
                            msg: axum::extract::ws::Message::Text(response_str),
                        });
                    }
                }
            }
        } else {
            let transfer_id = u32::from_be_bytes(data[1..5].try_into().unwrap_or([0;4]));
            if frame_type == 0x02 {
                self.notify_error_direct(sender_hash, Some(target_hash), "media_offline", "Recipient is offline. Media fragments were dropped.", Some(transfer_id)).await;
                return;
            }

            match self.redis.store_offline_message(target_hash, sender_hash, &payload, self.config.max_offline_messages, self.config.max_offline_messages_per_sender).await {
                Ok(_) => {
                    if let Some(sender_tx) = self.registry.get_connection(sender_hash) {
                        let response = json!({ "type": "delivery_status", "target": target_hash, "status": "relayed", "transfer_id": transfer_id });
                        let mut response_str = serde_json::to_string(&response).unwrap();
                        TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
                        let _ = sender_tx.send(QueuedMessage { msg: axum::extract::ws::Message::Text(response_str) });
                    }
                },
                Err(e) => {
                    let err_str = e.to_string();
                    let (reason, msg): (&str, &str) = if err_str.contains("ERR_MAILBOX_FULL") {
                        ("storage_full", "Recipient's mailbox is full (500/500).")
                    } else if err_str.contains("ERR_SENDER_QUOTA") {
                        ("sender_quota_exceeded", "You have reached your 15-message limit for this recipient.")
                    } else {
                        ("delivery_error", err_str.as_str())
                    };
                    self.notify_error_direct(sender_hash, Some(target_hash), reason, msg, Some(transfer_id)).await;
                }
            }
        }
    }

    async fn notify_error_direct(&self, sender_hash: &str, target_hash: Option<&str>, reason: &str, message: &str, transfer_id: Option<u32>) {
        if let Some(sender_tx) = self.registry.get_connection(sender_hash) {
            let response = json!({
                "type": "delivery_error",
                "reason": reason,
                "message": message,
                "target": target_hash,
                "transfer_id": transfer_id
            });
            let mut response_str = serde_json::to_string(&response).unwrap();
            TrafficNormalizer::pad_json_str(&mut response_str, self.config.pacing.packet_size);
            let _ = sender_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Text(response_str),
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
                msg: axum::extract::ws::Message::Binary(payload),
            });
        }
    }

    pub async fn deliver_pending(&self, identity_hash: &str, tx: tokio::sync::mpsc::UnboundedSender<QueuedMessage>) {
        if let Ok(messages) = self.redis.get_offline_messages(identity_hash).await {
            for data in messages {
                let _ = tx.send(QueuedMessage {
                    msg: axum::extract::ws::Message::Binary(data),
                });
            }
        }
    }
}
