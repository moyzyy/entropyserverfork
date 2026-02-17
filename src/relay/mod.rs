use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use rand::{thread_rng, Rng};
use serde_json::{json, Value};
use crate::config::ServerConfig;
use crate::db::redis::RedisManager;
use crate::server::registry::{Registry, MessageSender};
use crate::security::noise::TrafficNormalizer;
use crate::telemetry::metrics::Metrics;
use tracing::warn;

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
    pub is_media: bool,
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
            .or_else(|| val.get("to"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        RoutingInfo {
            msg_type,
            to,
            valid: true,
        }
    }

    pub async fn relay_message(&self, message_json: &str, sender_id: &str) {
        self.metrics.increment_counter("message_total", 1.0);
        
        if message_json.len() > self.config.max_message_size {
            self.metrics.increment_counter("message_error_total", 1.0);
            warn!("Message size limit exceeded: {} bytes", message_json.len());
            return;
        }

        let routing = self.extract_routing(message_json);
        if !routing.valid { return; }

        // Match C++: handle pings/dummies
        if routing.msg_type == "ping" || routing.msg_type == "dummy" || routing.msg_type == "dummy_pacing" {
            if let Some(sender_tx) = self.registry.get_connection(sender_id) {
                self.handle_dummy(sender_tx).await;
            }
            return;
        }

        let val_res: Result<Value, _> = serde_json::from_str(message_json);
        let obj = match val_res {
            Ok(Value::Object(o)) => o,
            _ => return,
        };

        // Reconstruct clean message (1-to-1 scrubbing)
        let mut clean_msg = json!({
            "sender": sender_id
        });
        
        // Pass-through specific keys
        let keys = ["type", "fragmentId", "index", "total", "data", "bundle", "body", "content", "id", "pow", "payload", "pq_ciphertext", "sender_identity_key", "ephemeral_key", "target_hash"];
        for key in keys {
            if let Some(v) = obj.get(key) {
                clean_msg[key] = v.clone();
            }
        }

        let is_media = routing.msg_type == "msg_fragment";
        TrafficNormalizer::pad_json(&mut clean_msg);
        let final_json = serde_json::to_string(&clean_msg).unwrap();

        if !routing.to.is_empty() {
            // Match C++: Recipient flood check (rcv: key)
            let rcv_limit = self.redis.check_rate_limit(&format!("rcv:{}", routing.to), 1000, 10, 1).await.unwrap_or(crate::db::redis::RateLimitResult { allowed: true, current: 0, limit: 1000, reset_after_sec: 0 });
            if !rcv_limit.allowed {
                self.metrics.increment_counter("recipient_flood_blocked", 1.0);
                return;
            }

            if let Some(recipient_tx) = self.registry.get_connection(&routing.to) {
                // Local delivery (async with jitter)
                let delay = thread_rng().gen_range(10..50);
                let msg = QueuedMessage {
                    msg: axum::extract::ws::Message::Text(final_json.into()),
                    is_media,
                };
                tokio::spawn(async move {
                    sleep(Duration::from_millis(delay)).await;
                    let _ = recipient_tx.send(msg);
                });
            } else {
                // Remote delivery
                let _ = self.redis.publish_message(&routing.to, &final_json).await;
                let stored = self.redis.store_offline_message(&routing.to, &final_json).await.unwrap_or(false);
                
                if let Some(sender_tx) = self.registry.get_connection(sender_id) {
                    let mut response = if stored {
                        json!({
                            "type": "delivery_status",
                            "target": routing.to,
                            "status": "relayed"
                        })
                    } else {
                        self.metrics.increment_counter("storage_failure", 1.0);
                        json!({
                            "type": "error",
                            "code": "storage_failed",
                            "message": "Recipient offline and storage unavailable"
                        })
                    };
                    
                    TrafficNormalizer::pad_json(&mut response);
                    let ack_str = serde_json::to_string(&response).unwrap();
                    let delay = thread_rng().gen_range(10..50);
                    tokio::spawn(async move {
                        sleep(Duration::from_millis(delay)).await;
                        let _ = sender_tx.send(QueuedMessage {
                            msg: axum::extract::ws::Message::Text(ack_str.into()),
                            is_media: false,
                        });
                    });
                }
            }
        }
    }

    pub async fn relay_binary(&self, target_hash: &str, data: &[u8], sender_id: &str) {
        if data.len() + sender_id.len() > self.config.max_message_size { return; }
        
        tracing::debug!("relay_binary: from={} to={} size={}", sender_id, target_hash, data.len());
        
        let mut payload = Vec::with_capacity(sender_id.len() + data.len());
        payload.extend_from_slice(sender_id.as_bytes());
        payload.extend_from_slice(data);

        // Binary normalization (1-to-1 parity)
        if payload.len() < TrafficNormalizer::REQUIRED_PACKET_SIZE {
            payload.resize(TrafficNormalizer::REQUIRED_PACKET_SIZE, 0);
        }

        if let Some(recipient_tx) = self.registry.get_connection(target_hash) {
            // Local delivery (async with jitter matching C++ logic)
            let delay = thread_rng().gen_range(10..50);
            let msg = QueuedMessage {
                msg: axum::extract::ws::Message::Binary(payload.into()),
                is_media: true,
            };
            
            let self_clone = self.registry.clone();
            let sender_id_string = sender_id.to_string();
            
            tokio::spawn(async move {
                sleep(Duration::from_millis(delay)).await;
                if recipient_tx.send(msg).is_ok() {
                    // ACK to sender after successful local relay (Match C++: sender->send_text)
                    if let Some(sender_tx) = self_clone.get_connection(&sender_id_string) {
                        let mut response = json!({
                            "type": "relay_success",
                            "status": "relayed"
                        });
                        TrafficNormalizer::pad_json(&mut response);
                        let _ = sender_tx.send(QueuedMessage {
                            msg: axum::extract::ws::Message::Text(serde_json::to_string(&response).unwrap().into()),
                            is_media: false,
                        });
                    }
                }
            });
        } else {
            // Remote/Offline delivery (Match C++ cross-instance logic)
            let wrapper = json!({
                "type": "binary_payload",
                "sender": sender_id,
                "data_hex": hex::encode(data)
            });
            let wrapper_str = serde_json::to_string(&wrapper).unwrap();
            
            // 1. Publish to Redis for other instances
            let _ = self.redis.publish_message(target_hash, &wrapper_str).await;
            
            // 2. Store in Redis for offline delivery (CRITICAL FIX)
            let _stored = self.redis.store_offline_message(target_hash, &wrapper_str).await.unwrap_or(false);
            
            // 3. ACK to sender (Match C++: delivery_status vs relay_success)
            if let Some(sender_tx) = self.registry.get_connection(sender_id) {
                let delay = thread_rng().gen_range(10..50);
                let mut response = json!({
                    "type": "delivery_status",
                    "target": target_hash,
                    "status": "relayed"
                });
                TrafficNormalizer::pad_json(&mut response);
                
                tokio::spawn(async move {
                    sleep(Duration::from_millis(delay)).await;
                    let _ = sender_tx.send(QueuedMessage {
                        msg: axum::extract::ws::Message::Text(serde_json::to_string(&response).unwrap().into()),
                        is_media: false,
                    });
                });
            }
        }
    }

    pub async fn relay_volatile(&self, target_hash: &str, data: &[u8], sender_id: &str) {
        tracing::debug!("relay_volatile: from={} to={} size={}", sender_id, target_hash, data.len());

        let mut payload = Vec::with_capacity(64 + data.len());
        let sender_padded = format!("{: <64}", sender_id);
        payload.extend_from_slice(sender_padded.as_bytes());
        payload.extend_from_slice(data);

        if payload.len() < TrafficNormalizer::REQUIRED_PACKET_SIZE {
            payload.resize(TrafficNormalizer::REQUIRED_PACKET_SIZE, 0);
        }

        if let Some(recipient_tx) = self.registry.get_connection(target_hash) {
            let _ = recipient_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Binary(payload.into()),
                is_media: true,
            });
        } else {
            let wrapper = json!({
                "type": "binary_payload",
                "volatile": true,
                "sender": sender_id,
                "data_hex": hex::encode(data)
            });
            let _ = self.redis.publish_message(target_hash, &serde_json::to_string(&wrapper).unwrap()).await;
        }
    }

    pub async fn relay_group_message(&self, targets: &Vec<Value>, sender_id: &str) {
        let target_count = targets.len().min(100);
        for i in 0..target_count {
            let target_val = &targets[i];
            let Some(target_obj) = target_val.as_object() else { continue; };
            let Some(to) = target_obj.get("to").and_then(|t| t.as_str()) else { continue; };
            let Some(body) = target_obj.get("body") else { continue; };
            
            let mut clean_msg = json!({
                "type": "sealed_message",
                "body": body,
                "sender": sender_id
            });
            if let Some(mt) = target_obj.get("msg_type") {
                clean_msg["msg_type"] = mt.clone();
            }

            TrafficNormalizer::pad_json(&mut clean_msg);
            let final_json = serde_json::to_string(&clean_msg).unwrap();

            if let Some(recipient_tx) = self.registry.get_connection(to) {
                let _ = recipient_tx.send(QueuedMessage {
                    msg: axum::extract::ws::Message::Text(final_json.into()),
                    is_media: false,
                });
            } else {
                let _ = self.redis.publish_message(to, &final_json).await;
                let _ = self.redis.store_offline_message(to, &final_json).await;
            }
        }
    }

    pub async fn handle_dummy(&self, sender_tx: MessageSender) {
        let mut ack = json!({
            "type": "dummy_ack",
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        });
        TrafficNormalizer::pad_json(&mut ack);
        let ack_str = serde_json::to_string(&ack).unwrap();
        
        let delay = thread_rng().gen_range(10..50);
        tokio::spawn(async move {
            sleep(Duration::from_millis(delay)).await;
            let _ = sender_tx.send(QueuedMessage {
                msg: axum::extract::ws::Message::Text(ack_str.into()),
                is_media: false,
            });
        });
    }

    pub async fn deliver_pending(&self, recipient_hash: &str, recipient_tx: MessageSender) {
        let messages = self.redis.retrieve_offline_messages(recipient_hash).await.unwrap_or_default();
        if messages.is_empty() { return; }

        let pacing_interval_ms = 10;
        for (i, msg_json) in messages.into_iter().enumerate() {
            let mut wrapper = json!({
                "type": "queued_message",
                "id": (i + 1) as i64
            });
            
            if let Ok(val) = serde_json::from_str::<Value>(&msg_json) {
                wrapper["payload"] = val;
            } else {
                wrapper["payload"] = json!(msg_json);
            }

            let final_payload = serde_json::to_string(&wrapper).unwrap();
            let delay = (i as u64) * pacing_interval_ms + thread_rng().gen_range(0..50);
            let tx = recipient_tx.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(delay)).await;
                let _ = tx.send(QueuedMessage {
                    msg: axum::extract::ws::Message::Text(final_payload.into()),
                    is_media: false,
                });
            });
        }
    }
}
