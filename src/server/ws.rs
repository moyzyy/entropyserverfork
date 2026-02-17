use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State, ConnectInfo},
    response::IntoResponse,
};
use std::sync::Arc;
use crate::AppState;
use futures_util::{StreamExt, SinkExt};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::time::{interval, Duration};
use crate::security::noise::TrafficNormalizer;
use crate::security::validator::InputValidator;
use crate::relay::QueuedMessage;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, addr))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, addr: SocketAddr) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<QueuedMessage>();

    let mut current_user_id: Option<String> = None;
    let mut aliases: Vec<String> = Vec::new();
    let mut authenticated = false;
    let mut _challenge_solved = false;

    // Global connection limit
    if state.registry.connection_count() >= state.config.max_global_connections {
        state.metrics.increment_counter("global_limit_rejected", 1.0);
        crate::security::logger::SecurityLogger::log(
            crate::security::logger::LogLevel::WARNING,
            crate::security::logger::EventType::ConnectionRejected,
            &addr.ip().to_string(),
            "Global connection limit reached"
        );
        return;
    }

    // Registry IP tracking
    if !state.registry.increment_ip_count(&addr.ip().to_string(), state.config.max_connections_per_ip) {
        state.metrics.increment_counter("ip_limit_rejected", 1.0);
        state.metrics.increment_counter("connection_rejected_limit_total", 1.0);
        crate::security::logger::SecurityLogger::log(
            crate::security::logger::LogLevel::WARNING,
            crate::security::logger::EventType::RateLimitHit,
            &addr.ip().to_string(),
            "Per-IP total connection limit reached"
        );
        let mut err = json!({
            "type": "error",
            "code": "connection_limit",
            "message": "Too many connections from your IP address"
        });
        TrafficNormalizer::pad_json(&mut err);
        let _ = sender.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
        return;
    }

    // Pacing loop state
    let mut pacing_interval = interval(Duration::from_millis(state.config.pacing.tick_interval_ms));
    let mut write_queue = std::collections::VecDeque::<QueuedMessage>::new();

    'outer: loop {
        tokio::select! {
            // Outgoing messages from internal relay logic
            Some(qm) = rx.recv() => {
                write_queue.push_back(qm);
            }
            
            // Pacing timer (Traffic Normalization)
            _ = pacing_interval.tick() => {
                if write_queue.is_empty() {
                    let mut dummy = json!({"type": "dummy_pacing"});
                    TrafficNormalizer::pad_json(&mut dummy);
                    write_queue.push_back(QueuedMessage {
                        msg: Message::Text(serde_json::to_string(&dummy).unwrap().into()),
                        is_media: false,
                    });
                }
                
                // Send exactly one message per tick (Strict Pacing)
                if let Some(target_qm) = write_queue.pop_front() {
                    let sent_media = target_qm.is_media;
                    if sender.send(target_qm.msg).await.is_err() { break 'outer; }
                    
                    if sent_media {
                        let mut new_interval = tokio::time::interval(Duration::from_millis(10));
                        new_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        new_interval.tick().await; 
                        pacing_interval = new_interval;
                    } else if pacing_interval.period().as_millis() == 10 {
                        // Switch back to normal pacing if we were in media mode
                        let mut new_interval = tokio::time::interval(Duration::from_millis(state.config.pacing.tick_interval_ms));
                        new_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        new_interval.tick().await;
                        pacing_interval = new_interval;
                    }
                }
            }

            // Incoming messages from client
            Some(result) = receiver.next() => {
                let Ok(msg) = result else { break; };
                
                match msg {
                    Message::Text(text) => {
                        let b_ip = state.registry.blind_id(&addr.ip().to_string());
                        let max_msgs = if authenticated { 1000 } else { 50 };
                        let limit_res = state.redis.check_rate_limit(&format!("ws_msg:{}", b_ip), max_msgs, 10, 1).await.unwrap_or(crate::db::redis::RateLimitResult { allowed: true, current: 0, limit: max_msgs, reset_after_sec: 0 });
                        
                        if !limit_res.allowed {
                            state.metrics.increment_counter("ws_rate_limit_hit", 1.0);
                            crate::security::logger::SecurityLogger::log(
                                crate::security::logger::LogLevel::WARNING,
                                crate::security::logger::EventType::RateLimitHit,
                                &addr.ip().to_string(),
                                "WebSocket rate limit exceeded"
                            );
                            break; // C++: session->close()
                        }

                        let Ok(val) = serde_json::from_str::<Value>(&text) else { continue; };
                        let msg_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");

                        match msg_type {
                            "ping" => {
                                let mut pong = json!({ "type": "pong", "timestamp": val.get("timestamp").cloned().unwrap_or(json!(0)) });
                               TrafficNormalizer::pad_json(&mut pong);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&pong).unwrap().into()), is_media: false });
                            }
                            "pow_challenge" => {
                                tracing::debug!("Received pow_challenge request: {:?}", val);
                                let mut res = state.identity.handle_pow_challenge(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "auth" => {
                                let mut auth_valid = false;
                                let mut id_hash_str = String::new();
                                if let Some(payload) = val.get("payload") {
                                    id_hash_str = payload.get("identity_hash").and_then(|h| h.as_str()).map(|s| InputValidator::sanitize_field(s, 256)).unwrap_or_default();
                                    
                                    if let Some(token) = payload.get("session_token").and_then(|t| t.as_str()) {
                                        if state.redis.verify_session_token(&id_hash_str, token).await.unwrap_or(false) {
                                            auth_valid = true;
                                        }
                                    }
                                    
                                    if !auth_valid {
                                        let intensity = state.redis.get_registration_intensity().await.unwrap_or(0);
                                        let mut penalty = 0;
                                        if intensity > 10 { penalty = 2; }
                                        if intensity > 50 { penalty = 4; }
                                        let age = state.redis.get_account_age(&id_hash_str).await.unwrap_or(0);
                                        let req_diff = crate::security::pow::PoWVerifier::get_required_difficulty(state.registry.connection_count(), penalty, age);
                                        if state.identity.validate_pow(payload, &id_hash_str, req_diff).await {
                                            auth_valid = true;
                                        }
                                    }
                                }

                                if auth_valid && !id_hash_str.is_empty() {
                                    if !authenticated {
                                        state.metrics.increment_gauge("active_connections", 1.0);
                                        state.metrics.increment_counter("connection_created_total", 1.0);
                                    }
                                    _challenge_solved = true;
                                    authenticated = true;
                                    current_user_id = Some(id_hash_str.clone());
                                    state.registry.add_connection(&id_hash_str, tx.clone());
                                    let _ = state.redis.subscribe_user(&id_hash_str).await;
                                    
                                    crate::security::logger::SecurityLogger::log(
                                        crate::security::logger::LogLevel::INFO,
                                        crate::security::logger::EventType::AuthSuccess,
                                        &addr.ip().to_string(),
                                        "User authenticated"
                                    );
                                    
                                    let new_token = state.redis.create_session_token(&id_hash_str, 3600).await.unwrap_or_default();
                                    let mut response = json!({
                                        "type": "auth_success",
                                        "identity_hash": id_hash_str,
                                        "session_token": new_token,
                                        "keys_missing": state.redis.get_user_bundle(&id_hash_str).await.map(|b| b.is_none()).unwrap_or(true)
                                    });
                                    TrafficNormalizer::pad_json(&mut response);
                                    let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&response).unwrap().into()), is_media: false });
                                    state.relay.deliver_pending(&id_hash_str, tx.clone()).await;
                                } else {
                                    crate::security::logger::SecurityLogger::log(
                                        crate::security::logger::LogLevel::ERROR,
                                        crate::security::logger::EventType::AuthFailure,
                                        &addr.ip().to_string(),
                                        "Authentication failed"
                                    );
                                    let mut err = json!({"type": "error", "status": "error", "code": "auth_failed", "error": "Authentication failed"});
                                    if let Some(rid) = val.get("req_id") { err.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                                    TrafficNormalizer::pad_json(&mut err);
                                    let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&err).unwrap().into()), is_media: false });
                                    break; // Match C++ session->close()
                                }
                            }
                            "subscribe_alias" => {
                                if !authenticated { continue; }
                                if aliases.len() >= 50 {
                                    let mut err = json!({"type": "error", "status": "error", "error": "Maximum alias limit reached"});
                                    if let Some(rid) = val.get("req_id") { err.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                                    TrafficNormalizer::pad_json(&mut err);
                                    let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&err).unwrap().into()), is_media: false });
                                    continue;
                                }
                                if let Some(payload) = val.get("payload") {
                                    let alias = payload.get("alias").and_then(|a| a.as_str()).map(|s| InputValidator::sanitize_field(s, 256)).unwrap_or_default();
                                    if !alias.is_empty() && state.identity.validate_pow(payload, &alias, -1).await {
                                        state.registry.add_connection(&alias, tx.clone());
                                        let _ = state.redis.subscribe_user(&alias).await;
                                        aliases.push(alias.clone());
                                        let mut res = json!({"type": "alias_subscribed", "alias": alias});
                                        TrafficNormalizer::pad_json(&mut res);
                                        let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                                    }
                                }
                            }
                            "keys_upload" => {
                                let mut res = state.identity.handle_keys_upload(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "fetch_key" => {
                                let mut res = state.identity.handle_keys_fetch(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "fetch_key_random" => {
                                let mut res = state.identity.handle_keys_random(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "nickname_register" => {
                                let mut res = state.identity.handle_nickname_register(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "nickname_lookup" => {
                                let mut res = state.identity.handle_nickname_lookup(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "account_burn" => {
                                tracing::debug!("Received account_burn request: {:?}", val);
                                let mut res = state.identity.handle_account_burn(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "link_preview" => {
                                let mut res = state.identity.handle_link_preview(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), is_media: false });
                            }
                            "volatile_relay" => {
                                if !authenticated { continue; }
                                if let (Some(uid), Some(to), Some(body)) = (current_user_id.as_ref(), val.get("to").and_then(|t| t.as_str()), val.get("body").and_then(|b| b.as_str())) {
                                    // Match C++: body.data(), body.size()
                                    state.relay.relay_volatile(to, body.as_bytes(), uid).await;
                                }
                            }
                            "group_multicast" => {
                                if let (Some(uid), Some(targets)) = (current_user_id.as_ref(), val.get("targets").and_then(|t| t.as_array())) {
                                    // Match C++: Rate limit multicast by IP (ws_multi: label)
                                    let cost = targets.len() as i64;
                                    let b_ip = state.registry.blind_id(&addr.ip().to_string());
                                    let rate_res = state.redis.check_rate_limit(&format!("ws_multi:{}", b_ip), 500, 60, cost).await.unwrap_or(crate::db::redis::RateLimitResult { allowed: true, current: 0, limit: 500, reset_after_sec: 0 });
                                    
                                    if !rate_res.allowed {
                                        let mut err = json!({"type": "error", "status": "error", "code": "rate_limit", "error": "Multicast rate limit exceeded"});
                                        if let Some(rid) = val.get("req_id") { err.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                                        TrafficNormalizer::pad_json(&mut err);
                                        let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&err).unwrap().into()), is_media: false });
                                    } else {
                                        state.relay.relay_group_message(targets, uid).await;
                                    }
                                }
                            }
                            _ => {
                                // IMPORTANT FALLTHROUGH: Handles "msg", "relay", "msg_fragment", etc.
                                if let Some(ref uid) = current_user_id {
                                    state.relay.relay_message(&text, uid).await;
                                }
                            }
                        }
                    }
                    Message::Binary(data) => {
                        // Match C++: Explicit auth check before processing binary
                        if !authenticated {
                            crate::security::logger::SecurityLogger::log(
                                crate::security::logger::LogLevel::ERROR,
                                crate::security::logger::EventType::AuthFailure,
                                &addr.ip().to_string(),
                                "Unauthenticated binary relay attempt"
                            );
                            break;
                        }

                        let b_ip = state.registry.blind_id(&addr.ip().to_string());
                        let max_msgs = if authenticated { 1000 } else { 50 };
                        let limit_res = state.redis.check_rate_limit(&format!("ws_msg:{}", b_ip), max_msgs, 10, 1).await.unwrap_or(crate::db::redis::RateLimitResult { allowed: true, current: 0, limit: max_msgs, reset_after_sec: 0 });
                        
                        if !limit_res.allowed {
                            break; 
                        }

                        if let Some(uid) = current_user_id.as_ref() {
                            if data.len() > 64 {
                                // Match C++: std::string recipient = data.substr(0, 64)
                                // Extract first 64 bytes and trim null bytes
                                let mut target = String::with_capacity(64);
                                for &byte in &data[0..64] {
                                    if byte == 0 { break; }
                                    target.push(byte as char);
                                }
                                state.relay.relay_binary(&target, &data[64..], uid).await;
                            }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    if authenticated {
        state.metrics.decrement_gauge("active_connections", 1.0);
    }
    if let Some(id) = current_user_id {
        state.registry.remove_connection(&id);
        let _ = state.redis.unsubscribe_user(&id).await;
    }
    for alias in aliases {
        state.registry.remove_connection(&alias);
        let _ = state.redis.unsubscribe_user(&alias).await;
    }
    state.registry.decrement_ip_count(&addr.ip().to_string());
}
