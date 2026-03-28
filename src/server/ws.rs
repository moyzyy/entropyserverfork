use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State, ConnectInfo},
    response::IntoResponse,
};
use std::sync::Arc;
use crate::AppState;
use futures_util::{StreamExt, SinkExt};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::time::Duration;
use rand::{thread_rng, Rng};
use crate::security::noise::TrafficNormalizer;
use crate::security::validator::InputValidator;
use crate::relay::QueuedMessage;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let blinded_ip = state.registry.blind_id(&addr.ip().to_string());
    ws.max_message_size(state.config.max_message_size)
      .on_upgrade(move |socket| handle_socket(socket, state, addr, blinded_ip))
}

struct ConnectionGuard {
    state: Arc<AppState>,
    blinded_ip: String,
    current_user_id: Option<String>,
    blinded_user_id: Option<String>,
    aliases: Vec<String>,
    authenticated: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.authenticated {
            self.state.metrics.decrement_gauge("active_connections", 1.0);
        }
        if let Some(id) = self.current_user_id.take() {
            let blinded_id = self.blinded_user_id.take().unwrap_or_else(|| self.state.registry.blind_id(&id));
            self.state.registry.remove_connection(&blinded_id);
            // Also notify redis to unsubscribe if applicable
            let redis = self.state.redis.clone();
            tokio::spawn(async move {
                let _ = redis.unsubscribe_user(&id).await;
            });
        }
        for alias in self.aliases.drain(..) {
            self.state.registry.remove_connection(&self.state.registry.blind_id(&alias));
        }
        self.state.registry.decrement_ip_count(&self.blinded_ip);
    }
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, addr: SocketAddr, blinded_ip: String) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<QueuedMessage>();

    let mut guard = ConnectionGuard {
        state: state.clone(),
        blinded_ip: blinded_ip.clone(),
        current_user_id: None,
        blinded_user_id: None,
        aliases: Vec::new(),
        authenticated: false,
    };
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
    if !state.registry.increment_ip_count(&blinded_ip, state.config.max_connections_per_ip) {
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

    // Pacing loop state: Event-driven sleep (no more fixed 10ms tick)
    let initial_sleep = Duration::from_millis(thread_rng().gen_range(1000..10000));
    let mut next_dummy_sleep = Box::pin(tokio::time::sleep(initial_sleep));
    
    // 🛡️ Hardening: WebSocket Pulse/Timeout state
    let conn_timeout = Duration::from_secs(state.config.connection_timeout_sec);
    let mut last_activity = tokio::time::Instant::now();

    'outer: loop {
        tokio::select! {
            // Outgoing messages from internal relay logic (REAL DATA: Send immediately)
            Some(qm) = rx.recv() => {
                if sender.send(qm.msg).await.is_err() { break 'outer; }
            }
            
            // Pacing timer (Idle Heartbeat: Randomized per config)
            _ = &mut next_dummy_sleep => {
                let mut dummy = json!({"type": "dummy_pacing"});
                crate::security::noise::TrafficNormalizer::pad_json(&mut dummy);
                if sender.send(Message::Text(serde_json::to_string(&dummy).unwrap().into())).await.is_err() { break 'outer; }
                
                // 🛡️ Hardening: Check for Connection Timeout (Client abandonment)
                if last_activity.elapsed() > conn_timeout {
                    crate::security::logger::SecurityLogger::log(
                        crate::security::logger::LogLevel::INFO,
                        crate::security::logger::EventType::ConnectionAbandoned,
                        &addr.ip().to_string(),
                        "Connection timed out due to inactivity"
                    );
                    break 'outer;
                }

                // Reset next dummy sleep (Exactly 1s to 10s as per specification)
                let sleep_ms = thread_rng().gen_range(1000..10000);
                next_dummy_sleep = Box::pin(tokio::time::sleep(Duration::from_millis(sleep_ms)));
            }

            // Incoming messages from client
            Some(result) = receiver.next() => {
                last_activity = tokio::time::Instant::now(); // Reset timeout on ANY client activity
                let Ok(msg) = result else { break; };
                
                match msg {
                    Message::Text(text) => {
                        // 🛡️ Hardening: Enforcement of Max JSON Depth before parsing
                        let mut depth = 0;
                        let mut max_depth = 0;
                        for c in text.chars() {
                            if c == '{' || c == '[' { 
                                depth += 1; 
                                if depth > max_depth { max_depth = depth; }
                            } else if c == '}' || c == ']' {
                                if depth > 0 { depth -= 1; }
                            }
                        }
                        
                        if max_depth > state.config.max_json_depth {
                            crate::security::logger::SecurityLogger::log(
                                crate::security::logger::LogLevel::CRITICAL,
                                crate::security::logger::EventType::ProtocolViolation,
                                &addr.ip().to_string(),
                                &format!("JSON Depth Violation ({} > {})", max_depth, state.config.max_json_depth)
                            );
                            break 'outer;
                        }

                        let b_ip = guard.blinded_ip.clone();
                        let max_msgs = if guard.authenticated { 1000 } else { 50 };
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
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&pong).unwrap().into()), });
                            }
                            "pow_challenge" => {
                                tracing::info!("Received pow_challenge request: {:?}", val);
                                let mut res = state.identity.handle_pow_challenge(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "auth" => {
                                let mut auth_valid = false;
                                let mut id_hash_str = String::new();
                                if let Some(payload) = val.get("payload") {
                                    id_hash_str = payload.get("identity_hash").and_then(|h| h.as_str()).map(|s| InputValidator::sanitize_field(s, 256)).unwrap_or_default();
                                    
                                    if let Some(token) = payload.get("session_token").and_then(|t| t.as_str()) {
                                        let b_user = state.registry.blind_id(&id_hash_str);
                                        if state.redis.verify_session_token(&b_user, token).await.unwrap_or(false) {
                                            auth_valid = true;
                                        }
                                    }
                                    
                                    if !auth_valid {
                                        // CRITICAL: Enforcement of Signature Proof for new auth sessions
                                        if payload.get("signature").is_none() {
                                            crate::security::logger::SecurityLogger::log(
                                                crate::security::logger::LogLevel::ERROR,
                                                crate::security::logger::EventType::AuthFailure,
                                                &addr.ip().to_string(),
                                                "Signature-less authentication attempt rejected"
                                            );
                                        } else {
                                            let intensity = state.redis.get_registration_intensity().await.unwrap_or(0);
                                            let mut penalty = 0;
                                            if intensity > 10 { penalty = 2; }
                                            if intensity > 50 { penalty = 4; }
                                            let req_diff = crate::security::pow::PoWVerifier::get_required_difficulty(state.registry.connection_count(), penalty);
                                            // Scale difficulty by 1000 to match VDF squaring requirement
                                            let is_valid = state.identity.validate_pow(payload, &id_hash_str, req_diff * 1000).await;
                                            tracing::info!("Auth payload evaluated: valid={} hash={} required_difficulty={}", is_valid, id_hash_str, req_diff * 1000);
                                            if is_valid {
                                                auth_valid = true;
                                            } else {
                                                tracing::info!("Auth Payload failed validation: {:?}", payload);
                                            }
                                        }
                                    }
                                }

                                    if auth_valid && !id_hash_str.is_empty() {
                                        let b_user = state.registry.blind_id(&id_hash_str);
                                        if !guard.authenticated {
                                            state.metrics.increment_gauge("active_connections", 1.0);
                                            state.metrics.increment_counter("connection_created_total", 1.0);
                                        }
                                        _challenge_solved = true;
                                        guard.authenticated = true;
                                        guard.current_user_id = Some(id_hash_str.clone());
                                        guard.blinded_user_id = Some(b_user.clone());
                                        state.registry.add_connection(b_user.clone(), tx.clone());
                                        let _ = state.redis.subscribe_user(&id_hash_str).await;
                                    
                                    crate::security::logger::SecurityLogger::log(
                                        crate::security::logger::LogLevel::INFO,
                                        crate::security::logger::EventType::AuthSuccess,
                                        &addr.ip().to_string(),
                                        "User authenticated"
                                    );
                                    
                                    let new_token = state.redis.create_session_token(&b_user, state.config.session_ttl_sec).await.unwrap_or_default();
                                    let mut response = json!({
                                        "type": "auth_success",
                                        "identity_hash": id_hash_str,
                                        "session_token": new_token,
                                        "keys_missing": state.redis.get_user_bundle(&b_user).await.map(|b| b.is_none()).unwrap_or(true)
                                    });
                                    TrafficNormalizer::pad_json(&mut response);
                                    let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&response).unwrap().into()), });
                                    state.relay.deliver_pending(&b_user, tx.clone()).await;
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
                                    let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&err).unwrap().into()), });
                                    break; // Match C++ session->close()
                                }
                            }
                            "subscribe_alias" => {
                                if !guard.authenticated { continue; }
                                if guard.aliases.len() >= 50 {
                                    let mut err = json!({"type": "error", "status": "error", "error": "Maximum alias limit reached"});
                                    if let Some(rid) = val.get("req_id") { err.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                                    TrafficNormalizer::pad_json(&mut err);
                                    let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&err).unwrap().into()), });
                                    continue;
                                }
                                if let Some(payload) = val.get("payload") {
                                    let alias = payload.get("alias").and_then(|a| a.as_str()).map(|s| InputValidator::sanitize_field(s, 256)).unwrap_or_default();
                                    // CRITICAL: Alias subscription must be signed to prevent hijacking
                                    if !alias.is_empty() && payload.get("signature").is_some() && state.identity.validate_pow(payload, &alias, -1).await {
                                        let b_alias = state.registry.blind_id(&alias);
                                        state.registry.add_connection(b_alias, tx.clone());
                                        let _ = state.redis.subscribe_user(&alias).await;
                                        guard.aliases.push(alias.clone());
                                        let mut res = json!({"type": "alias_subscribed", "alias": alias});
                                        TrafficNormalizer::pad_json(&mut res);
                                        let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                                    }
                                }
                            }
                            "keys_upload" => {
                                let mut res = state.identity.handle_keys_upload(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "fetch_key" => {
                                let mut res = state.identity.handle_keys_fetch(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "fetch_key_random" => {
                                let mut res = state.identity.handle_keys_random(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "nickname_register" => {
                                let mut res = state.identity.handle_nickname_register(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "nickname_lookup" => {
                                let mut res = state.identity.handle_nickname_lookup(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "account_burn" => {
                                tracing::debug!("Received account_burn request: {:?}", val);
                                let mut res = state.identity.handle_account_burn(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            "link_preview" => {
                                let mut res = state.identity.handle_link_preview(&val).await;
                                TrafficNormalizer::pad_json(&mut res);
                                let _ = tx.send(QueuedMessage { msg: Message::Text(serde_json::to_string(&res).unwrap().into()), });
                            }
                            _ => {
                                // Handled via relay_message (System pings/dummies only)
                                if let Some(ref uid) = guard.current_user_id {
                                    state.relay.relay_message(&text, uid).await;
                                }
                            }
                        }
                    }
                    Message::Binary(data) => {
                        // Match C++: Explicit auth check before processing binary
                        if !guard.authenticated {
                            crate::security::logger::SecurityLogger::log(
                                crate::security::logger::LogLevel::ERROR,
                                crate::security::logger::EventType::AuthFailure,
                                &addr.ip().to_string(),
                                "Unauthenticated binary relay attempt"
                            );
                            break;
                        }

                        // 1. Handle Protocol-level Binary Frames
                        if !data.is_empty() {
                            let b_type = data[0];
                            if b_type == 0x03 && data.len() == crate::security::noise::TrafficNormalizer::FIXED_FRAME_SIZE {
                                // Dummy/Pacing packet - Ignore and continue
                                continue;
                            }
                        }

                        let b_ip = guard.blinded_ip.clone();
                        let max_msgs = if guard.authenticated { 1000 } else { 50 };
                        let limit_res = state.redis.check_rate_limit(&format!("ws_msg:{}", b_ip), max_msgs, 10, 1).await.unwrap_or(crate::db::redis::RateLimitResult { allowed: true, current: 0, limit: max_msgs, reset_after_sec: 0 });
                        
                        if !limit_res.allowed {
                            break; 
                        }

                                if let Some(uid_blinded) = guard.blinded_user_id.as_ref() {
                                    if let Some(uid) = guard.current_user_id.as_ref() {
                                        if data.len() >= 64 {
                                            // Extraction logic for recipient (64 bytes)
                                            let mut target = String::with_capacity(64);
                                            for &byte in &data[0..64] {
                                                if byte == 0 { break; }
                                                target.push(byte as char);
                                            }
                                            let target_blinded = state.registry.blind_id(&target);
                                            state.relay.relay_binary(&target_blinded, &data[64..], uid, uid_blinded).await;
                                        }
                                    }
                                }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }

    // RAII guard will handle cleanup of registry, redis subscriptions, ip counts, and active_connections metrics
}
