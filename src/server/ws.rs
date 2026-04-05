use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
};
use std::sync::Arc;
use crate::AppState;
use futures_util::{StreamExt, SinkExt};
use serde_json::{json, Value};
use tokio::time::Duration;
use rand::{thread_rng, Rng};
use crate::security::noise::TrafficNormalizer;
use crate::security::validator::InputValidator;
use crate::relay::QueuedMessage;
use std::collections::HashMap;

pub struct FragmentBuffer {
    pub total: u32,
    pub chunks: HashMap<u32, Vec<u8>>,
    pub last_activity: tokio::time::Instant,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // IP-BLIND UPGRADE: Physical IP is strictly transient for transport.
    // We no longer extract or track ConnectInfo<SocketAddr>.
    ws.max_message_size(state.config.max_message_size)
      .on_upgrade(move |socket| handle_socket(socket, state))
}

struct ConnectionGuard {
    state: Arc<AppState>,
    identity_hash: Option<String>,
    authenticated: bool,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.registry.dec_total(); // Tracking for all connections
        if self.authenticated {
            self.state.metrics.decrement_gauge("active_connections", 1.0);
        }
        if let Some(id_hash) = self.identity_hash.take() {
            self.state.registry.remove_connection(&id_hash);
        }
    }
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    state.registry.inc_total(); // Immediate tracking
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<QueuedMessage>();

    let mut guard = ConnectionGuard {
        state: state.clone(),
        identity_hash: None,
        authenticated: false,
    };
    let mut _challenge_solved = false;
    let mut control_assembler: HashMap<u32, FragmentBuffer> = HashMap::new();

    // SECURITY: Limit global total connections (Identity-Agnostic)
    if state.registry.connection_count() >= state.config.max_global_connections {
        state.metrics.increment_counter("global_limit_rejected", 1.0);
        return;
    }

    let mut next_dummy_sleep = Box::pin(tokio::time::sleep(Duration::from_millis(thread_rng().gen_range(1000..10000))));
    let mut handshake_check_timer = tokio::time::interval(Duration::from_secs(2));
    handshake_check_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cleanup_timer = Box::pin(tokio::time::sleep(Duration::from_secs(30)));
    let conn_timeout = Duration::from_secs(state.config.connection_timeout_sec);
    let mut last_activity = tokio::time::Instant::now();

    'outer: loop {
        tokio::select! {
            Some(qm) = rx.recv() => {
                let frame_type = match &qm.msg { Message::Text(_) => "Text", Message::Binary(_) => "Binary", Message::Close(_) => "Close", _ => "Other" };
                let wire_size = match &qm.msg { Message::Text(t) => t.len(), Message::Binary(b) => b.len(), _ => 0 };
                tracing::info!("[Net] Server sending {} Frame: wire_size={}", frame_type, wire_size);
                if sender.send(qm.msg).await.is_err() { break 'outer; }
            }
            _ = &mut cleanup_timer => {
                let now = tokio::time::Instant::now();
                control_assembler.retain(|_, v| now.duration_since(v.last_activity) < Duration::from_secs(60));
                cleanup_timer = Box::pin(tokio::time::sleep(Duration::from_secs(30)));
            }
            _ = handshake_check_timer.tick() => {
                if !guard.authenticated && last_activity.elapsed() > Duration::from_secs(10) {
                    tracing::warn!("[Security] Handshake Watchdog: Timeout (Slow/No PoW) - Dropping Socket");
                    break 'outer;
                }
            }
            _ = &mut next_dummy_sleep => {
                let mut dummy_vec = vec![0u8; state.config.pacing.packet_size];
                dummy_vec[0] = 0x03; // Type 0x03 Binary Dummy
                TrafficNormalizer::pad_binary(&mut dummy_vec, state.config.pacing.packet_size);
                
                tracing::info!("[Net] Server sending Binary Dummy Pacing: wire_size={}", dummy_vec.len());
                if sender.send(Message::Binary(dummy_vec.into())).await.is_err() { break 'outer; }
                
                if last_activity.elapsed() > conn_timeout { break 'outer; }
                next_dummy_sleep = Box::pin(tokio::time::sleep(Duration::from_millis(thread_rng().gen_range(1000..10000))));
            }
            Some(result) = receiver.next() => {
                last_activity = tokio::time::Instant::now();
                let Ok(msg) = result else { break; };
                match msg {
                    Message::Text(text) => {
                        let frame_size = text.len();
                        if frame_size != state.config.pacing.packet_size {
                            tracing::warn!("[Security] Stealth Violation: Received Non-Standard Text Frame (size={}) - Prefix: {:?} - Dropping Connection", frame_size, &text[..std::cmp::min(100, text.len())]);
                            if let Some(ref id_hash) = guard.identity_hash {
                                let _ = state.redis.penalize_uid(id_hash, state.config.jail_duration_sec).await;
                            }
                            break 'outer;
                        }

                        if !InputValidator::pre_scan_depth(&text, state.config.max_json_depth) {
                            tracing::warn!("[Security] JSON Depth violation (Pre-Scan/Text) - Dropping Frame");
                            continue;
                        }
                        let Ok(val) = serde_json::from_str::<Value>(&text) else { continue; };
                        if !process_command(val, &state, &mut guard, &tx, &mut _challenge_solved, &text).await {
                            break 'outer;
                        }
                    }
                    Message::Binary(data) => {
                        let frame_size = data.len();
                        if frame_size != state.config.pacing.packet_size {
                            tracing::warn!("[Security] Stealth Violation: Received Non-Standard Binary Frame (size={}) - Dropping Connection", frame_size);
                            if let Some(ref id_hash) = guard.identity_hash {
                                let _ = state.redis.penalize_uid(id_hash, state.config.jail_duration_sec).await;
                            }
                            break 'outer; 
                        }
                        let target_bytes = &data[0..64];
                        let b_type = data[64];

                        // 🛡️ AUTHENTICATED JAIL CHECK (Binary Lane)
                        if let Some(ref uid) = guard.identity_hash {
                            if let Ok(res) = state.redis.check_rate_limit(&format!("limit:relay:uid:{}", uid), state.config.relay_limit.into(), state.config.relay_window_sec, 0).await {
                                if res.is_jailed {
                                    tracing::warn!("[Security] Dropping Binary from Jailed Identity: {}", uid);
                                    break 'outer;
                                }
                            }
                        }
                        
                        // FAST-DROP 0x03 (Dummy Pacing)
                        if b_type == 0x03 {
                            // Charge a cost of 1 token even for dummies to prevent pacing-floods
                            if let Some(ref uid) = guard.identity_hash {
                                let _ = state.redis.check_rate_limit(&format!("limit:relay:uid:{}", uid), state.config.relay_limit.into(), state.config.relay_window_sec, 1).await;
                            }
                            continue;
                        }

                        let transfer_id = u32::from_be_bytes(data[65..69].try_into().unwrap());
                        let index = u32::from_be_bytes(data[69..73].try_into().unwrap());
                        let total = u32::from_be_bytes(data[73..77].try_into().unwrap());
                        let len = u32::from_be_bytes(data[77..81].try_into().unwrap());
                        
                        if data.len() < (81 + len as usize) { 
                            tracing::warn!("[Security] Buffer/Spec mismatch (len field {} > capacity {}) - Dropping Frame", len, data.len().saturating_sub(81));
                            continue;
                        }

                        let chunk_data = &data[81..81 + len as usize];
                        let is_control = target_bytes.iter().all(|&b| b == 0) && b_type == 0x00;

                        if is_control {
                            let max_chunks = (state.config.max_message_size as f32 / 1300.0).ceil() as u32;
                            if total > max_chunks { tracing::warn!("[Security] Dropped Oversized Command (total={} > max={})", total, max_chunks); continue; }
                            let entry = control_assembler.entry(transfer_id).or_insert_with(|| FragmentBuffer {
                                total, chunks: HashMap::new(), last_activity: tokio::time::Instant::now(),
                            });
                            entry.chunks.insert(index, chunk_data.to_vec());
                            entry.last_activity = tokio::time::Instant::now();

                            if entry.chunks.len() as u32 == entry.total {
                                let mut full_data = Vec::new();
                                for i in 0..entry.total { if let Some(c) = entry.chunks.remove(&i) { full_data.extend(c); } }
                                control_assembler.remove(&transfer_id);
                                if let Ok(cmd_text) = String::from_utf8(full_data) {
                                    if !InputValidator::pre_scan_depth(&cmd_text, state.config.max_json_depth) {
                                        tracing::warn!("[Security] JSON Depth violation (Pre-Scan/Control) - Dropping Reassembly");
                                        continue;
                                    }
                                    if let Ok(val) = serde_json::from_str::<Value>(&cmd_text) {
                                        if !process_command(val, &state, &mut guard, &tx, &mut _challenge_solved, &cmd_text).await {
                                            break 'outer;
                                        }
                                    }
                                }
                            }
                        } else {
                            if let Some(uid_hash) = guard.identity_hash.as_ref() {
                                    let mut target = String::with_capacity(64);
                                    for &byte in target_bytes { if byte == 0 { break; } target.push(byte as char); }
                                    let target_hash = target.trim();
                                    if InputValidator::is_valid_hash(target_hash) {
                                        // 🛡️ SENDER CHECK: Enforce identity limits (Media or Relay)
                                        let (sender_limit_key, sender_limit_size) = if b_type == 0x02 {
                                            (format!("limit:media:uid:{}", uid_hash), state.config.media_limit.into())
                                        } else {
                                            (format!("limit:relay:uid:{}", uid_hash), state.config.relay_limit.into())
                                        };

                                        if let Ok(res) = state.redis.check_rate_limit(&sender_limit_key, sender_limit_size, state.config.relay_window_sec, 1).await {
                                            if !res.allowed {
                                                if res.is_jailed { 
                                                    let _ = tx.send(QueuedMessage { msg: Message::Text(json!({"type": "error", "error": "Identity Jailed"}).to_string()) });
                                                    break 'outer; 
                                                }
                                                let _ = tx.send(QueuedMessage { msg: Message::Text(json!({"type": "error", "error": "Rate limit exceeded"}).to_string()) });
                                                continue;
                                            }
                                        }

                                        // RECIPIENT PROTECTION REMOVED: Forwarding directly to target for unthrottled p2p transit
                                        if b_type == 0x04 {
                                            state.relay.relay_volatile(target_hash, &data[64..], uid_hash).await; 
                                        } else {
                                            state.relay.relay_binary(target_hash, &data[64..], uid_hash).await; 
                                        }
                                    }
                            } else { tracing::warn!("[Security] Rejected binary relay from unauthenticated socket."); }
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    }
}

async fn process_command(
    val: Value,
    state: &Arc<AppState>,
    guard: &mut ConnectionGuard,
    tx: &tokio::sync::mpsc::UnboundedSender<QueuedMessage>,
    _challenge_solved: &mut bool,
    raw_text: &str,
) -> bool {
    let depth = InputValidator::get_json_depth(&val);
    if depth > state.config.max_json_depth { 
        tracing::warn!("[Security] JSON Depth violation from authenticated identity - REJECTING"); 
        return false; 
    }

    let msg_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
    let req_id = val.get("req_id").cloned();
    let send_response = |mut res: Value, tx: &tokio::sync::mpsc::UnboundedSender<QueuedMessage>| {
        if let Some(id) = &req_id {
            res["req_id"] = id.clone();
        }
        let mut final_json = serde_json::to_string(&res).unwrap();
        let raw_len = final_json.len();
        TrafficNormalizer::pad_json_str(&mut final_json, state.config.pacing.packet_size);
        tracing::info!("[Net] Prepared Response: raw_size={} bytes, wire_size={} bytes, overhead={} bytes", 
            raw_len, 
            final_json.len(), 
            final_json.len().saturating_sub(raw_len));
        let _ = tx.send(QueuedMessage { msg: Message::Text(final_json.into()), });
    };

    if !guard.authenticated && !["pow_challenge", "auth", "dummy_pacing"].contains(&msg_type) {
        tracing::warn!("[Security] Unauthorized command: {}", msg_type);
        send_response(json!({"type": "error", "error": "Handshake required"}), tx);
        return true; 
    }

    // 🛡️ GLOBAL JAILING CHECK (Any authenticated activity)
    if let Some(ref uid) = guard.identity_hash {
        // Fix: Changed cost from 0 to 1 to prevent high-frequency Command-Flood DoS
        if let Ok(res) = state.redis.check_rate_limit(&format!("limit:relay:uid:{}", uid), state.config.relay_limit.into(), state.config.relay_window_sec, 1).await {
            if res.is_jailed {
                send_response(json!({"type": "error", "error": "Identity Jailed"}), tx);
                return false; // Terminal disconnect
            }
        }
    }

    match msg_type {
        "pow_challenge" => { send_response(state.identity.handle_pow_challenge(&val).await, tx); }
        "auth" => {
            let mut auth_valid = false;
            let mut id_hash_str = String::new();
            if let Some(payload) = val.get("payload") {
                id_hash_str = payload.get("identity_hash").and_then(|h| h.as_str()).map(|s| InputValidator::sanitize_field(s, 256)).unwrap_or_default();
                if let Some(token) = payload.get("session_token").and_then(|t| t.as_str()) {
                    if state.redis.verify_session_token(&id_hash_str, token).await.unwrap_or(false) { auth_valid = true; }
                }
                if !auth_valid {
                    let intensity = state.redis.get_registration_intensity().await.unwrap_or(0);
                    let mut penalty = 0; 
                    if intensity > state.config.registration_intensity_low as i32 { penalty = 2; } 
                    if intensity > state.config.registration_intensity_high as i32 { penalty = 4; }
                    
                    // 🚩 SHADOW PENALTY: Check if identity has recent violations
                    if !id_hash_str.is_empty() {
                        if let Ok(count) = state.redis.get_identity_violations(&id_hash_str).await {
                            if u64::from(count) >= state.config.identity_violation_threshold { penalty += 4; } // Identity-specific multiplier
                        }
                    }

                    let req_diff = crate::security::pow::PoWVerifier::get_required_difficulty(state.config.pow_base_difficulty, state.registry.connection_count(), penalty, state.config.max_pow_difficulty as u32);
                    if payload.get("signature").is_some() {
                        if state.identity.validate_pow(payload, &id_hash_str, req_diff).await { auth_valid = true; }
                    }
                }
            }
            if auth_valid && !id_hash_str.is_empty() {
                // 🛡️ JAILING PRE-CHECK
                if let Ok(res) = state.redis.check_rate_limit(&format!("limit:relay:uid:{}", id_hash_str), state.config.relay_limit.into(), state.config.relay_window_sec, 0).await {
                    if res.is_jailed {
                        send_response(json!({"type": "error", "error": "Identity Jailed"}), tx);
                        return false;
                    }
                }

                if !guard.authenticated { state.metrics.increment_gauge("active_connections", 1.0); }
                *_challenge_solved = true;
                guard.authenticated = true;
                guard.identity_hash = Some(id_hash_str.clone());

                if let Some(old_tx) = state.registry.add_connection(id_hash_str.clone(), tx.clone()) {
                    tracing::info!("[Net] Ghost Protocol: Terminating abandoned socket for {}", id_hash_str);
                    let _ = old_tx.send(QueuedMessage { msg: Message::Close(None) });
                }

                let new_token = state.redis.create_session_token(&id_hash_str, state.config.session_ttl_sec).await.unwrap_or_default();
                
                let otk_count = state.redis.get_otk_count(&id_hash_str).await.unwrap_or(0);
                let keys_missing = state.redis.get_user_bundle(&id_hash_str).await.map(|b| b.is_none()).unwrap_or(true);
                
                let response = json!({ 
                    "type": "auth_success", 
                    "identity_hash": id_hash_str, 
                    "session_token": new_token, 
                    "keys_missing": keys_missing,
                    "otk_count": otk_count
                });
                
                tracing::info!("[Auth] Login Success: id={} otk_remaining={}", id_hash_str, otk_count);
                send_response(response, tx);
                state.relay.deliver_pending(&id_hash_str, tx.clone()).await;
            } else {
                send_response(json!({"type": "error", "error": "Handshake failed"}), tx);
                return false;
            }
        }
        "keys_upload" => {
            let limit_key = if let Some(ref uid) = guard.identity_hash {
                format!("limit:keys_up:uid:{}", uid)
            } else {
                return false; 
            };
            if let Ok(res) = state.redis.check_rate_limit(&limit_key, state.config.keys_upload_limit.into(), state.config.keys_window_sec, 1).await {
                if !res.allowed { return false; }
            }
            send_response(state.identity.handle_keys_upload(&val).await, tx);
        }
        "fetch_key" => { send_response(state.identity.handle_keys_fetch(&val).await, tx); }
        "nickname_register" => { 
            if let Some(ref uid) = guard.identity_hash {
                let mut sanitized_val = val.clone();
                sanitized_val["identity_hash"] = json!(uid);
                send_response(state.identity.handle_nickname_register(&sanitized_val).await, tx); 
            } else {
                send_response(json!({"type": "error", "error": "Handshake required for nickname registration"}), tx);
            }
        }
        "nickname_lookup" => { send_response(state.identity.handle_nickname_lookup(&val).await, tx); }
        "identity_resolve" => { send_response(state.identity.handle_identity_resolve(&val).await, tx); }
        "account_burn" => { 
            if let Some(ref uid) = guard.identity_hash {
                let mut sanitized_val = val.clone();
                sanitized_val["identity_hash"] = json!(uid);
                send_response(state.identity.handle_account_burn(&sanitized_val).await, tx); 
            } else {
                send_response(json!({"type": "error", "error": "Handshake required for account burn"}), tx);
            }
        }
        _ => {
            if let Some(ref uid) = guard.identity_hash {
                let is_relay = val.get("target").is_some() || val.get("type").map(|t| t == "text_msg").unwrap_or(false);
                if is_relay {
                    if let Ok(res) = state.redis.check_rate_limit(&format!("limit:relay:uid:{}", uid), state.config.relay_limit.into(), state.config.relay_window_sec, 1).await {
                        if res.allowed { state.relay.relay_message(raw_text, uid).await; }
                        else {
                            if res.is_jailed {
                                send_response(json!({"type": "error", "error": "Identity Jailed"}), tx);
                                return false; 
                            }
                            send_response(json!({"type": "error", "error": "Rate limit exceeded"}), tx);
                            return true; // Simple rate limit
                        }
                    }
                }
            }
        }
    }
    true
}
