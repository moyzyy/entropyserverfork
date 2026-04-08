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

enum CommandResult {
    Continue,
    Close,
    ErrorAndClose(Value),
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.max_message_size(state.config.max_message_size)
      .on_upgrade(move |socket| handle_socket(socket, state))
}

struct ConnectionGuard {
    state: Arc<AppState>,
    identity_hash: Option<String>,
    authenticated: bool,
    jailed_until: Option<tokio::time::Instant>,
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
    state.registry.inc_total();
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<QueuedMessage>();

    let mut guard = ConnectionGuard {
        state: state.clone(),
        identity_hash: None,
        authenticated: false,
        jailed_until: None,
    };
    let mut _challenge_solved = false;
    let mut control_assembler: HashMap<u32, FragmentBuffer> = HashMap::new();

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

                if sender.send(qm.msg).await.is_err() { break 'outer; }
            }
            _ = &mut cleanup_timer => {
                let now = tokio::time::Instant::now();
                control_assembler.retain(|_, v| now.duration_since(v.last_activity) < Duration::from_secs(60));
                cleanup_timer = Box::pin(tokio::time::sleep(Duration::from_secs(30)));
            }
            _ = handshake_check_timer.tick() => {
                if !guard.authenticated && last_activity.elapsed() > Duration::from_secs(10) {
                    break 'outer;
                }
            }
            _ = &mut next_dummy_sleep => {
                let mut dummy_vec = vec![0u8; state.config.pacing.packet_size];
                dummy_vec[0] = 0x03; 
                TrafficNormalizer::pad_binary(&mut dummy_vec, state.config.pacing.packet_size);
                

                if sender.send(Message::Binary(dummy_vec)).await.is_err() { break 'outer; }
                
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
                            tracing::warn!("[Security] Stealth Violation: Received Non-Standard Text Frame (size={})", frame_size);
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
                        match process_command(val, &state, &mut guard, &tx, &mut _challenge_solved).await {
                            CommandResult::Continue => {},
                            CommandResult::Close => break 'outer,
                            CommandResult::ErrorAndClose(err_val) => {
                                let mut final_json = serde_json::to_string(&err_val).unwrap();
                                TrafficNormalizer::pad_json_str(&mut final_json, state.config.pacing.packet_size);
                                let _ = sender.send(Message::Text(final_json)).await;
                                break 'outer;
                            }
                        }
                    }
                    Message::Binary(data) => {
                        let target_bytes = &data[0..64];
                        let b_type = data[64];

                        if let Some(ref _uid) = guard.identity_hash {
                            if let Some(until) = guard.jailed_until {
                                if tokio::time::Instant::now() < until {
                                    continue; // SILENT DROP
                                } else {
                                    guard.jailed_until = None;
                                }
                            }
                        }
                        
                        if b_type == 0x03 {
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
                                        match process_command(val, &state, &mut guard, &tx, &mut _challenge_solved).await {
                                            CommandResult::Continue => {},
                                            CommandResult::Close => break 'outer,
                                            CommandResult::ErrorAndClose(err_val) => {
                                                let mut final_json = serde_json::to_string(&err_val).unwrap();
                                                TrafficNormalizer::pad_json_str(&mut final_json, state.config.pacing.packet_size);
                                                let _ = sender.send(Message::Text(final_json)).await;
                                                break 'outer;
                                            }
                                        }
                                    }
                                }
                            }
                        } else if let Some(uid_hash) = guard.identity_hash.as_ref() {
                            let mut target = String::with_capacity(64);
                            for &byte in target_bytes { if byte == 0 { break; } target.push(byte as char); }
                            let target_hash = target.trim();
                            if InputValidator::is_valid_hash(target_hash) {
                                let (sender_limit_key, sender_limit_size) = if b_type == 0x02 {
                                    (format!("limit:media:uid:{}", uid_hash), state.config.media_limit.into())
                                } else {
                                    (format!("limit:relay:uid:{}", uid_hash), state.config.relay_limit.into())
                                };

                                if let Ok(res) = state.redis.check_rate_limit(&sender_limit_key, sender_limit_size, state.config.relay_window_sec, 1).await {
                                    if !res.allowed {
                                        if res.is_jailed { 
                                            guard.jailed_until = Some(tokio::time::Instant::now() + Duration::from_secs(20));
                                            let _ = tx.send(QueuedMessage { msg: Message::Text(json!({"type": "error", "error": "Identity Jailed"}).to_string()) });
                                            break 'outer; 
                                        }
                                        let _ = tx.send(QueuedMessage { msg: Message::Text(json!({"type": "error", "error": "Rate limit exceeded"}).to_string()) });
                                        continue;
                                    }
                                }

                                if b_type == 0x04 {
                                    state.relay.relay_volatile(target_hash, &data[64..], uid_hash).await; 
                                } else {
                                    state.relay.relay_binary(target_hash, &data[64..], uid_hash).await; 
                                }
                            }
                        } else {
                            tracing::warn!("[Security] Malicious Intent: Attempted binary relay before authentication");
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
) -> CommandResult {
    let depth = InputValidator::get_json_depth(&val);
    if depth > state.config.max_json_depth { 
        tracing::warn!("[Security] JSON Depth violation from authenticated identity - REJECTING"); 
        return CommandResult::Close; 
    }

    let msg_type = val.get("type").and_then(|t| t.as_str()).unwrap_or("unknown");
    let req_id = val.get("req_id").cloned();
    let send_response = |mut res: Value, tx: &tokio::sync::mpsc::UnboundedSender<QueuedMessage>| {
        if let Some(id) = &req_id {
            res["req_id"] = id.clone();
        }
        let mut final_json = serde_json::to_string(&res).unwrap();

        TrafficNormalizer::pad_json_str(&mut final_json, state.config.pacing.packet_size);

        let _ = tx.send(QueuedMessage { msg: Message::Text(final_json), });
    };

    if !guard.authenticated && !["pow_challenge", "auth", "dummy_pacing"].contains(&msg_type) {
        return CommandResult::ErrorAndClose(json!({"type": "error", "error": "Handshake required"}));
    }
    if let Some(ref uid) = guard.identity_hash {
        if let Some(until) = guard.jailed_until {
            if tokio::time::Instant::now() < until {
                return CommandResult::ErrorAndClose(json!({"type": "error", "error": "Identity Jailed"}));
            } else {
                guard.jailed_until = None;
            }
        }

        if let Ok(res) = state.redis.check_rate_limit(&format!("limit:relay:uid:{}", uid), state.config.relay_limit.into(), state.config.relay_window_sec, 1).await {
            if res.is_jailed {
                guard.jailed_until = Some(tokio::time::Instant::now() + Duration::from_secs(20));
                return CommandResult::ErrorAndClose(json!({"type": "error", "error": "Identity Jailed"}));
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
                    
                    let req_diff = crate::security::pow::PoWVerifier::get_required_difficulty(state.config.pow_base_difficulty, state.registry.connection_count(), penalty, state.config.max_pow_difficulty as u32);
                    if payload.get("signature").is_some() && state.identity.validate_pow(payload, &id_hash_str, req_diff).await { auth_valid = true; }
                }
            }
            if auth_valid && !id_hash_str.is_empty() {
                if !guard.authenticated { state.metrics.increment_gauge("active_connections", 1.0); }
                *_challenge_solved = true;
                guard.authenticated = true;
                guard.identity_hash = Some(id_hash_str.clone());

                if let Some(old_tx) = state.registry.add_connection(id_hash_str.clone(), tx.clone()) {

                    let _ = old_tx.send(QueuedMessage { msg: Message::Close(None) });
                }

                let _ = state.redis.refresh_nickname_ttl(&id_hash_str).await;
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
                

                send_response(response, tx);
                state.relay.deliver_pending(&id_hash_str, tx.clone()).await;
            } else {
                let mut err_res = json!({"type": "error", "error": "Handshake failed", "code": "auth_failed"});
                if let Some(rid) = req_id { err_res["req_id"] = rid; }
                return CommandResult::ErrorAndClose(err_res);
            }
        }
        "keys_upload" => {
            let limit_key = if let Some(ref uid) = guard.identity_hash {
                format!("limit:keys_up:uid:{}", uid)
            } else {
                return CommandResult::Close; 
            };
            if let Ok(res) = state.redis.check_rate_limit(&limit_key, state.config.keys_upload_limit.into(), state.config.keys_window_sec, 1).await {
                if !res.allowed { return CommandResult::Close; }
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
        "session_revoke" => {
            if let Some(ref uid) = guard.identity_hash {
                send_response(state.identity.handle_session_revoke(uid).await, tx);
            }
        }
        _ => {}
    }
    CommandResult::Continue
}
