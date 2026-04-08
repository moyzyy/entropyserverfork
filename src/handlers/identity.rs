use serde_json::{json, Value};
use std::sync::Arc;
use crate::db::redis::RedisManager;
use crate::security::validator::InputValidator;
use crate::security::pow::PoWVerifier;
use crate::server::registry::Registry;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{thread_rng, Rng};
use hex;
use sha2::{Sha256, Digest};
use crate::config::ServerConfig;

pub struct IdentityHandler {
    redis: Arc<RedisManager>,
    registry: Arc<Registry>,
    config: Arc<ServerConfig>,
}

impl IdentityHandler {
    pub fn new(redis: Arc<RedisManager>, registry: Arc<Registry>, config: Arc<ServerConfig>) -> Self {
        Self { redis, registry, config }
    }

    pub async fn handle_pow_challenge(&self, req: &Value) -> Value {

        let ttl = 60;
        let seed_bytes: [u8; 32] = thread_rng().gen();
        let seed = hex::encode(seed_bytes);
        let _ = self.redis.issue_challenge_with_seed(&seed, ttl).await;
        let difficulty = self.get_required_pow(req).await;

        let mut res = json!({
            "type": "pow_challenge_res",
            "seed": seed,
            "difficulty": difficulty,
            "modulus": self.config.vdf_modulus
        });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
        res
    }

    async fn get_required_pow(&self, _req: &Value) -> u32 {
        let mut penalty = 0;
        let intensity = self.redis.get_registration_intensity().await.unwrap_or(0);
        if intensity > self.config.registration_intensity_low as i32 { penalty = 2; }
        if intensity > self.config.registration_intensity_high as i32 { penalty = 4; }

        let active_conns = self.registry.connection_count();
        PoWVerifier::get_required_difficulty(self.config.pow_base_difficulty, active_conns, penalty, self.config.max_pow_difficulty as u32)
    }

    pub async fn validate_pow(&self, obj: &Value, context: &str, target_difficulty: u32) -> bool {
        let Some(seed) = obj.get("seed").and_then(|s| s.as_str()) else { return false; };
        let Some(nonce) = obj.get("nonce").and_then(|n| n.as_str().map(|s| s.to_string())) else { return false; };

        if !self.redis.consume_challenge(seed).await.unwrap_or(false) { return false; }
        let x_bytes = hex::decode(seed).unwrap_or_default();

        if !PoWVerifier::validate_vdf(seed, &nonce, target_difficulty, &self.config.vdf_modulus, &self.config.vdf_phi) {
            return false;
        }

        let Some(sig_str) = obj.get("signature").and_then(|s| s.as_str()) else { return false; };
        let Some(pk_str) = obj.get("public_key").or_else(|| obj.get("identityKey")).and_then(|k| k.as_str()) else { return false; };

        let Ok(sig_bytes) = hex::decode(sig_str).or_else(|_| base64::engine::general_purpose::STANDARD.decode(sig_str)) else { return false; };
        let mut pk_bytes = hex::decode(pk_str).or_else(|_| base64::engine::general_purpose::STANDARD.decode(pk_str)).unwrap_or_default();
        if pk_bytes.len() == 33 && pk_bytes[0] == 0x05 { pk_bytes.remove(0); }

        if !InputValidator::verify_xeddsa(&pk_bytes, &x_bytes, &sig_bytes) && !InputValidator::verify_ed25519(&pk_bytes, &x_bytes, &sig_bytes) {
            return false;
        }

        if !InputValidator::verify_id_hash(context, &pk_bytes) { return false; }
        true
    }

    pub async fn handle_keys_upload(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") { response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }

        let id_field = req.get("identity_hash").or_else(|| req.get("id_hash"));
        let Some(id_hash) = id_field.and_then(|h| h.as_str()) else {
            response["error"] = json!("Missing identity_hash");
            return response;
        };

        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else {
            response["error"] = json!("Signature required");
            return response;
        };

        let pubkey_str = req.get("identityKey").or_else(|| req.get("public_key")).and_then(|k| k.as_str());
        let Some(pk_val) = pubkey_str else {
            response["error"] = json!("Missing public key");
            return response;
        };

        let pubkey_bytes = if pk_val.len() == 64 { hex::decode(pk_val).unwrap_or_default() } else { 
            let mut d = BASE64.decode(pk_val).unwrap_or_default();
            if d.len() == 33 && d[0] == 0x05 { d.remove(0); }
            d
        };

        let mut hasher = Sha256::new();
        hasher.update(&pubkey_bytes);
        if hex::encode(hasher.finalize()) != id_hash {
             response["error"] = json!("Identity mismatch");
             return response;
        }

        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };
        if !InputValidator::verify_xeddsa(&pubkey_bytes, id_hash.as_bytes(), &sig_bytes) && 
           !InputValidator::verify_ed25519(&pubkey_bytes, id_hash.as_bytes(), &sig_bytes) {
               response["error"] = json!("Ownership proof failed");
               return response;
        }

        let mut prekeys = Vec::new();
        if let Some(pk_list) = req.get("preKeys").and_then(|a| a.as_array()) {
            for pk in pk_list { prekeys.push(serde_json::to_string(pk).unwrap_or_default()); }
        }

        let mut kyber_prekeys = Vec::new();
        if let Some(kpk_list) = req.get("kyberPreKeys").and_then(|a| a.as_array()) {
            for kpk in kpk_list { kyber_prekeys.push(serde_json::to_string(kpk).unwrap_or_default()); }
        }

        if let Err(e) = self.redis.store_user_bundle(id_hash, &serde_json::to_string(req).unwrap_or_default()).await {
            response["error"] = json!(format!("Bundle storage failed: {}", e));
            return response;
        }

        if !prekeys.is_empty() { 
            if let Err(e) = self.redis.store_otk_pool(id_hash, prekeys).await {
                response["error"] = json!(format!("OTK pool storage failed: {}", e));
                return response;
            }
        }

        if !kyber_prekeys.is_empty() {
            if let Err(e) = self.redis.store_kyber_otk_pool(id_hash, kyber_prekeys).await {
                response["error"] = json!(format!("Kyber OTK pool storage failed: {}", e));
                return response;
            }
        }

        json!({"type": "keys_upload_res", "status": "success"})
    }

    pub async fn handle_keys_fetch(&self, req: &Value) -> Value {
        let response = json!({"type": "error", "status": "error"});
        let Some(target) = req.get("target_hash").and_then(|t| t.as_str()) else { return response; };
        let Some(initiator_hash) = req.get("initiator_hash").and_then(|h| h.as_str()) else { return response; };
        
        let mut res = json!({ "type": "fetch_key_res" });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }

        if let Ok(limit_res) = self.redis.check_rate_limit(&format!("limit:keys_f:uid:{}", initiator_hash), self.config.key_fetch_limit.into(), self.config.keys_window_sec, 1).await {
            if !limit_res.allowed { return json!({"type": "error", "error": "Key fetch rate limit exceeded"}); }
        }

        if let Ok(Some(bundle_str)) = self.redis.get_user_bundle(target).await {
            let mut bundle_json: Value = serde_json::from_str(&bundle_str).unwrap_or(json!({}));
            
            // Pop both standard and Kyber OTKs simultaneously
            if let Ok((otk, kyber_otk)) = self.redis.pop_pqdh_otks(target).await {
                if let Some(otk_str) = otk {
                    if let Ok(otk_json) = serde_json::from_str::<Value>(&otk_str) {
                        bundle_json.as_object_mut().unwrap().insert("preKey".to_string(), otk_json);
                    }
                }
                if let Some(kyber_otk_str) = kyber_otk {
                    if let Ok(kyber_otk_json) = serde_json::from_str::<Value>(&kyber_otk_str) {
                             bundle_json.as_object_mut().unwrap().insert("kyberPreKey".to_string(), kyber_otk_json);
                    }
                }
            }

            // Notify owner if their PreKey pool is running low
            if let Ok(count) = self.redis.get_otk_count(target).await {
                if count < 10 {
                    if let Some(target_tx) = self.registry.get_connection(target) {
                        let alert = json!({ "type": "keys_low", "count": count });
                        let mut alert_str = serde_json::to_string(&alert).unwrap();
                        crate::security::noise::TrafficNormalizer::pad_json_str(&mut alert_str, self.config.pacing.packet_size);
                        let _ = target_tx.send(crate::relay::QueuedMessage { msg: axum::extract::ws::Message::Text(alert_str) });
                    }
                }
            }

            res.as_object_mut().unwrap().insert("found".to_string(), json!(true));
            res.as_object_mut().unwrap().insert("bundle".to_string(), bundle_json);
        } else {
            res.as_object_mut().unwrap().insert("found".to_string(), json!(false));
        }
        res
    }

    pub async fn handle_nickname_register(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        let Some(raw_nick) = req.get("nickname").and_then(|n| n.as_str()) else { return response; };
        let nick = InputValidator::normalize_nickname(raw_nick);
        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else { return response; };

        // Enforced at WebSocket layer

        if let Ok(res) = self.redis.check_rate_limit(&format!("limit:nick:reg:{}", id_hash), self.config.nick_register_limit.into(), 3600, 1).await {
            if !res.allowed { response["error"] = json!("Rate limit exceeded"); return response; }
        }

        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else { return response; };
        let pk_val = req.get("identityKey").or_else(|| req.get("public_key")).and_then(|k| k.as_str()).unwrap_or("");
        let pk_bytes = if pk_val.len() == 64 { hex::decode(pk_val).unwrap_or_default() } else { BASE64.decode(pk_val).unwrap_or_default() };
        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };

        let payload = format!("NICKNAME_REGISTER:{}", raw_nick);
        if !InputValidator::verify_id_hash(id_hash, &pk_bytes) {
            return json!({"type": "error", "error": "Identity mismatch: Public key does not match hash"});
        }
        
        if !InputValidator::verify_xeddsa(&pk_bytes, payload.as_bytes(), &sig_bytes) && 
           !InputValidator::verify_ed25519(&pk_bytes, payload.as_bytes(), &sig_bytes) {
               return json!({"type": "error", "error": "Ownership proof failed"});
        }

        match self.redis.register_nickname(&nick, id_hash).await {
            Ok(true) => json!({ "type": "nickname_register_res", "status": "success" }),
            _ => json!({ "type": "error", "error": "Nickname already taken" }),
        }
    }

    pub async fn handle_nickname_lookup(&self, req: &Value) -> Value {
        let Some(raw_name) = req.get("name").and_then(|n| n.as_str()) else { return json!({}); };
        let name = InputValidator::normalize_nickname(raw_name);
        let Some(initiator_hash) = req.get("initiator_hash").and_then(|h| h.as_str()) else {
            return json!({"type": "error", "error": "Initiator hash required"});
        };
        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else {
            return json!({"type": "error", "error": "Signature required"});
        };
        let Some(pk_str) = req.get("public_key").and_then(|k| k.as_str()) else {
            return json!({"type": "error", "error": "Public key required"});
        };

        if let Ok(res) = self.redis.check_rate_limit(&format!("limit:lookup:uid:{}", initiator_hash), self.config.lookup_limit.into(), self.config.relay_window_sec, 1).await {
            if !res.allowed { return json!({"type": "error", "error": "Lookup rate limit exceeded"}); }
        }

        // Verify the requester is who they say they are
        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };
        let pk_bytes = if pk_str.len() == 64 { hex::decode(pk_str).unwrap_or_default() } else { BASE64.decode(pk_str).unwrap_or_default() };
        
        let payload = format!("LOOKUP_NICKNAME:{}", raw_name);
        if !InputValidator::verify_xeddsa(&pk_bytes, payload.as_bytes(), &sig_bytes) &&
           !InputValidator::verify_ed25519(&pk_bytes, payload.as_bytes(), &sig_bytes) {
               return json!({"type": "error", "error": "Initiator signature invalid"});
        }

        let h = self.redis.resolve_nickname(&name).await.unwrap_or_default();
        let mut res = json!({ "type": "nickname_lookup_res" });
        if let Some(target) = h { res.as_object_mut().unwrap().insert("identity_hash".to_string(), json!(target)); }
        res
    }

    pub async fn handle_identity_resolve(&self, req: &Value) -> Value {
        let Some(target_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else { return json!({}); };
        let Some(initiator_hash) = req.get("initiator_hash").and_then(|h| h.as_str()) else {
            return json!({"type": "error", "error": "Initiator hash required"});
        };
        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else {
            return json!({"type": "error", "error": "Signature required"});
        };
        let Some(pk_str) = req.get("public_key").and_then(|k| k.as_str()) else {
            return json!({"type": "error", "error": "Public key required"});
        };

        // Strictly rate limit resolution per identity
        if let Ok(res) = self.redis.check_rate_limit(&format!("limit:resolve:uid:{}", initiator_hash), self.config.lookup_limit.into(), self.config.relay_window_sec, 1).await {
            if !res.allowed { return json!({"type": "error", "error": "Resolution rate limit exceeded"}); }
        }

        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };
        let pk_bytes = if pk_str.len() == 64 { hex::decode(pk_str).unwrap_or_default() } else { BASE64.decode(pk_str).unwrap_or_default() };
        
        let payload = format!("RESOLVE_IDENTITY:{}", target_hash);
        if !InputValidator::verify_xeddsa(&pk_bytes, payload.as_bytes(), &sig_bytes) &&
           !InputValidator::verify_ed25519(&pk_bytes, payload.as_bytes(), &sig_bytes) {
               return json!({"type": "error", "error": "Initiator signature invalid"});
        }

        let nick = self.redis.get_nickname(target_hash).await.unwrap_or_default();
        json!({ "type": "identity_resolve_res", "identity_hash": target_hash, "nickname": nick })
    }

    pub async fn handle_account_burn(&self, req: &Value) -> Value {
        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else { return json!({}); };
        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else { return json!({}); };
        let pk_val = req.get("public_key").or_else(|| req.get("identityKey")).and_then(|k| k.as_str()).unwrap_or("");
        let pk_bytes = if pk_val.len() == 64 { hex::decode(pk_val).unwrap_or_default() } else { BASE64.decode(pk_val).unwrap_or_default() };
        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };

        let payload = format!("BURN_ACCOUNT:{}", id_hash);
        if !InputValidator::verify_xeddsa(&pk_bytes, payload.as_bytes(), &sig_bytes) { 
            return json!({}); 
        }
        match self.redis.nuclear_burn(id_hash).await {
            Ok(_) => json!({ "type": "account_burn_res", "status": "success" }),
            _ => json!({ "type": "error" }),
        }
    }

    pub async fn handle_session_revoke(&self, user_hash: &str) -> Value {
        match self.redis.revoke_session_token(user_hash).await {
            Ok(_) => json!({ "type": "session_revoke_res", "status": "success" }),
            Err(_) => json!({ "type": "error", "message": "Revocation failed" }),
        }
    }
}
