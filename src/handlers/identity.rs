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
        // 🛡️ JAILING ENFORCEMENT
        if let Some(id_hash) = req.get("identity_hash").or_else(|| req.get("id_hash")).and_then(|h| h.as_str()) {
            if let Ok(res) = self.redis.check_rate_limit(&format!("limit:relay:uid:{}", id_hash), self.config.relay_limit.into(), 60, 0).await {
                if res.is_jailed { return json!({"type": "error", "error": "Identity Jailed"}); }
            }
        }

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

    async fn get_required_pow(&self, req: &Value) -> u32 {
        let mut intensity_penalty = 0;
        let intensity = self.redis.get_registration_intensity().await.unwrap_or(0);
        if intensity > self.config.registration_intensity_low as i32 { intensity_penalty = 2; }
        if intensity > self.config.registration_intensity_high as i32 { intensity_penalty = 4; }
        
        let active_conns = self.registry.connection_count();
        let mut difficulty = PoWVerifier::get_required_difficulty(self.config.pow_base_difficulty, active_conns, intensity_penalty, self.config.max_pow_difficulty as u32);
        
        if let Some(nick) = req.get("nickname").and_then(|n| n.as_str()) {
            difficulty = PoWVerifier::get_difficulty_for_nickname(nick.len());
        }

        difficulty
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

        // 🛡️ JAILING ENFORCEMENT
        if let Ok(res) = self.redis.check_rate_limit(&format!("limit:relay:uid:{}", id_hash), self.config.relay_limit.into(), 60, 0).await {
            if res.is_jailed { return json!({"type": "error", "error": "Identity Jailed"}); }
        }

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

        let _ = self.redis.store_user_bundle(id_hash, &serde_json::to_string(req).unwrap_or_default()).await;
        if !prekeys.is_empty() { let _ = self.redis.store_otk_pool(id_hash, prekeys).await; }

        let mut res = json!({ "type": "keys_upload_res", "status": "success" });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
        res
    }

    pub async fn handle_keys_fetch(&self, req: &Value) -> Value {
        let response = json!({"type": "error", "status": "error"});
        let Some(target) = req.get("target_hash").and_then(|t| t.as_str()) else { return response; };
        
        let mut res = json!({ "type": "fetch_key_res" });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }

        match self.redis.get_user_bundle(target).await {
            Ok(Some(bundle_str)) => {
                let mut bundle_json = serde_json::from_str::<Value>(&bundle_str).unwrap_or(json!({}));
                if let Ok(Some(otk_str)) = self.redis.pop_otk(target).await {
                    if let Ok(otk_json) = serde_json::from_str::<Value>(&otk_str) {
                        bundle_json.as_object_mut().unwrap().insert("preKey".to_string(), otk_json);
                    }
                }
                
                // 🦾 SYNC ALERT: Notify owner if their PreKey pool is running low
                if let Ok(count) = self.redis.get_otk_count(target).await {
                    if count < 10 {
                        if let Some(target_tx) = self.registry.get_connection(target) {
                            let alert = json!({ "type": "keys_low", "count": count });
                            let mut alert_str = serde_json::to_string(&alert).unwrap();
                            crate::security::noise::TrafficNormalizer::pad_json_str(&mut alert_str, self.config.pacing.packet_size);
                            let _ = target_tx.send(crate::relay::QueuedMessage { msg: axum::extract::ws::Message::Text(alert_str.into()) });
                        }
                    }
                }

                res.as_object_mut().unwrap().insert("found".to_string(), json!(true));
                res.as_object_mut().unwrap().insert("bundle".to_string(), bundle_json);
            },
            _ => { res.as_object_mut().unwrap().insert("found".to_string(), json!(false)); }
        }
        res
    }

    pub async fn handle_nickname_register(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        let Some(nick) = req.get("nickname").and_then(|n| n.as_str()) else { return response; };
        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else { return response; };

        // 🛡️ JAILING ENFORCEMENT
        if let Ok(res) = self.redis.check_rate_limit(&format!("limit:relay:uid:{}", id_hash), self.config.relay_limit.into(), 60, 0).await {
            if res.is_jailed { return json!({"type": "error", "error": "Identity Jailed"}); }
        }

        if let Ok(res) = self.redis.check_rate_limit(&format!("limit:nick:reg:{}", id_hash), self.config.nick_register_limit.into(), 3600, 1).await {
            if !res.allowed { response["error"] = json!("Rate limit exceeded"); return response; }
        }

        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else { return response; };
        let pk_val = req.get("identityKey").or_else(|| req.get("public_key")).and_then(|k| k.as_str()).unwrap_or("");
        let pk_bytes = if pk_val.len() == 64 { hex::decode(pk_val).unwrap_or_default() } else { BASE64.decode(pk_val).unwrap_or_default() };
        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };

        let payload = format!("NICKNAME_REGISTER:{}", nick);
        if !InputValidator::verify_xeddsa(&pk_bytes, payload.as_bytes(), &sig_bytes) && 
           !InputValidator::verify_ed25519(&pk_bytes, payload.as_bytes(), &sig_bytes) {
               return json!({"type": "error", "error": "Ownership proof failed"});
        }

        match self.redis.register_nickname(nick, id_hash).await {
            Ok(true) => json!({ "type": "nickname_register_res", "status": "success" }),
            _ => json!({ "type": "error", "error": "Nickname already taken" }),
        }
    }

    pub async fn handle_nickname_lookup(&self, req: &Value) -> Value {
        let Some(name) = req.get("name").and_then(|n| n.as_str()) else { return json!({}); };
        let h = self.redis.resolve_nickname(name).await.unwrap_or_default();
        let mut res = json!({ "type": "nickname_lookup_res" });
        if let Some(target) = h { res.as_object_mut().unwrap().insert("identity_hash".to_string(), json!(target)); }
        res
    }

    pub async fn handle_identity_resolve(&self, req: &Value) -> Value {
        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else { return json!({}); };
        let nick = self.redis.get_nickname(id_hash).await.unwrap_or_default();
        json!({ "type": "identity_resolve_res", "identity_hash": id_hash, "nickname": nick })
    }

    pub async fn handle_account_burn(&self, req: &Value) -> Value {
        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else { return json!({}); };
        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else { return json!({}); };
        let pk_val = req.get("public_key").or_else(|| req.get("identityKey")).and_then(|k| k.as_str()).unwrap_or("");
        let pk_bytes = if pk_val.len() == 64 { hex::decode(pk_val).unwrap_or_default() } else { BASE64.decode(pk_val).unwrap_or_default() };
        let sig_bytes = if sig_str.len() == 128 { hex::decode(sig_str).unwrap_or_default() } else { BASE64.decode(sig_str).unwrap_or_default() };

        if !InputValidator::verify_xeddsa(&pk_bytes, id_hash.as_bytes(), &sig_bytes) { return json!({}); }
        match self.redis.nuclear_burn(id_hash).await {
            Ok(_) => json!({ "type": "account_burn_res", "status": "success" }),
            _ => json!({ "type": "error" }),
        }
    }
}
