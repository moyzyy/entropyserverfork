use serde_json::{json, Value};
use std::sync::Arc;
use crate::db::redis::RedisManager;
use crate::security::validator::InputValidator;
use crate::security::pow::PoWVerifier;
use crate::server::registry::Registry;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{thread_rng, Rng};

pub struct IdentityHandler {
    redis: Arc<RedisManager>,
    registry: Arc<Registry>,
}

impl IdentityHandler {
    pub fn new(redis: Arc<RedisManager>, registry: Arc<Registry>) -> Self {
        Self { redis, registry }
    }

    pub async fn handle_pow_challenge(&self, req: &Value) -> Value {
        let ttl = 60;
        
        // Exact 1-to-1 matching: CSPRNG seed generation (32 random bytes -> 64 hex chars)
        let seed_bytes: [u8; 32] = thread_rng().gen();
        let seed = hex::encode(seed_bytes);
        
        // Register seed in Redis to prevent replays
        let _ = self.redis.issue_challenge_with_seed(&seed, ttl).await;
        
        let mut intensity_penalty = 0;
        let intensity = self.redis.get_registration_intensity().await.unwrap_or(0);
        if intensity > 10 { intensity_penalty = 2; }
        if intensity > 50 { intensity_penalty = 4; }
        if intensity > 200 { intensity_penalty = 8; }
        
        let mut age = 0;
        let mut id_hash_log = "none";
        if let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) {
            id_hash_log = id_hash;
            age = self.redis.get_account_age(id_hash).await.unwrap_or(0);
        }

        let active_conns = self.registry.connection_count();
        let mut difficulty = PoWVerifier::get_required_difficulty(active_conns, intensity_penalty, age);
        
        if let Some(nick) = req.get("nickname").and_then(|n| n.as_str()) {
            difficulty = PoWVerifier::get_difficulty_for_nickname(nick, active_conns, intensity_penalty, age);
        }

        if let Some(intent) = req.get("intent").and_then(|i| i.as_str()) {
            if intent == "burn" {
                difficulty = 4;
            }
        }

        let mut res = json!({
            "type": "pow_challenge_res",
            "seed": seed,
            "difficulty": difficulty
        });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
        
        tracing::debug!("Generated PoW challenge: id={} seed={} diff={}", id_hash_log, res["seed"], res["difficulty"]);
        res
    }

    pub async fn validate_pow(&self, obj: &Value, context: &str, target_difficulty: i32) -> bool {
        let Some(seed) = obj.get("seed").and_then(|s| s.as_str()) else { return false; };
        let Some(nonce) = obj.get("nonce").and_then(|n| {
            if n.is_string() { n.as_str().map(|s| s.to_string()) }
            else if n.is_number() { n.as_i64().map(|i| i.to_string()) }
            else { None }
        }) else { return false; };

        if seed.len() != 64 || !InputValidator::is_valid_hex(seed, Some(64)) { return false; }
        if nonce.len() > 32 { return false; }

        if !self.redis.consume_challenge(seed).await.unwrap_or(false) {
            return false;
        }

        PoWVerifier::verify(seed, &nonce, context, target_difficulty)
    }

    pub async fn handle_keys_upload(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") {
            response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone());
        }

        let id_field = req.get("identity_hash").or_else(|| req.get("id_hash"));
        let Some(id_hash) = id_field.and_then(|h| h.as_str()) else {
            response["error"] = json!("Missing identity_hash");
            return response;
        };

        if !self.validate_pow(req, id_hash, -1).await {
            response["error"] = json!("Invalid PoW");
            return response;
        }

        match self.redis.store_user_bundle(id_hash, &serde_json::to_string(req).unwrap()).await {
            Ok(_) => {
                let mut res = json!({
                    "type": "keys_upload_res",
                    "status": "success"
                });
                if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                res
            },
            Err(e) => {
                response["error"] = json!(format!("Storage error: {}", e));
                response
            }
        }
    }

    pub async fn handle_keys_fetch(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") {
            response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone());
        }

        let Some(target) = req.get("target_hash").and_then(|t| t.as_str()) else {
            response["error"] = json!("target_hash required");
            return response;
        };

        let mut hashes: Vec<String> = if target.contains(',') {
            target.split(',').filter(|s| !s.is_empty() && InputValidator::is_valid_hash(s)).map(|s| s.to_string()).collect()
        } else if InputValidator::is_valid_hash(target) {
            vec![target.to_string()]
        } else {
            response["error"] = json!("No valid hashes provided");
            return response;
        };

        if hashes.is_empty() {
            response["error"] = json!("No valid hashes provided");
            return response;
        }
        if hashes.len() > 10 { hashes.truncate(10); }

        let mut res = json!({ "type": "fetch_key_res" });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }

        if hashes.len() == 1 {
            match self.redis.get_user_bundle(&hashes[0]).await {
                Ok(Some(bundle)) => {
                    res.as_object_mut().unwrap().insert("found".to_string(), json!(true));
                    res.as_object_mut().unwrap().insert("bundle".to_string(), serde_json::from_str::<Value>(&bundle).unwrap_or(json!(bundle)));
                },
                _ => { res.as_object_mut().unwrap().insert("found".to_string(), json!(false)); }
            }
        } else {
            let mut bundles = json!({});
            for h in hashes {
                if let Ok(Some(bundle)) = self.redis.get_user_bundle(&h).await {
                    bundles.as_object_mut().unwrap().insert(h, serde_json::from_str::<Value>(&bundle).unwrap_or(json!(bundle)));
                }
            }
            res.as_object_mut().unwrap().insert("found".to_string(), json!(!bundles.as_object().unwrap().is_empty()));
            res.as_object_mut().unwrap().insert("bundles".to_string(), bundles);
        }
        res
    }

    pub async fn handle_keys_random(&self, req: &Value) -> Value {
        let count = req.get("count").and_then(|c| c.as_i64()).unwrap_or(5).clamp(1, 20) as usize;
        let hashes = self.redis.get_random_user_hashes(count).await.unwrap_or_default();
        
        let mut res = json!({
            "type": "fetch_key_random_res",
            "hashes": hashes
        });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
        res
    }

    pub async fn handle_nickname_register(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") {
            response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone());
        }

        let Some(nick) = req.get("nickname").and_then(|n| n.as_str()) else {
            response["error"] = json!("Missing nickname");
            return response;
        };
        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else {
            response["error"] = json!("Missing identity_hash");
            return response;
        };

        if !self.validate_pow(req, nick, -1).await {
            response["error"] = json!("Invalid PoW");
            return response;
        }

        match self.redis.register_nickname(nick, id_hash).await {
            Ok(true) => {
                let mut res = json!({
                    "type": "nickname_register_res",
                    "status": "success"
                });
                if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                res
            },
            Ok(false) => {
                response["error"] = json!("Nickname already taken");
                response
            },
            Err(e) => {
                response["error"] = json!(format!("Server error: {}", e));
                response
            }
        }
    }

    pub async fn handle_nickname_lookup(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") {
            response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone());
        }

        let Some(name) = req.get("name").and_then(|n| n.as_str()) else {
            response["error"] = json!("Missing lookup name");
            return response;
        };
        
        let h = self.redis.resolve_nickname(name).await.unwrap_or_default();
        let mut res = json!({ "type": "nickname_lookup_res" });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
        
        if let Some(id_hash) = h {
            res.as_object_mut().unwrap().insert("identity_hash".to_string(), json!(id_hash));
            res.as_object_mut().unwrap().insert("nickname".to_string(), json!(name));
        } else {
            res.as_object_mut().unwrap().insert("error".to_string(), json!("Not found"));
        }
        res
    }
    
    pub async fn handle_account_burn(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") {
            response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone());
        }

        let Some(id_hash) = req.get("identity_hash").and_then(|h| h.as_str()) else {
            response["error"] = json!("Missing identity_hash");
            return response;
        };

        tracing::debug!("Handling account_burn for id={}", id_hash);
        
        if !self.validate_pow(req, id_hash, 4).await {
            tracing::warn!("PoW validation failed for account_burn: id={}", id_hash);
            response["error"] = json!("Invalid PoW");
            return response;
        }
        
        let Some(sig_str) = req.get("signature").and_then(|s| s.as_str()) else {
            response["error"] = json!("Missing signature");
            return response;
        };
        
        let sig_bytes = if sig_str.len() == 128 && InputValidator::is_valid_hex(sig_str, Some(128)) {
            hex::decode(sig_str).unwrap_or_default()
        } else {
            BASE64.decode(sig_str).unwrap_or_default()
        };

        if sig_bytes.len() != 64 {
            response["error"] = json!("Invalid signature length");
            return response;
        }

        // Try to get public key from request or fallback to Redis
        let mut pk_str = req.get("public_key")
            .or_else(|| req.get("identityKey"))
            .and_then(|k| k.as_str())
            .map(|s| s.to_string());

        if pk_str.is_none() {
            // Fallback: try to fetch from stored keys (Match SPECS: self-healing burn)
            if let Ok(Some(bundle_json)) = self.redis.get_user_bundle(id_hash).await {
                if let Ok(bundle) = serde_json::from_str::<Value>(&bundle_json) {
                    pk_str = bundle.get("identityKey").and_then(|k| k.as_str()).map(|s| s.to_string());
                }
            }
        }

        let Some(pk_val) = pk_str else {
            response["error"] = json!("Missing verification key");
            return response;
        };

        let pubkey_bytes = if pk_val.len() == 64 && InputValidator::is_valid_hex(&pk_val, Some(64)) {
            hex::decode(&pk_val).unwrap_or_default()
        } else if pk_val.len() == 66 && InputValidator::is_valid_hex(&pk_val, Some(66)) {
            let mut decoded = hex::decode(&pk_val).unwrap_or_default();
            if decoded.first() == Some(&0x05) { decoded.remove(0); }
            decoded
        } else {
            let mut decoded = BASE64.decode(&pk_val).unwrap_or_default() ;
            if decoded.len() == 33 && decoded.first() == Some(&0x05) { decoded.remove(0); }
            decoded
        };

        if pubkey_bytes.len() != 32 {
            response["error"] = json!("Invalid public key length");
            return response;
        }

        let payload = format!("BURN_ACCOUNT:{}", id_hash);
        let msg_bytes = payload.as_bytes();

        tracing::debug!("Burn validation: id={} msg=\"{}\" msg_hex={} pk_hex={} sig_hex={}", 
            id_hash, payload, hex::encode(msg_bytes), hex::encode(&pubkey_bytes), hex::encode(&sig_bytes));

        if !InputValidator::verify_xeddsa(&pubkey_bytes, msg_bytes, &sig_bytes) && 
           !InputValidator::verify_ed25519(&pubkey_bytes, msg_bytes, &sig_bytes) {
            tracing::warn!("Ownership proof failed for account_burn: id={}", id_hash);
            response["error"] = json!("Ownership proof failed");
            return response;
        }
        
        match self.redis.burn_account(id_hash).await {
            Ok(_) => {
                let mut res = json!({
                    "type": "account_burn_res",
                    "status": "success"
                });
                if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
                res
            },
            Err(e) => {
                tracing::error!("Nuclear burn failed for {}: {}", id_hash, e);
                response["error"] = json!(format!("Burn failed: {}", e));
                response
            }
        }
    }

    pub async fn handle_link_preview(&self, req: &Value) -> Value {
        let mut response = json!({"type": "error", "status": "error"});
        if let Some(rid) = req.get("req_id") {
            response.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone());
        }

        let Some(url) = req.get("url").and_then(|u| u.as_str()) else {
            response["message"] = json!("Missing URL");
            return response;
        };

        if !url.starts_with("http") {
            response["message"] = json!("Invalid protocol");
            return response;
        }

        // 1-to-1 matching C++ URL parsing logic
        let host = if let Some(pos) = url.find("://") {
            let h = &url[pos+3..];
            h.split('/').next().unwrap_or("unknown")
        } else {
            "unknown"
        };

        let mut res = json!({
            "type": "link_preview_res",
            "url": url,
            "title": host,
            "siteName": host,
            "status": "proxied"
        });
        if let Some(rid) = req.get("req_id") { res.as_object_mut().unwrap().insert("req_id".to_string(), rid.clone()); }
        res
    }
}
