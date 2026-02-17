use redis::{AsyncCommands, Client};
use futures_util::StreamExt;
use std::sync::Arc;
use crate::config::ServerConfig;
use crate::server::registry::Registry;
use anyhow::Result;
use tracing::error;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{thread_rng, RngCore};
use hex;

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub current: i64,
    pub limit: i64,
    pub reset_after_sec: i64,
}

pub struct RedisManager {
    client: Client,
    registry: Arc<Registry>,
}

impl RedisManager {
    pub async fn new(config: &ServerConfig, registry: Arc<Registry>) -> Result<Arc<Self>> {
        let client = Client::open(config.redis_url.clone())?;
        let manager = Arc::new(Self {
            client,
            registry,
        });

        let manager_clone = manager.clone();
        tokio::spawn(async move {
            if let Err(e) = manager_clone.run_subscriber_loop().await {
                error!("Redis subscriber loop error: {}", e);
            }
        });

        Ok(manager)
    }

    async fn run_subscriber_loop(&self) -> Result<()> {
        let client = self.client.clone();
        let registry_clone = self.registry.clone();
        
        loop {
            let mut pubsub = client.get_async_pubsub().await?;
            pubsub.psubscribe("relay:*").await?;
            
            let mut stream = pubsub.on_message();
            
            while let Some(msg) = stream.next().await {
                let channel: String = msg.get_channel_name().to_string();
                
                if channel.starts_with("relay:") {
                    let blinded_id = &channel[6..];
                    let payload: String = msg.get_payload().unwrap_or_default();
                    if let Some(sender) = registry_clone.get_connection_by_blinded_id(blinded_id) {
                        let _ = sender.send(crate::relay::QueuedMessage {
                            msg: axum::extract::ws::Message::Text(payload.into()),
                            is_media: false,
                        });
                    }
                }
            }
        }
    }

    pub async fn check_rate_limit(&self, key: &str, limit: i64, window_sec: i64, cost: i64) -> Result<RateLimitResult> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        // Match C++ GCRA (Generic Cell Rate Algorithm) with jail/violation tracking
        let script = redis::Script::new(r"
            local key = KEYS[1]
            local rate = tonumber(ARGV[1])
            local burst = tonumber(ARGV[2])
            local period = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])
            local cost = tonumber(ARGV[5])
            
            local emission_interval = period / burst
            local jail_key = key .. ':jail'
            local violation_key = key .. ':viol'
            
            local jail_ttl = redis.call('TTL', jail_key)
            if jail_ttl > 0 then return {-1, 0, jail_ttl} end
            
            local tat = redis.call('GET', key)
            if not tat then tat = now else tat = tonumber(tat) end
            
            local tat_val = tat
            local increment = emission_interval * cost
            local burst_offset = period
            
            if tat_val < now then tat_val = now end
            
            if tat_val + increment - now > burst_offset then
                local retry_after = tat_val + increment - now - burst_offset
                local viol = redis.call('INCR', violation_key)
                if viol == 1 then redis.call('EXPIRE', violation_key, period * 2) end
                
                if viol > 5 then
                    redis.call('SETEX', jail_key, 300, 'banned')
                    return {-1, 0, 300}
                end
                
                return {0, math.ceil(retry_after), 0}
            end
            
            local new_tat_res = tat_val + increment
            redis.call('SET', key, new_tat_res, 'EX', period * 2)
            
            local remaining_time = burst_offset - (new_tat_res - now)
            local remaining_count = math.floor(remaining_time / emission_interval)
            
            return {1, remaining_count, 0}
        ");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64();

        let result: Vec<i64> = script
            .key(key)
            .arg((limit as f64) / (window_sec as f64))  // rate
            .arg(limit)                                  // burst
            .arg(window_sec)                             // period
            .arg(now)                                    // now
            .arg(cost)                                   // cost
            .invoke_async(&mut conn)
            .await?;

        if result.len() >= 3 {
            let status = result[0];
            let val1 = result[1];
            let val2 = result[2];

            if status == 1 {
                Ok(RateLimitResult {
                    allowed: true,
                    current: limit - val1,
                    limit,
                    reset_after_sec: 0,
                })
            } else if status == -1 {
                Ok(RateLimitResult {
                    allowed: false,
                    current: limit,
                    limit,
                    reset_after_sec: val2,
                })
            } else {
                Ok(RateLimitResult {
                    allowed: false,
                    current: limit,
                    limit,
                    reset_after_sec: val1,
                })
            }
        } else {
            Ok(RateLimitResult {
                allowed: true,
                current: 0,
                limit,
                reset_after_sec: 0,
            })
        }
    }

    pub async fn publish_message(&self, recipient_hash: &str, message: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(recipient_hash);
        let channel = format!("relay:{}", blinded);
        let _: () = conn.publish(channel, message).await?;
        Ok(())
    }

    pub async fn publish_multicast(&self, recipients: &Vec<String>, message: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        for recipient in recipients {
            let blinded = self.registry.blind_id(recipient);
            let channel = format!("relay:{}", blinded);
            let _: () = conn.publish(channel, message).await?;
        }
        Ok(())
    }

    pub async fn store_offline_message(&self, recipient_hash: &str, message: &str) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(recipient_hash);
        let key = format!("msg:{}", blinded);
        
        // Match C++: RPUSH, LTRIM -100 -1, EXPIRE 86400
        let _: () = conn.rpush(&key, message).await?;
        let _: () = conn.ltrim(&key, -100, -1).await?;
        let _: () = conn.expire(&key, 86400).await?;
        
        Ok(true)
    }

    pub async fn retrieve_offline_messages(&self, recipient_hash: &str) -> Result<Vec<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(recipient_hash);
        let key = format!("msg:{}", blinded);
        
        // Match C++ atomic pop script
        let script = redis::Script::new(r"
            local msgs = redis.call('LRANGE', KEYS[1], 0, -1)
            if #msgs > 0 then
                redis.call('DEL', KEYS[1])
            end
            return msgs
        ");
        
        let messages: Vec<String> = script.key(key).invoke_async(&mut conn).await?;
        Ok(messages)
    }

    pub async fn subscribe_user(&self, _user_hash: &str) -> Result<()> {
        Ok(())
    }

    pub async fn unsubscribe_user(&self, _user_hash: &str) -> Result<()> {
        Ok(())
    }

    pub async fn store_user_bundle(&self, user_hash: &str, bundle_json: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(user_hash);
        let key = format!("keys:{}", blinded);
        
        // Match C++: SET, EXPIRE 30 days
        let _: () = conn.set(&key, bundle_json).await?;
        let _: () = conn.expire(&key, 2592000).await?;
        
        // Track in active_users set
        let _: () = conn.sadd("active_users", user_hash).await?;
        let _: () = conn.expire("active_users", 2592000).await?;
        
        self.mark_id_seen(user_hash).await?;
        Ok(())
    }

    pub async fn get_user_bundle(&self, user_hash: &str) -> Result<Option<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(user_hash);
        let key = format!("keys:{}", blinded);
        let val: Option<String> = conn.get(&key).await?;
        Ok(val)
    }

    pub async fn get_random_user_hashes(&self, count: usize) -> Result<Vec<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let hashes: Vec<String> = redis::cmd("SRANDMEMBER")
            .arg("active_users")
            .arg(count as isize)
            .query_async(&mut conn)
            .await?;
        Ok(hashes)
    }

    pub async fn register_nickname(&self, nickname: &str, user_hash: &str) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("nick:{}", nickname);
        
        // Match C++: SET NX, then check if same owner if failed
        let success: bool = conn.set_nx(&key, user_hash).await?;
        if !success {
            let val: Option<String> = conn.get(&key).await?;
            if let Some(owner) = val {
                if owner == user_hash {
                    let _: () = conn.expire(&key, 2592000).await?;
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        
        let _: () = conn.expire(&key, 2592000).await?;
        
        // Registration event for intensity tracking
        let mut bytes = [0u8; 8];
        thread_rng().fill_bytes(&mut bytes);
        let event_id = hex::encode(bytes);
        let _: () = conn.set_ex(format!("reg_event:{}", event_id), "1", 300).await?;
        
        // Reverse mapping for deletion
        let blinded = self.registry.blind_id(user_hash);
        let _: () = conn.set_nx(format!("rn:{}", blinded), nickname).await?;
        let _: () = conn.expire(format!("rn:{}", blinded), 2592000).await?;
        
        Ok(true)
    }

    pub async fn resolve_nickname(&self, nickname: &str) -> Result<Option<String>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("nick:{}", nickname);
        let val: Option<String> = conn.get(key).await?;
        Ok(val)
    }

    pub async fn mark_id_seen(&self, user_hash: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(user_hash);
        let key = format!("seen:{}", blinded);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let _: () = conn.set(key, now).await?;
        Ok(())
    }

    pub async fn get_account_age(&self, user_hash: &str) -> Result<i64> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(user_hash);
        let key = format!("seen:{}", blinded);
        let val: Option<String> = conn.get(key).await?;
        
        if let Some(first_seen_str) = val {
            let first_seen: i64 = first_seen_str.parse().unwrap_or(0);
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            Ok(now - first_seen)
        } else {
            Ok(0)
        }
    }

    pub async fn get_registration_intensity(&self) -> Result<i32> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        // Match C++: SCAN for reg_event:*
        let mut cursor = 0i64;
        let mut keys = Vec::new();
        loop {
            let (next_cursor, mut part_keys): (i64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("reg_event:*")
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn).await?;
            keys.append(&mut part_keys);
            cursor = next_cursor;
            if cursor == 0 { break; }
            if keys.len() >= 100 { break; } // Parity check
        }
        Ok(keys.len() as i32)
    }

    pub async fn burn_account(&self, user_hash: &str) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(user_hash);
        
        // Match SPECS Section 5: Atomic Lua Script for "Nuclear Option"
        let script = r#"
            local blinded = ARGV[1]
            local unblinded = ARGV[2]
            
            -- Remove primary data
            redis.call('DEL', 'keys:' .. blinded)
            redis.call('DEL', 'msg:' .. blinded)
            redis.call('DEL', 'sess:' .. blinded)
            redis.call('DEL', 'seen:' .. blinded)
            
            -- Remove nicknames
            local nick = redis.call('GET', 'rn:' .. blinded)
            if nick then
                redis.call('DEL', 'nick:' .. nick)
                redis.call('DEL', 'rn:' .. blinded)
            end
            
            -- Remove from global discovery
            redis.call('SREM', 'active_users', unblinded)
            
            return 1
        "#;
        
        let _: i32 = redis::Script::new(script)
            .arg(&blinded)
            .arg(user_hash)
            .invoke_async(&mut conn).await?;
            
        tracing::info!("Nuclear burn completed for id={} blinded={}", user_hash, blinded);
        Ok(true)
    }

    pub async fn create_session_token(&self, user_hash: &str, ttl_sec: u64) -> Result<String> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let mut bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        
        let blinded = self.registry.blind_id(user_hash);
        let key = format!("sess:{}", blinded);
        let _: () = conn.set_ex(&key, &token, ttl_sec).await?;
        Ok(token)
    }

    pub async fn verify_session_token(&self, user_hash: &str, token: &str) -> Result<bool> {
        if token.is_empty() { return Ok(false); }
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let blinded = self.registry.blind_id(user_hash);
        let key = format!("sess:{}", blinded);
        let val: Option<String> = conn.get(&key).await?;
        
        if let Some(stored) = val {
            // Match subtle comparison if possible or use constant_time_eq
            Ok(Self::constant_time_eq(stored.as_bytes(), token.as_bytes()))
        } else {
            Ok(false)
        }
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() { return false; }
        let mut res = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            res |= x ^ y;
        }
        res == 0
    }

    pub async fn issue_challenge_with_seed(&self, seed: &str, ttl_sec: u64) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("pow_seed:{}", seed);
        let _: () = conn.set_ex(&key, "1", ttl_sec).await?;
        Ok(())
    }

    pub async fn consume_challenge(&self, seed: &str) -> Result<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("pow_seed:{}", seed);
        let deleted: i64 = conn.del(&key).await?;
        Ok(deleted > 0)
    }
}
