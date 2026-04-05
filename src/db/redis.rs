use redis::AsyncCommands;
use std::sync::Arc;
use crate::config::ServerConfig;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{thread_rng, RngCore};
use hex;

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub current: i64,
    pub limit: i64,
    pub reset_after_sec: i64,
    pub is_jailed: bool,
}

pub struct RedisManager {
    connection: redis::aio::MultiplexedConnection,
    config: Arc<ServerConfig>,
}

impl RedisManager {
    pub async fn new(config: Arc<ServerConfig>) -> Result<Arc<Self>> {
        let client = redis::Client::open(config.redis_url.clone())?;
        let connection = client.get_multiplexed_async_connection().await?;
        
        let manager = Arc::new(Self {
            connection,
            config: config.clone(),
        });

        Ok(manager)
    }


    pub async fn check_rate_limit(&self, key: &str, limit: i64, window_sec: i64, cost: i64) -> Result<RateLimitResult> {
        let mut conn = self.connection.clone();
        
        let script = redis::Script::new(r"
            local key = KEYS[1]
            local rate = tonumber(ARGV[1])
            local burst = tonumber(ARGV[2])
            local period = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])
            local cost = tonumber(ARGV[5])
            local jail_duration = tonumber(ARGV[6])
            local violation_threshold = tonumber(ARGV[7])
            
            local emission_interval = period / burst
            local jail_key = key .. ':jail'
            local violation_key = key .. ':viol'
            
            -- 🛡️ UNIVERSAL JAIL CHECK: If media spammed, the relay jail key also bans you
            if key:sub(1,11) == 'limit:media' then
               local global_jail = 'limit:relay' .. key:sub(12) .. ':jail'
               local global_ttl = redis.call('TTL', global_jail)
               if global_ttl > 0 then return {-1, 0, global_ttl} end
            end

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
                
                if viol > violation_threshold then
                    -- 🔐 BAN THE IDENTITY: Set both the specific and global jail keys
                    redis.call('SETEX', jail_key, jail_duration, 'banned')
                    if key:sub(1,11) == 'limit:media' then
                        local global_jail = 'limit:relay' .. key:sub(12) .. ':jail'
                        redis.call('SETEX', global_jail, jail_duration, 'banned')
                    end
                    return {-1, 0, jail_duration}
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
        let jail_duration = self.config.jail_duration_sec;
         
        if self.config.jail_duration_sec > 0 {
             // Debug print only if log is visible
             // println!("[Redis] Checking Rate Limit: {} (threshold={})", key, self.config.violation_jail_threshold);
        }

        let result: Vec<i64> = script
            .key(key)
            .arg((limit as f64) / (window_sec as f64))
            .arg(limit)
            .arg(window_sec)
            .arg(now)
            .arg(cost)
            .arg(jail_duration)
            .arg(self.config.violation_jail_threshold)
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
                    is_jailed: false,
                })
            } else if status == -1 {
                Ok(RateLimitResult {
                    allowed: false,
                    current: limit,
                    limit,
                    reset_after_sec: val2,
                    is_jailed: true,
                })
            } else {
                let current = (limit as i64).saturating_sub(val1); 
                
                if key.starts_with("limit:relay:uid:") {
                    let viol_key = format!("{}:viol", key);
                    let _: () = redis::cmd("INCR").arg(&viol_key).query_async(&mut conn).await.unwrap_or_default();
                    let _: () = redis::cmd("EXPIRE").arg(&viol_key).arg(self.config.violation_reset_sec).query_async(&mut conn).await.unwrap_or_default();
                }

                Ok(RateLimitResult {
                    allowed: false,
                    current,
                    limit,
                    reset_after_sec: val2,
                    is_jailed: false,
                })
            }
        } else {
            Ok(RateLimitResult {
                allowed: true,
                current: 0,
                limit,
                reset_after_sec: 0,
                is_jailed: false,
            })
        }
    }

    pub async fn penalize_uid(&self, user_hash: &str, duration_sec: u64) -> Result<()> {
        let mut conn = self.connection.clone();
        let jail_key = format!("limit:relay:uid:{}:jail", user_hash);
        let _: () = conn.set_ex(&jail_key, "banned", duration_sec).await?;
        Ok(())
    }


    pub async fn store_offline_message(&self, recipient_hash: &str, sender_hash: &str, message: &[u8], limit: usize, sender_limit: usize) -> Result<bool> {
        let mut conn = self.connection.clone();
        let key = format!("msg:{}", recipient_hash);
        let sender_count_key = format!("offcnt:{}:{}", recipient_hash, sender_hash);
        let sender_set_key = format!("offsenders:{}", recipient_hash);
        
        let script = redis::Script::new(r"
            local msg_key = KEYS[1]
            local sc_key = KEYS[2]
            local ss_key = KEYS[3]
            local msg_data = ARGV[1]
            local limit = tonumber(ARGV[2])
            local sender_limit = tonumber(ARGV[3])
            
            -- 🛡️ ATOMIC PROTECTION: One check to rule them all
            local global_count = redis.call('LLEN', msg_key)
            if global_count >= limit then
                return {err = 'ERR_MAILBOX_FULL'}
            end
            
            local current_sender_count = tonumber(redis.call('GET', sc_key) or 0)
            if current_sender_count >= sender_limit then
                return {err = 'ERR_SENDER_QUOTA'}
            end
            
            -- Success Path
            redis.call('RPUSH', msg_key, msg_data)
            redis.call('EXPIRE', msg_key, 86400)
            
            redis.call('INCR', sc_key)
            redis.call('EXPIRE', sc_key, 86400)
            redis.call('SADD', ss_key, sc_key)
            redis.call('EXPIRE', ss_key, 86400)
            
            return 1
        ");

        let _: () = script.key(key).key(sender_count_key).key(sender_set_key)
            .arg(message).arg(limit).arg(sender_limit)
            .invoke_async(&mut conn).await?;
            
        Ok(true)
    }

    pub async fn get_offline_count(&self, recipient_hash: &str) -> Result<u64> {
        let mut conn = self.connection.clone();
        let key = format!("msg:{}", recipient_hash);
        let len: u64 = conn.llen(&key).await?;
        Ok(len)
    }

    pub async fn get_offline_messages(&self, recipient_hash: &str) -> Result<Vec<Vec<u8>>> {
        let mut conn = self.connection.clone();
        let key = format!("msg:{}", recipient_hash);
        let sender_set_key = format!("offsenders:{}", recipient_hash);
        
        let script = redis::Script::new(r"
            local msgs = redis.call('LRANGE', KEYS[1], 0, -1)
            if #msgs > 0 then
                redis.call('DEL', KEYS[1])
                local senders = redis.call('SMEMBERS', KEYS[2])
                for _, sc_key in ipairs(senders) do
                    redis.call('DEL', sc_key)
                end
                redis.call('DEL', KEYS[2])
            end
            return msgs
        ");
        let messages: Vec<Vec<u8>> = script.key(key).key(sender_set_key).invoke_async(&mut conn).await?;
        Ok(messages)
    }


    pub async fn store_user_bundle(&self, user_hash: &str, bundle_json: &str) -> Result<()> {
        let mut conn = self.connection.clone();
        let key = format!("keys:{}", user_hash);
        let _: () = conn.set(&key, bundle_json).await?;
        let _: () = conn.expire(&key, 2592000).await?;
        let _: () = conn.sadd("active_users", user_hash).await?;
        let _: () = conn.expire("active_users", 2592000).await?;
        self.mark_id_seen(user_hash).await?;
        Ok(())
    }

    pub async fn get_user_bundle(&self, user_hash: &str) -> Result<Option<String>> {
        let mut conn = self.connection.clone();
        let key = format!("keys:{}", user_hash);
        let val: Option<String> = conn.get(&key).await?;
        Ok(val)
    }

    pub async fn store_otk_pool(&self, user_hash: &str, keys: Vec<String>) -> Result<()> {
        if keys.is_empty() { return Ok(()); }
        
        let mut conn = self.connection.clone();
        let key = format!("otk:{}", user_hash);
        
        let script = redis::Script::new(r#"
            local key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local current_count = redis.call('SCARD', key)
            
            local slots_available = limit - current_count
            if slots_available <= 0 then
                return 0
            end
            
            local added = 0
            for i = 2, #ARGV do
                if added >= slots_available then
                    break
                end
                redis.call('SADD', key, ARGV[i])
                added = added + 1
            end
            
            redis.call('EXPIRE', key, 2592000)
            return added
        "#);

        let mut inv = script.key(&key);
        inv.arg(100); // The limit
        for k in keys { inv.arg(k); }
        
        let _: u64 = inv.invoke_async(&mut conn).await?;
        Ok(())
    }

    pub async fn pop_otk(&self, user_hash: &str) -> Result<Option<String>> {
        let mut conn = self.connection.clone();
        let key = format!("otk:{}", user_hash);
        let val: Option<String> = conn.spop(&key).await?;
        Ok(val)
    }

    pub async fn get_otk_count(&self, user_hash: &str) -> Result<u32> {
        let mut conn = self.connection.clone();
        let key = format!("otk:{}", user_hash);
        let count: u32 = conn.scard(&key).await?;
        Ok(count)
    }

    pub async fn register_nickname(&self, nickname: &str, user_hash: &str) -> Result<bool> {
        let mut conn = self.connection.clone();
        let owner_key = format!("rn:{}", user_hash);
        let existing_nick: Option<String> = conn.get(&owner_key).await?;
        if let Some(ref old_name) = existing_nick {
            if old_name == nickname {
                let _: () = conn.expire(&format!("nick:{}", nickname), 2592000).await?;
                let _: () = conn.expire(&owner_key, 2592000).await?;
                return Ok(true);
            }
        }
        let new_key = format!("nick:{}", nickname);
        let success: bool = conn.set_nx(&new_key, user_hash).await?;
        if !success { return Ok(false); }
        if let Some(old_name) = existing_nick {
            let _: () = conn.del(&format!("nick:{}", old_name)).await?;
        }
        let _: () = conn.expire(&new_key, 2592000).await?;
        let _: () = conn.set(&owner_key, nickname).await?;
        let _: () = conn.expire(&owner_key, 2592000).await?;
        Ok(true)
    }

    pub async fn resolve_nickname(&self, nickname: &str) -> Result<Option<String>> {
        let mut conn = self.connection.clone();
        let key = format!("nick:{}", nickname);
        let val: Option<String> = conn.get(key).await?;
        Ok(val)
    }

    pub async fn get_nickname(&self, user_hash: &str) -> Result<Option<String>> {
        let mut conn = self.connection.clone();
        let owner_key = format!("rn:{}", user_hash);
        let nick: Option<String> = conn.get(&owner_key).await?;
        Ok(nick)
    }

    pub async fn mark_id_seen(&self, user_hash: &str) -> Result<()> {
        let mut conn = self.connection.clone();
        let key = format!("seen:{}", user_hash);
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let _: () = conn.set(&key, now).await?;
        let _: () = conn.expire(&key, 2592000).await?;
        Ok(())
    }

    pub async fn get_account_age(&self, user_hash: &str) -> Result<i64> {
        let mut conn = self.connection.clone();
        let key = format!("seen:{}", user_hash);
        let val: Option<String> = conn.get(key).await?;
        if let Some(first_seen_str) = val {
            let first_seen: i64 = first_seen_str.parse().unwrap_or(0);
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
            Ok(now - first_seen)
        } else { Ok(0) }
    }

    pub async fn get_identity_violations(&self, user_hash: &str) -> Result<u32> {
        let mut conn = self.connection.clone();
        let key = format!("limit:relay:uid:{}:viol", user_hash);
        let res: Option<u32> = conn.get(&key).await?;
        Ok(res.unwrap_or(0))
    }

    pub async fn get_registration_intensity(&self) -> Result<i32> {
        let mut conn = self.connection.clone();
        let mut cursor = 0i64;
        let mut keys = Vec::new();
        loop {
            let (next_cursor, mut part_keys): (i64, Vec<String>) = redis::cmd("SCAN").arg(cursor).arg("MATCH").arg("reg_event:*").arg("COUNT").arg(100).query_async(&mut conn).await?;
            keys.append(&mut part_keys);
            cursor = next_cursor;
            if cursor == 0 || keys.len() >= 500 { break; }
        }
        Ok(keys.len() as i32)
    }

    pub async fn nuclear_burn(&self, user_hash: &str) -> Result<bool> {
        let mut conn = self.connection.clone();
        let script = r"
            local id = ARGV[1]
            local nick = redis.call('GET', 'rn:' .. id)
            if nick then redis.call('DEL', 'nick:' .. nick) end
            redis.call('DEL', 'rn:' .. id)
            redis.call('DEL', 'keys:' .. id)
            redis.call('DEL', 'msg:' .. id)
            redis.call('DEL', 'sess:' .. id)
            redis.call('DEL', 'seen:' .. id)
            redis.call('DEL', 'otk:' .. id)
            redis.call('DEL', 'limit:relay:uid:' .. id)
            redis.call('DEL', 'limit:relay:uid:' .. id .. ':jail')
            redis.call('DEL', 'limit:relay:uid:' .. id .. ':viol')
            redis.call('DEL', 'limit:media:uid:' .. id)
            redis.call('DEL', 'limit:media:uid:' .. id .. ':jail')
            redis.call('DEL', 'limit:media:uid:' .. id .. ':viol')
            redis.call('DEL', 'limit:keys_up:uid:' .. id)
            redis.call('DEL', 'limit:nick:reg:' .. id)
            redis.call('SREM', 'active_users', id)
            return 1
        ";
        let _: i32 = redis::Script::new(script).arg(user_hash).invoke_async(&mut conn).await?;
        Ok(true)
    }

    pub async fn create_session_token(&self, user_hash: &str, ttl_sec: u64) -> Result<String> {
        let mut conn = self.connection.clone();
        let mut bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        let key = format!("sess:{}", user_hash);
        let _: () = conn.set_ex(&key, &token, ttl_sec).await?;
        Ok(token)
    }

    pub async fn verify_session_token(&self, user_hash: &str, token: &str) -> Result<bool> {
        if token.is_empty() { return Ok(false); }
        let mut conn = self.connection.clone();
        let key = format!("sess:{}", user_hash);
        let val: Option<String> = conn.get(&key).await?;
        if let Some(stored_token) = val {
            return Ok(Self::constant_time_eq(stored_token.as_bytes(), token.as_bytes()));
        }
        Ok(false)
    }

    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() { return false; }
        let mut res = 0;
        for (x, y) in a.iter().zip(b.iter()) { res |= x ^ y; }
        res == 0
    }

    pub async fn issue_challenge_with_seed(&self, seed: &str, ttl_sec: u64) -> Result<()> {
        let mut conn = self.connection.clone();
        let key = format!("pow_seed:{}", seed);
        let _: () = conn.set_ex(&key, "1", ttl_sec).await?;
        Ok(())
    }

    pub async fn consume_challenge(&self, seed: &str) -> Result<bool> {
        let mut conn = self.connection.clone();
        let key = format!("pow_seed:{}", seed);
        let deleted: i64 = conn.del(&key).await?;
        Ok(deleted > 0)
    }
}
