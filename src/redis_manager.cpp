#include "redis_manager.hpp"
#include "connection_manager.hpp"
#include "server_config.hpp" 
#include "challenge.hpp"
#include "security_logger.hpp"
#include <openssl/crypto.h>
#include <iostream>
#include <chrono>
#include <iterator>
#include <boost/json.hpp>

namespace entropy {

    /**
     * RedisManager Constructor.
     * Establishes connection to the Redis cluster and configures "Quiet Persistence"
     * to minimize forensic metadata footprints on disk.
     */
    RedisManager::RedisManager(const ServerConfig& config, ConnectionManager& conn_manager, const std::string& salt)
    : conn_manager_(conn_manager), server_salt_(salt) {
        try {
            redis_ = std::make_unique<sw::redis::Redis>(config.redis_url);
            connected_ = true;
            
            try {
                // Configure 15-minute snapshot intervals and disable AOF to maximize privacy and performance.
                redis_->command("CONFIG", "SET", "save", "900 1"); 
                redis_->command("CONFIG", "SET", "appendonly", "no"); 
                redis_->command("CONFIG", "SET", "maxmemory-policy", "noeviction");
            } catch (...) {}
            
            running_ = true;
            subscriber_thread_ = std::thread(&RedisManager::subscriber_loop, this);
        } catch (const std::exception& e) {
            SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis connection failed: " + std::string(e.what()));
            connected_ = false;
        }
    }

    /**
     * Executes an atomic Generic Cell Rate Algorithm (GCRA) for rate-limiting.
     * Integrates temporary "jail" state for repeat violators to mitigate DDoS/Brute-force.
     */
    RateLimitResult RedisManager::rate_limit(const std::string& key, int limit, int period_sec, int cost) {
        RateLimitResult result = {true, (long long)0, (long long)limit, 0};
        if (!connected_) return result; 
        
        try {
            static const std::string script = R"(
                local key = KEYS[1]
                local rate = tonumber(ARGV[1])
                local burst = tonumber(ARGV[2])
                local period = tonumber(ARGV[3])
                local now = tonumber(ARGV[4])
                local cost = tonumber(ARGV[5])
                
                local emission_interval = period / burst 
                local jail_key = key .. ":jail"
                local violation_key = key .. ":viol"
                
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
                         redis.call('SETEX', jail_key, 300, "banned")
                         return {-1, 0, 300}
                    end
                    
                    return {0, math.ceil(retry_after), 0}
                end
                
                local new_tat_res = tat_val + increment
                redis.call('SET', key, new_tat_res, 'EX', period * 2)
                
                local remaining_time = burst_offset - (new_tat_res - now)
                local remaining_count = math.floor(remaining_time / emission_interval)
                
                return {1, remaining_count, 0}
            )";

        auto now = std::chrono::system_clock::now();
        double now_sec = std::chrono::duration<double>(now.time_since_epoch()).count();
        
        std::vector<std::string> args = {
            std::to_string((double)limit / period_sec), 
            std::to_string(limit),
            std::to_string(period_sec),
            std::to_string(now_sec),
            std::to_string(cost)
        };

        std::vector<long long> res;
        std::vector<std::string> keys = {key};
        redis_->eval(script, keys.begin(), keys.end(), args.begin(), args.end(), std::back_inserter(res));

        if (res.size() >= 3) {
            int status = (int)res[0];
            long long val1 = res[1];
            long long val2 = res[2];
            
            if (status == 1) {
                result.allowed = true;
                result.current = limit - val1; 
                result.reset_after_sec = 0;
            } else if (status == -1) {
                result.allowed = false;
                result.current = limit;
                result.reset_after_sec = val2; 
            } else {
                result.allowed = false;
                result.current = limit;
                result.reset_after_sec = val1; 
            }
        }
        return result;
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis rate limit error: " + std::string(e.what()));
        return result; 
    }
}

RedisManager::~RedisManager() {
    running_ = false;
    if (subscriber_thread_.joinable()) {
        subscriber_thread_.join();
    }
}

// Publishes a message to a specific relay channel. Used for cross-instance delivery.
void RedisManager::publish_message(const std::string& recipient_hash, const std::string& message_json) {
    if (!connected_) return;
    try {
        std::string blinded = blind(recipient_hash);
        std::string channel = "relay:" + blinded;
        redis_->publish(channel, message_json);
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis publish failed: " + std::string(e.what()));
    }
}

void RedisManager::publish_multicast(const std::vector<std::string>& recipients, const std::string& message_json) {
    if (!connected_) return;
    for (const auto& r : recipients) {
        publish_message(r, message_json);
    }
}

void RedisManager::subscribe_user(const std::string& user_hash) {
    if (!connected_) return;
    std::string blinded = blind(user_hash);
    std::lock_guard<std::mutex> lock(subscriber_mutex_);
    if (subscriber_) {
        subscriber_->subscribe("relay:" + blinded);
    }
}

void RedisManager::unsubscribe_user(const std::string& user_hash) {
    if (!connected_) return;
    std::string blinded = blind(user_hash);
    std::lock_guard<std::mutex> lock(subscriber_mutex_);
    if (subscriber_) {
        subscriber_->unsubscribe("relay:" + blinded);
    }
}

// Subscriber loop responsible for processing messages from the Redis cluster.
void RedisManager::subscriber_loop() {
    if (!connected_) return;

    while (running_) {
        try {
            {
                std::lock_guard<std::mutex> lock(subscriber_mutex_);
                subscriber_ = std::make_unique<sw::redis::Subscriber>(redis_->subscriber());
                
                subscriber_->on_message([this](std::string channel, std::string msg) {
                    if (channel.rfind("relay:", 0) == 0) {
                        std::string blinded_id = channel.substr(6);
                        conn_manager_.process_distributed_message_for_blinded_id(blinded_id, msg);
                    }
                });
            }

            while (running_) {
                try {
                    bool has_subscriber = false;
                    {
                        std::lock_guard<std::mutex> lock(subscriber_mutex_);
                        has_subscriber = (subscriber_ != nullptr);
                    }
                    if (has_subscriber) {
                        subscriber_->consume();
                    } else {
                        break; 
                    }
                } catch (const sw::redis::TimeoutError &e) {
                    continue;
                } catch (const std::exception &e) {
                    throw; 
                }
            }
        } catch (const std::exception& e) {
            if (running_) {
                SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis subscriber error (reconnecting...): " + std::string(e.what()));
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }
    }
}

// Stores a message in a FIFO list for offline recipients (24h TTL).
bool RedisManager::store_offline_message(const std::string& user_hash, const std::string& message_json) {
    if (!connected_) return false;
    try {
        std::string blinded = blind(user_hash);
        std::string key = "msg:" + blinded;
        redis_->rpush(key, message_json);
        redis_->ltrim(key, -100, -1); // Limit of 100 queued messages per user
        redis_->expire(key, 86400);   // Messages expire after 24 hours
        return true;
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis store_message failed: " + std::string(e.what()));
        return false;
    }
}

// Atomically retrieves and deletes all offline messages for a specific recipient.
std::vector<std::string> RedisManager::retrieve_offline_messages(const std::string& user_hash) {
    std::vector<std::string> messages;
    if (!connected_) return messages;
    try {
        std::string blinded = blind(user_hash);
        std::string key = "msg:" + blinded;
        
        static const std::string atomic_pop_script = R"(
            local msgs = redis.call('LRANGE', KEYS[1], 0, -1)
            if #msgs > 0 then
                redis.call('DEL', KEYS[1])
            end
            return msgs
        )";
        
        std::vector<std::string> keys = {key};
        redis_->eval(atomic_pop_script, {key}, {}, 
                    std::back_inserter(messages));
        
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis retrieve_messages failed: " + std::string(e.what()));
    }
    return messages;
}

// Stores a user's cryptographic identity bundle.
bool RedisManager::store_user_bundle(const std::string& user_hash, const std::string& bundle_json) {
    if (!connected_) return false;
    try {
        std::string blinded = blind(user_hash);
        std::string key = "keys:" + blinded;
        redis_->set(key, bundle_json);
        redis_->expire(key, 2592000); // Bundles expire after 30 days of inactivity
        
        mark_id_seen(user_hash);
        
        // Track the identity in a set for decoy/random discovery
        redis_->sadd("active_users", user_hash);
        redis_->expire("active_users", 86400 * 30); 
        
        return true;
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis store_keys failed: " + std::string(e.what()));
        return false;
    }
}

std::string RedisManager::get_user_bundle(const std::string& user_hash) {
    if (!connected_) return "";
    try {
        std::string blinded = blind(user_hash);
        std::string key = "keys:" + blinded;
        auto val = redis_->get(key);
        if (val) return *val;
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis get_keys failed: " + std::string(e.what()));
    }
    return "";
}

// Returns random user hashes for decoy traffic generation.
std::vector<std::string> RedisManager::get_random_user_hashes(int count) {
    std::vector<std::string> hashes;
    if (!connected_) return hashes;
    try {
        redis_->srandmember("active_users", count, std::back_inserter(hashes));
    } catch (...) {}
    return hashes;
}

// Maps a human-readable nickname to a cryptographic public key hash.
bool RedisManager::register_nickname(const std::string& nickname, const std::string& user_hash) {
    if (!connected_ || nickname.empty()) return false;
    try {
        std::string key = "nick:" + nickname;
        
        // Use NX (Not Exists) to ensure nickname uniqueness
        bool success = redis_->set(key, user_hash, std::chrono::seconds(2592000), sw::redis::UpdateType::NOT_EXIST);
        if (!success) {
            // If already owned by the same hash, just update the TTL
            auto val = redis_->get(key);
            if (val && *val == user_hash) {
                redis_->expire(key, 2592000); 
                return true;
            }
            return false;
        }
        redis_->expire(key, 2592000); 
        
        // Create an event key to track registration intensity (for dynamic PoW adjustments)
        std::string event_id = ::entropy::ChallengeGenerator::generate_seed().substr(0, 8);
        redis_->set("reg_event:" + event_id, "1", std::chrono::seconds(300)); 
        
        // Store reverse mapping for clean account deletion
        redis_->set("rn:" + blind(user_hash), nickname, std::chrono::seconds(2592000), sw::redis::UpdateType::NOT_EXIST);

        return true;

    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis register_nickname failed: " + std::string(e.what()));
        return false;
    }
}

// Calculates recent registration frequency to adjust Anti-Spam (PoW) costs.
int RedisManager::get_registration_intensity() {
    if (!connected_) return 0;
    try {
        std::vector<std::string> keys;
        auto cursor = 0LL;
        cursor = redis_->scan(cursor, "reg_event:*", 100, std::back_inserter(keys));
        return (int)keys.size();
    } catch (...) {
        return 0;
    }
}

std::string RedisManager::resolve_nickname(const std::string& nickname) {
    if (!connected_ || nickname.empty()) return "";
    try {
        std::string key = "nick:" + nickname;
        auto val = redis_->get(key);
        if (val) return *val;
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Redis resolve_nickname failed: " + std::string(e.what()));
    }
    return "";
}

long long RedisManager::get_account_age(const std::string& user_hash) {
    if (!connected_) return 0;
    try {
        std::string blinded = blind(user_hash);
        auto val = redis_->get("seen:" + blinded);
        if (val) {
            long long first_seen = std::stoll(*val);
            auto now = std::chrono::system_clock::now();
            long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            return std::max(0LL, now_sec - first_seen);
        }
    } catch (...) {}
    return 0;
}

void RedisManager::mark_id_seen(const std::string& user_hash) {
    if (!connected_) return;
    try {
        std::string blinded = blind(user_hash);
        std::string key = "seen:" + blinded;
        auto now = std::chrono::system_clock::now();
        long long now_sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        redis_->set(key, std::to_string(now_sec), std::chrono::seconds(31536000), sw::redis::UpdateType::NOT_EXIST);
    } catch (...) {}
}

std::string RedisManager::issue_challenge(int ttl_sec) {
    if (!connected_) return "";
    try {
        std::string seed = ::entropy::ChallengeGenerator::generate_seed();
        std::string key = "pow_seed:" + seed;
        redis_->set(key, "1", std::chrono::seconds(ttl_sec));
        return seed;
    } catch (...) {
        return "";
    }
}

bool RedisManager::consume_challenge(const std::string& seed) {
    if (!connected_) return false;
    try {
        std::string key = "pow_seed:" + seed;
        auto deleted = redis_->del(key);
        return deleted > 0;
    } catch (...) {
        return false;
    }
}

std::string RedisManager::create_session_token(const std::string& user_hash, int ttl_sec) {
    if (!connected_) return "";
    try {
        std::string token = ::entropy::ChallengeGenerator::generate_seed();
        std::string blinded = blind(user_hash);
        std::string key = "sess:" + blinded;
        redis_->set(key, token, std::chrono::seconds(ttl_sec));
        return token;
    } catch (...) {
        return "";
    }
}

bool RedisManager::verify_session_token(const std::string& user_hash, const std::string& token) {
    if (!connected_ || token.empty()) return false;
    try {
        std::string blinded = blind(user_hash);
        std::string key = "sess:" + blinded;
        auto val = redis_->get(key);
        
        // Constant-time memory comparison to prevent timing attacks on session tokens
        if (val && val->length() == token.length()) {
            return CRYPTO_memcmp(val->c_str(), token.c_str(), token.length()) == 0;
        }
        return false;
    } catch (...) {
        return false;
    }
}

// Irreversibly purges all data associated with a public key hash from Redis.
bool RedisManager::burn_account(const std::string& user_hash) {
    if (!connected_) return false;
    try {
        std::string blinded = blind(user_hash);
        
        // Remove all primary anonymous data
        redis_->del("keys:" + blinded);
        redis_->del("msg:" + blinded);
        redis_->del("sess:" + blinded);
        redis_->del("seen:" + blinded);

        // Remove linked nicknames
        auto nick_val = redis_->get("rn:" + blinded);
        if (nick_val) {
             std::string nick = *nick_val;
             redis_->del("nick:" + nick);
             redis_->del("rn:" + blinded);
        }
        
        // Remove from discovery set
        redis_->srem("active_users", user_hash);
        
        std::cout << "[!] Burn completed for blinded ID: " << blinded << "\n";
        return true;
    } catch (...) {
        return false;
    }
}

// Blind an identifier using the server's secret salt.
std::string RedisManager::blind(const std::string& input) {
    std::string data = input + server_salt_;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool RedisManager::delete_key(const std::string& key) {
    if (!connected_) return false;
    try {
        return redis_->del(key) > 0;
    } catch (...) {
        return false;
    }
}

}
