#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <shared_mutex>

#include "redis_manager.hpp"

namespace entropy {

class RateLimiter {
public:
    explicit RateLimiter(RedisManager& redis);
    ~RateLimiter() = default;

    /**
     * Evaluates rate-limit for a key via Redis.
     */
    RateLimitResult check(const std::string& key, int limit, int window_sec, int cost = 1);
    
    std::string issue_challenge(int ttl_sec);
    
    bool consume_challenge(const std::string& seed);

private:
    RedisManager& redis_;
};

} 
