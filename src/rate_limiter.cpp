#include "rate_limiter.hpp"
#include <algorithm>
#include <mutex>

namespace entropy {

RateLimiter::RateLimiter(RedisManager& redis)
    : redis_(redis)
{}

RateLimitResult RateLimiter::check(const std::string& key, int limit, int window_sec, int cost) {
    return redis_.rate_limit(key, limit, window_sec, cost);
}

std::string RateLimiter::issue_challenge(int ttl_sec) {
    return redis_.issue_challenge(ttl_sec);
}

bool RateLimiter::consume_challenge(const std::string& seed) {
    return redis_.consume_challenge(seed);
}

}
