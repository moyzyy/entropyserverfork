#pragma once

#include <boost/json.hpp>
#include <string>
#include "server_config.hpp"
#include "connection_manager.hpp"
#include "metrics.hpp"
#include "key_storage.hpp"
#include "redis_manager.hpp"
#include "rate_limiter.hpp"

namespace json = boost::json;

namespace entropy {

class IdentityHandler {
public:
    IdentityHandler(const ServerConfig& config, 
                    KeyStorage& key_storage, 
                    RedisManager& redis,
                    RateLimiter& rate_limiter)
        : config_(config)
        , key_storage_(key_storage)
        , redis_(redis)
        , rate_limiter_(rate_limiter) {}

    json::object handle_keys_upload_ws(const json::object& req, const std::string& remote_addr);
    json::object handle_keys_fetch_ws(const json::object& req, const std::string& remote_addr);
    json::object handle_nickname_register_ws(const json::object& req, const std::string& remote_addr);
    
    json::object handle_pow_challenge_ws(const json::object& req, const std::string& remote_addr);
    json::object handle_keys_random_ws(const json::object& req, const std::string& remote_addr);
    json::object handle_nickname_lookup_ws(const json::object& req, const std::string& remote_addr);
    json::object handle_account_burn_ws(const json::object& req, const std::string& remote_addr);
    json::object handle_link_preview_ws(const json::object& req, const std::string& remote_addr);

private:
    const ServerConfig& config_;
    KeyStorage& key_storage_;
    RedisManager& redis_;
    RateLimiter& rate_limiter_;
    

    bool validate_pow_msg(const json::object& obj, const std::string& remote_addr, int target_difficulty = -1, const std::string& context = "");

};

}