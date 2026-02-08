#pragma once

#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <string>
#include "server_config.hpp"
#include "connection_manager.hpp"
#include "metrics.hpp"
#include "key_storage.hpp"
#include "redis_manager.hpp"
#include "rate_limiter.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
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

    http::response<http::string_body> handle_keys_upload(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_keys_fetch(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_keys_random(const http::request<http::string_body>& req, const std::string& remote_addr);
    
    http::response<http::string_body> handle_nickname_register(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_nickname_lookup(const http::request<http::string_body>& req, const std::string& remote_addr);
    http::response<http::string_body> handle_account_burn(const http::request<http::string_body>& req, const std::string& remote_addr);
    
    http::response<http::string_body> handle_pow_challenge(const http::request<http::string_body>& req, const std::string& remote_addr);

private:
    const ServerConfig& config_;
    KeyStorage& key_storage_;
    RedisManager& redis_;
    RateLimiter& rate_limiter_;
    
    std::string blind_ip(const std::string& ip, const std::string& salt);
    bool validate_pow(const http::request<http::string_body>& req, RateLimiter& rate_limiter, const std::string& remote_addr, int target_difficulty = -1, const std::string& context = "");

    template<class Body>
    void add_security_headers(http::response<Body>& res) {
        res.set(beast::http::field::server, "Entropy/2.0");
        res.set("X-Content-Type-Options", "nosniff");
        res.set("X-Frame-Options", "DENY");
        res.set("X-XSS-Protection", "1; mode=block");
        res.set("Referrer-Policy", "strict-origin-when-cross-origin");
        res.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    }
    
    template<class Body>
    void add_cors_headers(http::response<Body>& res, const http::request<http::string_body>* req = nullptr) {
        std::string origin;
        if (req) {
            auto origin_it = req->find(http::field::origin);
            if (origin_it != req->end()) {
                origin = std::string(origin_it->value());
            }
        }

        // Basic allowance for local development and Tauri apps
        if (!origin.empty()) {
            if (origin.find("localhost") != std::string::npos || 
                origin.find("tauri://") != std::string::npos || 
                origin.find("127.0.0.1") != std::string::npos) {
                res.set(http::field::access_control_allow_origin, origin);
                res.set(http::field::access_control_allow_credentials, "true");
            } else {
                res.set(http::field::access_control_allow_origin, "*");
            }
        } else {
            res.set(http::field::access_control_allow_origin, "*");
        }
        
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type, Authorization, X-PoW-Seed, X-PoW-Nonce, x-pow-seed, x-pow-nonce, X-Admin-Token");
        res.set(http::field::access_control_max_age, "86400");
        res.set(http::field::vary, "Origin");
    }
    
    http::response<http::string_body> handle_rate_limited(const RateLimitResult& res_info, unsigned version);
};

} // namespace entropy
