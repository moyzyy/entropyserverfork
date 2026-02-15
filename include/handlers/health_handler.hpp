#pragma once

#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include "server_config.hpp"
#include "connection_manager.hpp"
#include "metrics.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;

namespace entropy {

class HealthHandler {
public:
    HealthHandler(const ServerConfig& config, ConnectionManager& conn_manager)
        : config_(config), conn_manager_(conn_manager) {}

    http::response<http::string_body> handle_health(unsigned version);
    http::response<http::string_body> handle_stats(const http::request<http::string_body>& req);
    http::response<http::string_body> handle_metrics(unsigned version);
    
    // Helper used by stats/metrics
    bool verify_admin_request(const http::request<http::string_body>& req);

private:
    const ServerConfig& config_;
    ConnectionManager& conn_manager_;

    template<class Body>
    void add_security_headers(http::response<Body>& res) {
        res.set("X-Content-Type-Options", "nosniff");
        res.set("X-Frame-Options", "DENY");
        res.set("Content-Security-Policy", "default-src 'none'");
    }
    
    template<class Body>
    void add_cors_headers(http::response<Body>& res) {
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type, X-PoW-Seed, X-PoW-Nonce");
    }
};

} 