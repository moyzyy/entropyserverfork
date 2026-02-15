#include "handlers/health_handler.hpp"
#include <iomanip>

namespace entropy {

http::response<http::string_body> HealthHandler::handle_health(unsigned version) {
    json::object response;
    response["status"] = "healthy";
    response["storage"] = "none";
    response["message"] = "Ephemeral relay only - no data stored";
    response["tls"] = config_.enable_tls;
    
    http::response<http::string_body> res{http::status::ok, version};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

http::response<http::string_body> HealthHandler::handle_stats(const http::request<http::string_body>& req) {
    if (!verify_admin_request(req)) {
        http::response<http::string_body> res{http::status::unauthorized, req.version()};
        res.body() = "Unauthorized";
        res.prepare_payload();
        return res;
    }

    json::object response;
    response["active_connections"] = static_cast<int64_t>(conn_manager_.connection_count());
    response["uptime_info"] = "Server stores ZERO messages";
    
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

http::response<http::string_body> HealthHandler::handle_metrics(unsigned version) {
    
    std::string body = MetricsRegistry::instance().collect_prometheus();
    
    http::response<http::string_body> res{http::status::ok, version};
    res.set(http::field::content_type, "text/plain; version=0.0.4");
    res.body() = body;
    res.prepare_payload();
    
    add_security_headers(res);
    
    return res;
}

bool HealthHandler::verify_admin_request(const http::request<http::string_body>& req) {
    
    if (config_.admin_token.empty()) {
        return false;
    }

    auto auth_it = req.find("X-Admin-Token");
    if (auth_it == req.end()) {
        return false;
    }

    std::string provided_token(auth_it->value());
    return provided_token == config_.admin_token;
}

} 
