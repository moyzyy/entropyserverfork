#pragma once

#include <string>
#include <vector>
#include <memory>
#include <boost/json.hpp>
#include "connection_manager.hpp"
#include "redis_manager.hpp"
#include "rate_limiter.hpp"

namespace json = boost::json;

#include "server_config.hpp"
namespace entropy {

class WebSocketSession;

class MessageRelay {
public:
    static constexpr size_t MAX_MESSAGE_SIZE = 128 * 1024; // 128KB Limit
    explicit MessageRelay(ConnectionManager& conn_manager, RedisManager& redis, RateLimiter& rate_limiter, const ServerConfig& config);
    ~MessageRelay() = default;
    
    void relay_message(std::string_view message_json, 
                       std::shared_ptr<WebSocketSession> sender);

    void relay_message(const json::object& obj,
                       std::shared_ptr<WebSocketSession> sender);
    
    void relay_binary(std::string_view recipient_hash,
                      const void* data, 
                      size_t length,
                      std::shared_ptr<WebSocketSession> sender);

    void relay_volatile(std::string_view recipient_hash,
                        const void* data,
                        size_t length,
                        std::shared_ptr<WebSocketSession> sender);

    void handle_dummy(std::shared_ptr<WebSocketSession> sender);

    void deliver_pending(const std::string& recipient_hash,
                         std::shared_ptr<WebSocketSession> recipient);

    void confirm_delivery(const std::vector<int64_t>& /*ids*/) {}
    
    bool validate_message_size(size_t size) const {
        return size <= config_.max_message_size;
    }

private:
    ConnectionManager& conn_manager_;
    RedisManager& redis_;
    RateLimiter& rate_limiter_;
    const ServerConfig& config_;
    
    struct RoutingInfo {
        std::string type;
        std::string to;
        bool valid;
    };
    
    RoutingInfo extract_routing(std::string_view message_json);
};

}
