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

 
// Routes messages between local sessions and remote nodes.
class MessageRelay {
public:
    static constexpr size_t MAX_MESSAGE_SIZE = 5 * 1024 * 1024; // 5MB Limit per relay
    
    explicit MessageRelay(ConnectionManager& conn_manager, RedisManager& redis, RateLimiter& rate_limiter, const ServerConfig& config);
    ~MessageRelay() = default;
    

    

    
    // --- Message Distribution ---
    /**
     * Relays a JSON message to its destination(s).
     * If recipient is local, it's delivered directly. Otherwise, it's published to Redis.
     */
    void relay_message(const std::string& message_json, 
                       std::shared_ptr<WebSocketSession> sender);
    
    void relay_binary(const std::string& recipient_hash,
                      const void* data, 
                      size_t length,
                      std::shared_ptr<WebSocketSession> sender);

    void relay_volatile(const std::string& recipient_hash,
                        const void* data,
                        size_t length,
                        std::shared_ptr<WebSocketSession> sender = nullptr);

    void relay_multicast(const std::vector<std::string>& recipients,
                         const std::string& message_json);

    void relay_group_message(const boost::json::array& targets,
                            std::shared_ptr<WebSocketSession> sender);
    
    void handle_dummy(std::shared_ptr<WebSocketSession> sender);

    void deliver_pending(const std::string& recipient_hash,
                         std::shared_ptr<WebSocketSession> recipient);

    void subscribe_user(const std::string& user_hash) { redis_.subscribe_user(user_hash); }
    void unsubscribe_user(const std::string& user_hash) { redis_.unsubscribe_user(user_hash); }

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
    
    RoutingInfo extract_routing(const std::string& message_json);
};

}
