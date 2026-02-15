#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <memory>
#include <boost/asio.hpp>

namespace net = boost::asio;

namespace entropy {

class WebSocketSession;

class ConnectionManager {
public:
    using SessionPtr = std::shared_ptr<WebSocketSession>;
    using WeakSessionPtr = std::weak_ptr<WebSocketSession>;
    
    explicit ConnectionManager(const std::string& salt);
    ~ConnectionManager();
    
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    
    void add_connection(const std::string& pub_key_hash, SessionPtr session);
    
    bool add_connection_with_limit(const std::string& pub_key_hash, SessionPtr session, 
                                    const std::string& ip_address, size_t max_per_ip);
    
    void remove_session(WebSocketSession* session);
    
    SessionPtr get_connection(const std::string& pub_key_hash);
    
    

    void start_pacing_loop(net::io_context& ioc, int interval_ms);
    
    bool is_online(const std::string& pub_key_hash);
    
    size_t connection_count() const;
    
    size_t connection_count_for_ip(const std::string& ip_address) const;
    
    void cleanup_dead_connections();
    void close_all_connections();

    bool increment_ip_count(const std::string& ip, size_t limit);
    void decrement_ip_count(const std::string& ip);
    
    std::string blind_id(const std::string& id) const;

private:
    void on_pacing_tick(int interval_ms);
    
    std::unordered_map<std::string, WeakSessionPtr> connections_;
    std::unordered_map<WebSocketSession*, WeakSessionPtr> unique_sessions_;
    std::unordered_map<std::string, size_t> ip_counts_;
    mutable std::shared_mutex connections_mutex_;
    std::string salt_;
    std::unique_ptr<net::steady_timer> pacing_timer_;
    std::vector<SessionPtr> sessions_to_flush_cache_;
};

} 
