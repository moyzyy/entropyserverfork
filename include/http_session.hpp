#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/strand.hpp>
#include <memory>
#include <string>
#include <variant>

#include "server_config.hpp"
#include "key_storage.hpp"

#include "redis_manager.hpp"
#include "handlers/health_handler.hpp"
#include "handlers/identity_handler.hpp" 

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

namespace entropy {

class ConnectionManager;
class MessageRelay;
class RateLimiter;

 
class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(
        beast::ssl_stream<beast::tcp_stream>&& stream,
        const ServerConfig& config,
        ConnectionManager& conn_manager,
        MessageRelay& relay,
        RateLimiter& rate_limiter,
        KeyStorage& key_storage,
        RedisManager& redis,
        std::shared_ptr<void> conn_guard
    );
    
    
    HttpSession(
        beast::tcp_stream&& stream,
        const ServerConfig& config,
        ConnectionManager& conn_manager,
        MessageRelay& relay,
        RateLimiter& rate_limiter,
        KeyStorage& key_storage,
        RedisManager& redis,
        std::shared_ptr<void> conn_guard
    );
    
    ~HttpSession() = default;
    
     
    void run();

private:
    std::variant<
        beast::ssl_stream<beast::tcp_stream>,
        beast::tcp_stream
    > stream_;
    bool is_tls_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    boost::optional<http::request_parser<http::string_body>> parser_; 
    
    const ServerConfig& config_;
    ConnectionManager& conn_manager_;
    MessageRelay& relay_;

    RateLimiter& rate_limiter_;
    KeyStorage& key_storage_;
    RedisManager& redis_;
    
    // Handlers (Shared to survive upgrade to WebSocket)
    std::shared_ptr<HealthHandler> health_handler_;
    std::shared_ptr<IdentityHandler> identity_handler_;
    
    std::string remote_addr_;
    std::shared_ptr<void> conn_guard_;
    
    void on_handshake(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    
    
    void handle_request();
    void send_response(http::response<http::string_body>&& res);
    void on_write(bool close, beast::error_code ec, std::size_t bytes_transferred);
    
    
    void upgrade_to_websocket();
    
    // Delegated to Handlers or retained wrappers
    http::response<http::string_body> handle_cors_preflight();
    http::response<http::string_body> handle_not_found();
    http::response<http::string_body> handle_rate_limited(const RateLimitResult& res_info);

    std::string blind_ip(const std::string& ip);


    
    

    
    
    template<class Body>
    void add_security_headers(http::response<Body>& res);
    
    
    template<class Body>
    void add_cors_headers(http::response<Body>& res);
};

} 
