#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <memory>
#include <filesystem>
#include <cstdlib>

#include "server_config.hpp"
#include "connection_manager.hpp"
#include "message_relay.hpp"
#include "redis_manager.hpp"
#include "key_storage.hpp"
#include "http_session.hpp"
#include "rate_limiter.hpp"
#include "security_logger.hpp"
#include "metrics.hpp"


namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

namespace entropy {

class Listener : public std::enable_shared_from_this<Listener> {
public:
    Listener(
        net::io_context& ioc,
        ssl::context& ssl_ctx,
        tcp::endpoint endpoint,
        const ServerConfig& config,
        ConnectionManager& conn_manager,
        MessageRelay& relay,

        RateLimiter& rate_limiter,
        KeyStorage& key_storage,
        RedisManager& redis
    )
        : ioc_(ioc)
        , ssl_ctx_(ssl_ctx)
        , acceptor_(net::make_strand(ioc))
        , config_(config)
        , conn_manager_(conn_manager)
        , relay_(relay)
        , rate_limiter_(rate_limiter)
        , key_storage_(key_storage)
        , redis_(redis)
    {
        beast::error_code ec;
        
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            throw std::runtime_error("Failed to open acceptor: " + ec.message());
        }
        
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            throw std::runtime_error("Failed to set SO_REUSEADDR: " + ec.message());
        }
        
        acceptor_.bind(endpoint, ec);
        if (ec) {
            throw std::runtime_error("Failed to bind: " + ec.message());
        }
        
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            throw std::runtime_error("Failed to listen: " + ec.message());
        }
    }
    
    void run() {
        do_accept();
    }

    void stop() {
        beast::error_code ec;
        acceptor_.close(ec);
    }

private:
    net::io_context& ioc_;
    ssl::context& ssl_ctx_;
    tcp::acceptor acceptor_;
    
    const ServerConfig& config_;
    ConnectionManager& conn_manager_;
    MessageRelay& relay_;

    RateLimiter& rate_limiter_;
    KeyStorage& key_storage_;
    RedisManager& redis_;
    
    void do_accept() {
        acceptor_.async_accept(
            net::make_strand(ioc_),
            [self = shared_from_this()](beast::error_code ec, tcp::socket socket) {
                self->on_accept(ec, std::move(socket));
            });
    }
    
    void on_accept(beast::error_code ec, tcp::socket socket) {
        if (ec) {
            SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::CONNECTION_REJECTED, "internal", "Accept error: " + ec.message());
            
            // If the listener is still open, wait a bit before retrying to avoid spinning on fatal errors
            if (acceptor_.is_open()) {
                auto timer = std::make_shared<net::steady_timer>(ioc_);
                timer->expires_after(std::chrono::seconds(1));
                timer->async_wait([self = shared_from_this(), timer](beast::error_code ec_timer) {
                    if (!ec_timer) {
                        self->do_accept();
                    }
                });
                return;
            }
        } else {
            std::string remote_ip;
            try {
                remote_ip = socket.remote_endpoint().address().to_string();
            } catch (...) {
                remote_ip = "unknown";
            }

            // Accepted connection from remote peer
            
            if (conn_manager_.connection_count() >= config_.max_global_connections) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::CONNECTION_REJECTED,
                                  remote_ip, "Global connection limit reached");
                MetricsRegistry::instance().increment_counter("global_limit_rejected");
            } else if (!conn_manager_.increment_ip_count(remote_ip, config_.max_connections_per_ip)) {
                // Enforce per-IP connection limit BEFORE creating session
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT,
                                  remote_ip, "Per-IP total connection limit reached");
                MetricsRegistry::instance().increment_counter("ip_limit_rejected");
                // Socket will be closed when it goes out of scope here
            } else {
                // Create a guard to decrement the IP count when the session tree is destroyed
                auto guard = std::shared_ptr<void>(nullptr, [self_ref = shared_from_this(), remote_ip](void*){
                    self_ref->conn_manager_.decrement_ip_count(remote_ip);
                });

                if (config_.enable_tls) {
                    auto stream = beast::ssl_stream<beast::tcp_stream>(
                        beast::tcp_stream(std::move(socket)),
                        ssl_ctx_
                    );
                    
                    std::make_shared<HttpSession>(
                        std::move(stream),
                        config_,
                        conn_manager_,
                        relay_,
                        rate_limiter_,
                        key_storage_,
                        redis_,
                        guard
                    )->run();
                } else {
                    std::make_shared<HttpSession>(
                        beast::tcp_stream(std::move(socket)),
                        config_,
                        conn_manager_,
                        relay_,
                        rate_limiter_,
                        key_storage_,
                        redis_,
                        guard
                    )->run();
                }
            }
        }
        
        do_accept();
    }
};

} 

// Configures the SSL context (TLS 1.2+).
void load_server_certificate(ssl::context& ctx, const std::string& cert_path, const std::string& key_path) {
    ctx.set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2 |
        ssl::context::no_sslv3 |
        ssl::context::no_tlsv1 |
        ssl::context::no_tlsv1_1 |
        ssl::context::single_dh_use
    );
    
    SSL_CTX_set_options(ctx.native_handle(), SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_2_VERSION);
    
    SSL_CTX_set_cipher_list(ctx.native_handle(),
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256"
    );
    
    ctx.use_certificate_chain_file(cert_path);
    ctx.use_private_key_file(key_path, ssl::context::pem);
}

int main(int argc, char* argv[]) {
    using entropy::SecurityLogger;
    try {
        entropy::ServerConfig config;
        
        // --- CLI Argument Parsing ---
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--no-tls" || arg == "-n") {
                config.enable_tls = false;
            } else if (arg == "--help" || arg == "-h") {
                std::cout << "Usage: " << argv[0] << " [port] [options]\n"
                          << "Options:\n"
                          << "  --no-tls, -n   Disable TLS (for local development)\n"
                          << "  --help, -h     Show this help\n";
                return 0;
            } else {
                try {
                    config.port = static_cast<uint16_t>(std::stoi(arg));
                } catch (...) {
                    return 1;
                }
            }
        }
        
        // --- Environment Variable Overrides ---
        
        if (const char* env_port = std::getenv("ENTROPY_PORT")) {
            config.port = static_cast<uint16_t>(std::stoi(env_port));
        }
        if (const char* env_addr = std::getenv("ENTROPY_ADDR")) {
            config.address = env_addr;
        }
        if (const char* env_redis = std::getenv("ENTROPY_REDIS_URL")) {
            config.redis_url = env_redis;
        }
        if (const char* env_origins = std::getenv("ENTROPY_ALLOWED_ORIGINS")) {
            config.allowed_origins.clear();
            std::string origins_str(env_origins);
            size_t pos = 0;
            while ((pos = origins_str.find(',')) != std::string::npos) {
                config.allowed_origins.push_back(origins_str.substr(0, pos));
                origins_str.erase(0, pos + 1);
            }
            if (!origins_str.empty()) {
                config.allowed_origins.push_back(origins_str);
            }
        }
        
        if (const char* env_salt = std::getenv("ENTROPY_SECRET_SALT")) {
            config.secret_salt = env_salt;
        }

        if (const char* env_admin = std::getenv("ENTROPY_ADMIN_TOKEN")) {
            config.admin_token = env_admin;
        }

        if (const char* env_max_ip = std::getenv("ENTROPY_MAX_CONNS_PER_IP")) {
            config.max_connections_per_ip = static_cast<size_t>(std::stoull(env_max_ip));
        }

        if (const char* env_rate = std::getenv("ENTROPY_RATE_LIMIT")) {
            config.rate_limit_per_sec = std::stod(env_rate);
            config.rate_limit_burst = static_cast<size_t>(config.rate_limit_per_sec * 2);
        }

        if (const char* env_pow = std::getenv("ENTROPY_POW_LIMIT")) {
            config.pow_rate_limit = std::stoi(env_pow);
        }

        // Granular Rate Limits
        if (const char* e = std::getenv("ENTROPY_LIMIT_GLOBAL")) config.global_rate_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_KEYS_UPLOAD")) config.keys_upload_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_KEYS_FETCH")) config.keys_fetch_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_KEYS_RANDOM")) config.keys_random_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_RELAY")) config.relay_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_NICK_REGISTER")) config.nick_register_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_NICK_LOOKUP")) config.nick_lookup_limit = std::stoi(e);
        if (const char* e = std::getenv("ENTROPY_LIMIT_ACCOUNT_BURN")) config.account_burn_limit = std::stoi(e);
        
        if (config.allowed_origins.empty()) {
             SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT, "internal", "No CORS origins configured");
        }
        
        static const std::string DEFAULT_SALT = "CHANGE_ME_IN_PRODUCTION_VIA_ENV_OR_LOGS_WILL_BE_INSECURE";
        if (config.secret_salt == DEFAULT_SALT) {
            std::cerr << "CRITICAL SECURITY ERROR: DEFAULT SECRET SALT DETECTED\n";
            std::cerr << "Set 'ENTROPY_SECRET_SALT' environment variable immediately!\n";
            return 1;
        }
        
        
        if (config.thread_count == 0) {
            config.thread_count = static_cast<int>(std::thread::hardware_concurrency());
            if (config.thread_count == 0) config.thread_count = 4;
        }
        
        
        // Initialize environment
        std::filesystem::path exe_path;
        try {
            exe_path = std::filesystem::canonical("/proc/self/exe").parent_path();
        } catch (const std::exception& e) {
            std::cerr << "[!] Warning: Could not detect executable path via /proc/self/exe: " << e.what() << std::endl;
            exe_path = std::filesystem::current_path();
        }
        
        if (config.enable_tls) {
            if (config.cert_path.rfind("certs/", 0) == 0) {
                config.cert_path = (exe_path / config.cert_path).string();
                config.key_path = (exe_path / config.key_path).string();
            }
            
            
            if (!std::filesystem::exists(config.cert_path) || 
                !std::filesystem::exists(config.key_path)) {
                std::cerr << "[!] TLS certificates not found at:\n"
                          << "    " << config.cert_path << "\n"
                          << "    " << config.key_path << "\n"
                          << "[*] Run 'cmake --build . --target generate_certs' to generate them.\n"
                          << "[*] Or use --no-tls for development without TLS.\n";
                return 1;
            }
        }
        
        
        std::cout << R"(
ENTROPY SECURE MESSAGING SERVER v2.0            
)" << (config.enable_tls ? "  ✓ TLS 1.2+/1.3 encrypted transport                          \n" 
                         : "  ⚠ TLS DISABLED (development mode)                           \n")
   << "\n";
        
        
        net::io_context ioc{config.thread_count};
        
        
        ssl::context ssl_ctx{ssl::context::tlsv12};
        if (config.enable_tls) {
            load_server_certificate(ssl_ctx, config.cert_path, config.key_path);
        }
        
        entropy::ConnectionManager conn_manager(config.secret_salt);
        
        entropy::RedisManager redis(config, conn_manager, config.secret_salt); 
        
        entropy::RateLimiter rate_limiter(redis);
        entropy::MessageRelay relay(conn_manager, redis, rate_limiter);

        
        net::steady_timer cleanup_timer(ioc, std::chrono::minutes(5));
        std::function<void(beast::error_code)> on_cleanup;
        on_cleanup = [&](beast::error_code ec) {
            if (!ec) {
                conn_manager.cleanup_dead_connections();
                cleanup_timer.expires_after(std::chrono::minutes(5));
                cleanup_timer.async_wait(on_cleanup);
            }
        };
        cleanup_timer.async_wait(on_cleanup);

        
    // Flag to track server running state
        std::atomic<bool> running{true};
        
        auto listener = std::make_shared<entropy::Listener>(
            ioc,
            ssl_ctx,
            tcp::endpoint{net::ip::make_address(config.address), config.port},
            config,
            conn_manager,
            relay,
            rate_limiter,
            redis,
            redis
        );
        listener->run();
        
        // Server started successfully
        // Captured SIGINT and SIGTERM to perform a clean shutdown
        net::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait(
            [&ioc, &running, &conn_manager, listener, &cleanup_timer](beast::error_code const&, int sig) {
                SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "internal", "Initiating graceful shutdown");
                running = false;
                beast::error_code ec;
                cleanup_timer.cancel(ec);
                listener->stop();
                conn_manager.close_all_connections();
            });
        
        std::vector<std::thread> threads;
        threads.reserve(config.thread_count - 1);
        
        for (int i = 0; i < config.thread_count - 1; ++i) {
            threads.emplace_back([&ioc] {
                ioc.run();
            });
        }
        
        ioc.run();
        
        for (auto& t : threads) {
            t.join();
        }
        
        running = false;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "[!] Fatal error: " << e.what() << "\n";
        return 1;
    }
}
