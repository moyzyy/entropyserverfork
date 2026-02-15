#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace entropy {

 
// Server configuration and security policies.
struct ServerConfig {
    // Network
    std::string address = "0.0.0.0";
    uint16_t port = 8080;
    std::string redis_url = "tcp://127.0.0.1:6379?socket_timeout=1s";
    std::string redis_password = "";
    std::string redis_username = "";
    int thread_count = 0;
    
    // TLS
    bool enable_tls = false;
    std::string cert_path = "certs/server.crt";
    std::string key_path = "certs/server.key";
    
    // Resource Limits
    size_t max_message_size = 128 * 1024; // 128KB for media chunking
    size_t max_connections_per_ip = 10;
    size_t max_global_connections = 8000;
    int connection_timeout_sec = 60;
    int websocket_ping_interval_sec = 30;
    
    // Rate Limiting
    double rate_limit_per_sec = 200.0;
    size_t rate_limit_burst = 400;
    
    // PoW
    int pow_rate_limit = 20; 
    
    // Redis-backed Window Limits
    int global_rate_limit = 300;
    int keys_upload_limit = 10;
    int keys_fetch_limit = 50;
    int keys_random_limit = 20;
    int relay_limit = 100; // Reduced global relay limit
    int offline_msg_limit = 100; // Hard limit for offline queue 
    int nick_register_limit = 5;
    int nick_lookup_limit = 30;
    int account_burn_limit = 3;

    // Keys
    std::string secret_salt = "CHANGE_IN_PROD_998811"; // MUST Override via ENTROPY_SECRET_SALT
    std::string admin_token = "";
    
    // CORS
    std::vector<std::string> allowed_origins = {"localhost", "127.0.0.1", "tauri://"};
    std::vector<std::string> allowed_methods = {"GET", "POST", "OPTIONS"};
    std::vector<std::string> allowed_headers = {"Content-Type", "Authorization"};
    
    // Protocol
    size_t max_nickname_length = 32;
    size_t max_prekeys_per_upload = 100;
    int max_pow_difficulty = 5; 
    size_t max_json_depth = 8;

    // Traffic Pacing
    struct Pacing {
        static constexpr int idle_threshold_ms = 5000;
        static constexpr size_t packet_size = 256; 
        static constexpr int tick_interval_ms = 500;
    } pacing;

    // Randomized Cover Traffic
    struct Dummy {
        bool enabled = true;
        int min_interval_s = 10;
        int max_interval_s = 60;
    } dummy;
    
    // Resource Pool
    int blocking_thread_count = 16; // Optimized for mass-reconnect resilience
};

}
