#pragma once

#include <string>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <sw/redis++/redis++.h>
#include <boost/asio.hpp>
#include "key_storage.hpp"

namespace net = boost::asio;

namespace entropy {

class ConnectionManager;
struct ServerConfig;

struct RateLimitResult {
    bool allowed;
    long long current;
    long long limit;
    long long reset_after_sec;
};
class RedisManager : public KeyStorage {
public:
    using MessageHandler = std::function<void(const std::string& channel, const std::string& msg)>;

    RedisManager(const ServerConfig& config, ConnectionManager& conn_manager, const std::string& salt);
    ~RedisManager();

    bool is_connected() const { return connected_; }

    // Implements an atomic token-bucket rate limiter via Lua scripting.
    RateLimitResult rate_limit(const std::string& key, int limit, int period_sec, int cost = 1);

    // Issues a cryptographically random seed for a Proof-of-Work challenge.
    virtual std::string issue_challenge(int ttl_sec);
    
    // Consumes a seed solution, ensuring it cannot be replayed.
    virtual bool consume_challenge(const std::string& seed);
    
    std::string create_session_token(const std::string& user_hash, int ttl_sec);
    bool verify_session_token(const std::string& user_hash, const std::string& token);

    virtual bool store_offline_message(const std::string& user_hash, const std::string& message_json);
    std::vector<std::string> retrieve_offline_messages(const std::string& user_hash);
    
    bool store_user_bundle(const std::string& user_hash, const std::string& bundle_json);
    
    // KeyStorage Interface mapping
    bool store_bundle(const std::string& user_hash, const std::string& bundle_json) override {
        return store_user_bundle(user_hash, bundle_json);
    }
    
    std::string get_bundle(const std::string& user_hash) override {
        return get_user_bundle(user_hash);
    }

    std::string get_user_bundle(const std::string& user_hash);
    
    // Returns a set of random hashes for traffic normalization/decoy discovery.
    std::vector<std::string> get_random_user_hashes(int count);

    bool register_nickname(const std::string& nickname, const std::string& user_hash);
    std::string resolve_nickname(const std::string& nickname);
    
    // Tracks global registration frequency to dynamically adjust PoW difficulty.
    int get_registration_intensity();
    
    long long get_account_age(const std::string& user_hash);
    void mark_id_seen(const std::string& user_hash);

    // Permanently purges all data associated with an identity.
    bool burn_account(const std::string& user_hash);

    // Deletes a specific key (mainly for testing/internal cleanup).
    bool delete_key(const std::string& key);
    
    void set_blocking_executor(net::any_io_executor exec) { blocking_exec_ = std::move(exec); }
    net::any_io_executor get_blocking_executor() { return blocking_exec_; }

private:
    net::any_io_executor blocking_exec_;
    std::unique_ptr<sw::redis::Redis> redis_;
    ConnectionManager& conn_manager_;
    
    std::atomic<bool> connected_{false};

    std::string blind(const std::string& input);
    std::string server_salt_;
    size_t offline_msg_limit_;
};

} 
