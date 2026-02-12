#pragma once

#include <string>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <sw/redis++/redis++.h>
#include "key_storage.hpp"

namespace entropy {

class ConnectionManager;
struct ServerConfig;

 
struct RateLimitResult {
    bool allowed;
    long long current;
    long long limit;
    long long reset_after_sec;
};
// Redis-backed state manager for rate limiting, Pub/Sub, and identity storage.
class RedisManager : public KeyStorage {
public:
    using MessageHandler = std::function<void(const std::string& channel, const std::string& msg)>;

    RedisManager(const ServerConfig& config, ConnectionManager& conn_manager, const std::string& salt);
    ~RedisManager();

    // --- Distributed Messaging (Pub/Sub) ---
    // Publishes a message to a specific recipient hash across all cluster nodes.
    virtual void publish_message(const std::string& recipient_hash, const std::string& message_json);
    
    // Publishes a message to multiple recipients atomically.
    virtual void publish_multicast(const std::vector<std::string>& recipients, const std::string& message_json);

    // Subscribes the current node to receive messages for a user hash.
    void subscribe_user(const std::string& user_hash);

    // Unsubscribes from a user hash, usually on connection termination.
    void unsubscribe_user(const std::string& user_hash);
    
    // Connection health check.
    bool is_connected() const { return connected_; }

    // --- Global Rate Limiting ---
    // Implements an atomic token-bucket rate limiter via Lua scripting.
    RateLimitResult rate_limit(const std::string& key, int limit, int period_sec, int cost = 1);

    // --- Anti-Spam Challenges (PoW) ---
    // Issues a cryptographically random seed for a Proof-of-Work challenge.
    virtual std::string issue_challenge(int ttl_sec);
    
    // Consumes a seed solution, ensuring it cannot be replayed.
    virtual bool consume_challenge(const std::string& seed);
    
    // --- Session & Identity Management ---
    std::string create_session_token(const std::string& user_hash, int ttl_sec);
    bool verify_session_token(const std::string& user_hash, const std::string& token);

    // --- Persistent Storage (Offline Messages & Identity Bundles) ---
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

    // --- Nickname Registry ---
    bool register_nickname(const std::string& nickname, const std::string& user_hash);
    std::string resolve_nickname(const std::string& nickname);
    
    // Tracks global registration frequency to dynamically adjust PoW difficulty.
    int get_registration_intensity();
    
    // --- Forensic Utilities ---
    long long get_account_age(const std::string& user_hash);
    void mark_id_seen(const std::string& user_hash);

    // Permanently purges all data associated with an identity.
    bool burn_account(const std::string& user_hash);

    // Deletes a specific key (mainly for testing/internal cleanup).
    bool delete_key(const std::string& key);

private:
    std::unique_ptr<sw::redis::Redis> redis_;
    std::unique_ptr<sw::redis::Subscriber> subscriber_;
    ConnectionManager& conn_manager_;
    
    std::atomic<bool> connected_{false};
    std::atomic<bool> running_{false};
    std::thread subscriber_thread_;
    mutable std::mutex subscriber_mutex_;

    void subscriber_loop();
    std::string blind(const std::string& input);
    std::string server_salt_;
};

} 
