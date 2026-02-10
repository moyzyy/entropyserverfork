#include <boost/json.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <random>
#include <shared_mutex>
#include "connection_manager.hpp"
#include "websocket_session.hpp"
#include "metrics.hpp"
#include "server_config.hpp"
#include "security_logger.hpp"

namespace json = boost::json;

namespace entropy {

    /**
     * ConnectionManager Constructor.
     * Initializes the manager with a server-specific salt for ID blinding.
     */
    ConnectionManager::ConnectionManager(const std::string& salt) : salt_(salt) {}

    /**
     * Routes a distributed message from the Redis pub/sub layer to a local session.
     * Uses blinded ID mapping to preserve anonymity in the routing table.
     */
    void ConnectionManager::process_distributed_message_for_blinded_id(const std::string& blinded_id, const std::string& message_json) {
        std::shared_lock lock(connections_mutex_);
        auto it = connections_.find(blinded_id);
        if (it != connections_.end()) {
            if (auto session = it->second.lock()) {
                session->send_text(message_json);
            }
        }
    }

// Parses a distributed message and routes it to one or more local recipients.
void ConnectionManager::process_distributed_message(const std::string& message_json) {
    try {
        auto json_val = json::parse(message_json);
        if (!json_val.is_object()) return;
        
        auto& obj = json_val.as_object();
        
        auto deliver_to = [this, &message_json](const std::string& to_hash) {
            std::string blinded = blind_id(to_hash);
            std::shared_lock lock(connections_mutex_);
            auto it = connections_.find(blinded);
            if (it != connections_.end()) {
                if (auto session = it->second.lock()) {
                    session->send_text(message_json);
                }
            }
        };

        if (obj.contains("to")) {
            if (obj["to"].is_string()) {
                deliver_to(std::string(obj["to"].as_string()));
            } else if (obj["to"].is_array()) {
                for (const auto& r : obj["to"].as_array()) {
                    if (r.is_string()) {
                        deliver_to(std::string(r.as_string()));
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, 
                           SecurityLogger::EventType::INVALID_INPUT, 
                           "SYSTEM", 
                           "JSON Distribution Failed: " + std::string(e.what()));
    } catch (...) {
        SecurityLogger::log(SecurityLogger::Level::ERROR,
                           SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                           "SYSTEM",
                           "Unknown error in distributed message processing");
    }
}

// Registers a session in the connection pool.
void ConnectionManager::add_connection(const std::string& pub_key_hash, SessionPtr session) {
    std::string blinded = blind_id(pub_key_hash);
    std::unique_lock lock(connections_mutex_);
    connections_[blinded] = session;
}

// Registers a session in the connection pool while enforcing per-IP resource limits.
bool ConnectionManager::add_connection_with_limit(const std::string& pub_key_hash, 
                                                   SessionPtr session,
                                                   const std::string& ip_address,
                                                   size_t max_per_ip) {
    std::unique_lock lock(connections_mutex_);
    
    std::string b_ip = blind_id(ip_address);
    size_t count = ip_counts_[b_ip];
    
    // Check against max_per_ip (this is a secondary check, primary is in on_accept)
    if (count > max_per_ip) {
        MetricsRegistry::instance().increment_counter("connection_rejected_limit_total");
        return false;
    }
    
    std::string blinded = blind_id(pub_key_hash);
    connections_[blinded] = session;
    
    if (!session->is_authenticated()) {
        session->set_authenticated(true);
        MetricsRegistry::instance().increment_gauge("active_connections");
    }
    
    MetricsRegistry::instance().increment_counter("connection_created_total");
    
    return true;
}

    void ConnectionManager::remove_session(WebSocketSession* session) {
        if (!session) return;
        
        std::unique_lock lock(connections_mutex_);
        std::string b_ip = blind_id(session->remote_address());
        std::string user_data = session->get_user_data();
        
        if (!user_data.empty()) {
            std::string blinded = blind_id(user_data);
            auto it = connections_.find(blinded);
            if (it != connections_.end()) {
                if (auto existing = it->second.lock()) {
                    if (existing.get() == session) connections_.erase(it);
                } else {
                    connections_.erase(it);
                }
            }
        }
        
        for (const auto& alias : session->get_aliases()) {
            std::string blinded = blind_id(alias);
            auto it = connections_.find(blinded);
            if (it != connections_.end()) {
                if (auto existing = it->second.lock()) {
                    if (existing.get() == session) connections_.erase(it);
                } else {
                    connections_.erase(it);
                }
            }
        }
        
        if (session->is_authenticated()) {
            MetricsRegistry::instance().decrement_gauge("active_connections");
            session->set_authenticated(false);
        }
    }

// Returns a direct reference to a session given a public key hash.
ConnectionManager::SessionPtr ConnectionManager::get_connection(const std::string& pub_key_hash) {
    std::string blinded = blind_id(pub_key_hash);
    std::shared_lock lock(connections_mutex_);
    auto it = connections_.find(blinded);
    if (it != connections_.end()) {
        return it->second.lock();  
    }
    return nullptr;
}

// Checks if a given ID is currently connected to this specific server instance.
bool ConnectionManager::is_online(const std::string& pub_key_hash) {
    if (pub_key_hash.empty()) return false;
    std::string blinded = blind_id(pub_key_hash);
    std::shared_lock lock(connections_mutex_);
    auto it = connections_.find(blinded);
    if (it != connections_.end()) {
        return !it->second.expired();
    }
    return false;
}

size_t ConnectionManager::connection_count() const {
    std::shared_lock lock(connections_mutex_);
    return connections_.size();
}

size_t ConnectionManager::connection_count_for_ip(const std::string& ip_address) const {
    std::string b_ip = blind_id(ip_address);
    std::shared_lock lock(connections_mutex_);
    auto it = ip_counts_.find(b_ip);
    if (it != ip_counts_.end()) {
        return it->second;
    }
    return 0;
}

// Scans and removes entries for sessions that have timed out or been disconnected.
void ConnectionManager::cleanup_dead_connections() {
    {
        std::unique_lock lock(connections_mutex_);
        for (auto it = connections_.begin(); it != connections_.end(); ) {
            if (it->second.expired()) {
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// Closes all tracked websocket sessions immediately.
void ConnectionManager::close_all_connections() {
    std::vector<SessionPtr> active_sessions;
    {
        std::shared_lock lock(connections_mutex_);
        for (auto const& [id, weak_session] : connections_) {
            if (auto session = weak_session.lock()) {
                active_sessions.push_back(session);
            }
        }
    }
    
    for (auto const& session : active_sessions) {
        try {
            session->close();
        } catch (...) {}
    }
}

    /**
     * Generates a salted SHA256 "Blinded ID" to decouple public identity from session tracking.
     * This provides a primitive layer of metadata resistance for the routing layer.
     */
    std::string ConnectionManager::blind_id(const std::string& id) const {
        std::string data = id + salt_;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

bool ConnectionManager::increment_ip_count(const std::string& ip, size_t limit) {
    std::unique_lock lock(connections_mutex_);
    std::string b_ip = blind_id(ip);
    size_t& count = ip_counts_[b_ip];
    if (count >= limit) return false;
    count++;
    return true;
}

void ConnectionManager::decrement_ip_count(const std::string& ip) {
    std::unique_lock lock(connections_mutex_);
    std::string b_ip = blind_id(ip);
    auto it = ip_counts_.find(b_ip);
    if (it != ip_counts_.end()) {
        if (it->second > 0) it->second--;
        if (it->second == 0) ip_counts_.erase(it);
    }
}

}
 
