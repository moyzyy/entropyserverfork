#include <boost/json.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>
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

    ConnectionManager::ConnectionManager(const std::string& salt) : salt_(salt) {}

    ConnectionManager::~ConnectionManager() {
        std::unique_lock lock(connections_mutex_);
        pacing_timer_.reset();
        for (auto& [ptr, weak] : unique_sessions_) {
            if (auto s = weak.lock()) {
                s->set_close_handler(nullptr);
            }
        }
    }

void ConnectionManager::add_connection(const std::string& pub_key_hash, SessionPtr session) {
    std::string blinded = blind_id(pub_key_hash);
    std::unique_lock lock(connections_mutex_);
    connections_[blinded] = session;
    unique_sessions_[session.get()] = session;
}

bool ConnectionManager::add_connection_with_limit(const std::string& pub_key_hash, 
                                                   SessionPtr session,
                                                   const std::string& ip_address,
                                                   size_t max_per_ip) {
    std::unique_lock lock(connections_mutex_);
    
    std::string b_ip = blind_id(ip_address);
    size_t& count = ip_counts_[b_ip];
    
    if (count > max_per_ip) {
        MetricsRegistry::instance().increment_counter("connection_rejected_limit_total");
        return false;
    }
    
    std::string blinded = blind_id(pub_key_hash);
    connections_[blinded] = session;
    unique_sessions_[session.get()] = session;
    
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
        
        // Decrement IP count if we have the address
        std::string ip = session->remote_address();
        if (!ip.empty()) {
             std::string b_ip = blind_id(ip);
             auto it = ip_counts_.find(b_ip);
             if (it != ip_counts_.end()) {
                 if (it->second > 0) it->second--;
                 if (it->second == 0) ip_counts_.erase(it);
             }
        }

        std::string user_data = session->get_user_data();
        if (!user_data.empty()) {
            std::string blinded = session->get_blinded_user_data();
            if (blinded.empty()) blinded = blind_id(user_data); 
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

        unique_sessions_.erase(session);
    }

ConnectionManager::SessionPtr ConnectionManager::get_connection(const std::string& pub_key_hash) {
    std::string blinded = blind_id(pub_key_hash);
    std::shared_lock lock(connections_mutex_);
    auto it = connections_.find(blinded);
    if (it != connections_.end()) {
        return it->second.lock();  
    }
    return nullptr;
}

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
    return unique_sessions_.size();
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
        for (auto it = unique_sessions_.begin(); it != unique_sessions_.end(); ) {
            if (it->second.expired()) {
                it = unique_sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void ConnectionManager::close_all_connections() {
    std::vector<SessionPtr> active_sessions;
    {
        std::shared_lock lock(connections_mutex_);
        for (auto const& [ptr, weak_session] : unique_sessions_) {
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

    std::string ConnectionManager::blind_id(const std::string& id) const {
        unsigned int len = SHA256_DIGEST_LENGTH;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        
        HMAC(EVP_sha256(), salt_.c_str(), salt_.size(), 
             reinterpret_cast<const unsigned char*>(id.c_str()), id.size(), 
             hash, &len);
        
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(SHA256_DIGEST_LENGTH * 2);
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            result.push_back(hex_chars[hash[i] >> 4]);
            result.push_back(hex_chars[hash[i] & 0x0F]);
        }
        return result;
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

void ConnectionManager::start_pacing_loop(net::io_context& ioc, int interval_ms) {
    pacing_timer_ = std::make_unique<net::steady_timer>(ioc, std::chrono::milliseconds(interval_ms));
    pacing_timer_->async_wait([this, interval_ms](beast::error_code ec) {
        if (!ec) on_pacing_tick(interval_ms);
    });
}

void ConnectionManager::on_pacing_tick(int interval_ms) {
    {
        std::shared_lock lock(connections_mutex_);
        sessions_to_flush_cache_.clear();
        sessions_to_flush_cache_.reserve(unique_sessions_.size());
        
        for (auto const& [ptr, weak_session] : unique_sessions_) {
            if (auto session = weak_session.lock()) {
                sessions_to_flush_cache_.push_back(session);
            }
        }
    }

    for (auto& session : sessions_to_flush_cache_) {
        net::post(session->get_executor(), [session = std::move(session)]() {
            session->flush_pacing_queue();
            session->check_dummy_traffic(); 
        });
    }
    sessions_to_flush_cache_.clear();

    std::unique_lock lock(connections_mutex_);
    if (pacing_timer_) {
        pacing_timer_->expires_after(std::chrono::milliseconds(interval_ms));
        pacing_timer_->async_wait([this, interval_ms](beast::error_code ec) {
            if (!ec) on_pacing_tick(interval_ms);
        });
    }
}

}
