#include "message_relay.hpp"
#include "websocket_session.hpp"
#include "traffic_normalizer.hpp"

#include <boost/json.hpp>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include "metrics.hpp"
#include "pow_verifier.hpp"
#include <random>
#include <thread>
#include <boost/asio/steady_timer.hpp>
#include "input_validator.hpp"

static const size_t REQUIRED_PACKET_SIZE = 1536; 
static const size_t SYSTEM_MSG_PADDING = 1536;

namespace json = boost::json;

namespace entropy {

// Appends random white-space padding to JSON objects to ensure constant packet size.
// This is used to prevent side-channel analysis of message lengths.


MessageRelay::MessageRelay(ConnectionManager& conn_manager, RedisManager& redis, RateLimiter& rate_limiter, const ServerConfig& config)
    : conn_manager_(conn_manager), redis_(redis), rate_limiter_(rate_limiter), config_(config) {}



    /**
     * Extracts routing metadata (type, destination) from a JSON payload.
     * Performs sanitization and structural validation before higher-level processing.
     */
    MessageRelay::RoutingInfo MessageRelay::extract_routing(const std::string& message_json) {
        RoutingInfo info{.type = "", .to = "", .valid = false};
        
        try {
            auto json_val = InputValidator::safe_parse_json(message_json);
            if (!json_val.is_object()) return info;
            auto& obj = json_val.as_object();
            
            if (obj.contains("type") && (obj["type"].is_string() || obj["type"].is_number())) {
                if (obj["type"].is_string()) {
                    info.type = InputValidator::sanitize_field(std::string(obj["type"].as_string()), 64);
                } else {
                    info.type = std::to_string(obj["type"].as_int64());
                }
            }
            if (obj.contains("to") && obj["to"].is_string()) {
                info.to = InputValidator::sanitize_field(std::string(obj["to"].as_string()), 256);
            }

            info.valid = !info.type.empty();
        } catch (...) {}
        
        return info;
    }

// Core routing logic. Routes messages to local sessions or pushes to Redis for remote instances.
void MessageRelay::relay_message(const std::string& message_json, 
                                  std::shared_ptr<WebSocketSession> sender) {
    
    if (!validate_message_size(message_json.size())) {
        MetricsRegistry::instance().increment_counter("message_error_total", 1.0);
        return;
    }
    
    MetricsRegistry::instance().increment_counter("message_total");
    
    if (!sender->is_authenticated()) {
         json::object err;
         err["type"] = "error";
         err["code"] = "auth_required";
         err["message"] = "Identity authentication required for message relay";
         sender->send_text(json::serialize(err));
         return;
    }
    
    auto routing = extract_routing(message_json);
    if (!routing.valid) {
        return;
    }

        if (routing.type == "ping" || routing.type == "dummy" || routing.type == "dummy_pacing") {
            handle_dummy(sender);
            return;
        }
        
        try {
            auto json_val = InputValidator::safe_parse_json(message_json);
            if (!json_val.is_object()) return;
            auto& obj = json_val.as_object();
            
            json::object clean_msg;
            if (obj.contains("type")) clean_msg["type"] = obj["type"];
            if (obj.contains("fragmentId")) clean_msg["fragmentId"] = obj["fragmentId"];
            if (obj.contains("index")) clean_msg["index"] = obj["index"];
            if (obj.contains("total")) clean_msg["total"] = obj["total"];
            if (obj.contains("data")) clean_msg["data"] = obj["data"];
            if (obj.contains("bundle")) clean_msg["bundle"] = obj["bundle"];
            if (obj.contains("body")) clean_msg["body"] = obj["body"];
            if (obj.contains("content")) clean_msg["content"] = obj["content"];
            if (obj.contains("id")) clean_msg["id"] = obj["id"];
            if (obj.contains("pow")) clean_msg["pow"] = obj["pow"];
            if (obj.contains("payload")) clean_msg["payload"] = obj["payload"];
            if (obj.contains("pq_ciphertext")) clean_msg["pq_ciphertext"] = obj["pq_ciphertext"];
            if (obj.contains("sender_identity_key")) clean_msg["sender_identity_key"] = obj["sender_identity_key"];
            if (obj.contains("ephemeral_key")) clean_msg["ephemeral_key"] = obj["ephemeral_key"];
            if (obj.contains("target_hash")) clean_msg["target_hash"] = obj["target_hash"];
            
            clean_msg["sender"] = sender->get_user_data();
            std::string final_json = json::serialize(clean_msg);
            
            if (final_json.size() < REQUIRED_PACKET_SIZE) {
                 json::object padded_obj = clean_msg;
                 TrafficNormalizer::pad_json(padded_obj, REQUIRED_PACKET_SIZE);
                 final_json = json::serialize(padded_obj);
            }

            thread_local std::mt19937 gen{std::random_device{}()};
            std::uniform_int_distribution<> dis(10, 50); 
            
            if (!routing.to.empty()) {
                auto rcv_limit = rate_limiter_.check("rcv:" + routing.to, 1000, 10); 
                if (!rcv_limit.allowed) {
                    MetricsRegistry::instance().increment_counter("recipient_flood_blocked");
                    return; 
                }

                auto recipient = conn_manager_.get_connection(routing.to);
                if (recipient) {
                    bool is_media = (clean_msg.contains("type") && clean_msg["type"] == "msg_fragment");
                
                // Local delivery (async with jitter)
                auto timer = std::make_shared<boost::asio::steady_timer>(recipient->get_executor());
                timer->expires_after(std::chrono::milliseconds(dis(gen)));
                
                timer->async_wait([recipient, final_json, is_media, timer](const boost::system::error_code& ec) {
                    if (!ec) {
                        recipient->send_text(final_json, is_media);
                    }
                });
            } else {
                // Remote delivery via Redis and temporary encryption-store for offline recipients
                redis_.publish_message(routing.to, final_json);
                bool stored = redis_.store_offline_message(routing.to, final_json);
                
                auto ack_timer = std::make_shared<boost::asio::steady_timer>(sender->get_executor());
                ack_timer->expires_after(std::chrono::milliseconds(dis(gen)));
                
                json::object response;
                
                if (stored) {
                    response["type"] = "delivery_status";
                    response["target"] = routing.to;
                    response["status"] = "relayed";
                } else {
                    MetricsRegistry::instance().increment_counter("storage_failure");
                    response["type"] = "error";
                    response["code"] = "storage_failed";
                    response["message"] = "Recipient offline and storage unavailable";
                }
                
                TrafficNormalizer::pad_json(response, REQUIRED_PACKET_SIZE);
                std::string ack_str = json::serialize(response);
                
                ack_timer->async_wait([sender, ack_str, ack_timer](const boost::system::error_code& ec) {
                    if (!ec) {
                        sender->send_text(ack_str);
                    }
                });
            }
        } else {
             std::cerr << "[!] Message delivery aborted: No recipient identifier provided\n";
        }
    } catch (...) {}
}

// Routes raw binary data directly to sessions. Primarily used for low-latency P2P signals.
void MessageRelay::relay_binary(const std::string& recipient_hash,
                                 const void* data, 
                                 size_t length,
                                 std::shared_ptr<WebSocketSession> sender) {
    
    if (!validate_message_size(length)) {
        std::cerr << "[!] Binary data exceeds maximum size limit\n";
        return;
    }

    if (!sender->is_authenticated()) {
        std::cerr << "[!] Unauthenticated binary relay blocked\n";
        json::object err;
        err["type"] = "error";
        err["code"] = "auth_required";
        err["message"] = "Login or Proof-of-Work required for binary relay";
        sender->send_text(json::serialize(err));
        return;
    }
    
    std::string safe_hash = InputValidator::sanitize_field(recipient_hash, 256);
    if (safe_hash.empty()) return;
    
    auto recipient = conn_manager_.get_connection(safe_hash);
    if (recipient) {
        try {
            std::string sender_hash = sender->get_user_data();
            std::string delivered_payload = sender_hash + std::string(static_cast<const char*>(data), length);
            
            // Binary normalization
            if (delivered_payload.size() < REQUIRED_PACKET_SIZE) {
                delivered_payload.resize(REQUIRED_PACKET_SIZE, '\0');
            }
            
            thread_local std::mt19937 gen{std::random_device{}()};
            std::uniform_int_distribution<> dis(10, 50);
            
            auto timer = std::make_shared<boost::asio::steady_timer>(recipient->get_executor());
            timer->expires_after(std::chrono::milliseconds(dis(gen)));
            
            timer->async_wait([recipient, delivered_payload, sender, timer](const boost::system::error_code& ec) {
                if (!ec) {
                    recipient->send_binary(delivered_payload, true); // Binary is always media-paced
                    
                    json::object response;
                    response["type"] = "relay_success";
                    response["status"] = "relayed";
                    TrafficNormalizer::pad_json(response, REQUIRED_PACKET_SIZE);
                    sender->send_text(json::serialize(response));
                }
            });
        } catch (const std::exception& e) {
            std::cerr << "[!] Binary relay failure: " << e.what() << "\n";
        }
    } else {
        // Fallback for cross-instance binary delivery via hex-encoded JSON wrapper
        std::string binary_data(static_cast<const char*>(data), length);
        json::object wrapper;
        wrapper["type"] = "binary_payload";
        wrapper["sender"] = sender->get_user_data(); 
        
        std::stringstream ss;
        for (unsigned char c : binary_data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        wrapper["data_hex"] = ss.str();
        std::string wrapper_str = json::serialize(wrapper);
        redis_.publish_message(safe_hash, wrapper_str);
        redis_.store_offline_message(safe_hash, wrapper_str);

        thread_local std::mt19937 gen{std::random_device{}()};
        std::uniform_int_distribution<> dis(10, 50);
        auto ack_timer = std::make_shared<boost::asio::steady_timer>(sender->get_executor());
        ack_timer->expires_after(std::chrono::milliseconds(dis(gen)));

        json::object response;
        response["type"] = "delivery_status";
        response["target"] = safe_hash;
        response["status"] = "relayed";
        TrafficNormalizer::pad_json(response, REQUIRED_PACKET_SIZE);
        std::string ack_str = json::serialize(response);

        ack_timer->async_wait([sender, ack_str, ack_timer](const boost::system::error_code& ec) {
            if (!ec) {
                sender->send_text(ack_str);
            }
        });
    }
}
// Low-overhead relay for ephemeral data. Does not provide ACKs or persistence.
void MessageRelay::relay_volatile(const std::string& recipient_hash,
                                  const void* data,
                                  size_t length,
                                  std::shared_ptr<WebSocketSession> sender) {
    std::string safe_hash = InputValidator::sanitize_field(recipient_hash, 256);
    if (safe_hash.empty()) return;

    auto recipient = conn_manager_.get_connection(safe_hash);
    if (recipient) {
        try {
            std::string sender_hash = sender ? sender->get_user_data() : std::string(64, '0');
            std::string delivered_payload = sender_hash + std::string(static_cast<const char*>(data), length);
            if (delivered_payload.size() < REQUIRED_PACKET_SIZE) {
                delivered_payload.resize(REQUIRED_PACKET_SIZE, '\0');
            }
            
            thread_local std::mt19937 gen{std::random_device{}()};
            std::uniform_int_distribution<> dis(10, 50);
            
            auto timer = std::make_shared<boost::asio::steady_timer>(recipient->get_executor());
            timer->expires_after(std::chrono::milliseconds(dis(gen)));
            
            timer->async_wait([recipient, delivered_payload, timer](const boost::system::error_code& ec) {
                if (!ec) {
                    recipient->send_binary(delivered_payload);
                }
            });
        } catch (...) {}
    } else {
        std::string binary_data(static_cast<const char*>(data), length);
        json::object wrapper;
        wrapper["type"] = "binary_payload";
        wrapper["volatile"] = true;
        wrapper["sender"] = sender ? sender->get_user_data() : "unknown";
        std::stringstream ss;
        for (unsigned char c : binary_data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        wrapper["data_hex"] = ss.str();
        redis_.publish_message(safe_hash, json::serialize(wrapper));
    }
}

// Routes one message to multiple recipients. Optimized for group chats.
void MessageRelay::relay_multicast(const std::vector<std::string>& recipients,
                                    const std::string& message_json) {
    if (!validate_message_size(message_json.size())) {
        std::cerr << "[!] Multicast message exceeds maximum size limit\n";
        return;
    }

    std::string final_json;
    try {
        auto json_val = InputValidator::safe_parse_json(message_json);
        if (!json_val.is_object()) return;
        auto& obj = json_val.as_object();
        
        json::object clean_msg;
        if (obj.contains("type")) clean_msg["type"] = obj["type"];
        clean_msg["body"] = obj["body"];
        if (obj.contains("pow")) clean_msg["pow"] = obj["pow"];
        
        final_json = json::serialize(clean_msg);
        if (final_json.size() < REQUIRED_PACKET_SIZE) {
            json::object padded_obj = clean_msg;
            TrafficNormalizer::pad_json(padded_obj, REQUIRED_PACKET_SIZE);
            final_json = json::serialize(padded_obj);
        }
    } catch (...) {
        return;
    }

    size_t recipient_count = recipients.size();
    if (recipient_count > 100) {
        std::cerr << "[!] Multicast recipients truncated from " << recipient_count << " to 100\n";
        recipient_count = 100; // Hard limit on fan-out for stability
    }

    std::vector<std::string> remote_recipients;
    for (size_t i = 0; i < recipient_count; ++i) {
        const auto& recipient_hash = recipients[i];
        if (recipient_hash.empty()) continue;
        std::string safe_to = InputValidator::sanitize_field(recipient_hash, 256);
        
        auto conn = conn_manager_.get_connection(safe_to);
        if (conn) {
            try {
                thread_local std::mt19937 gen{std::random_device{}()};
                std::uniform_int_distribution<> dis(10, 50);
                
                auto timer = std::make_shared<boost::asio::steady_timer>(conn->get_executor());
                timer->expires_after(std::chrono::milliseconds(dis(gen)));
                
                timer->async_wait([conn, final_json, timer](const boost::system::error_code& ec) {
                    if (!ec) {
                        conn->send_text(final_json);
                    }
                });
            } catch(...) {}
        } else {
            remote_recipients.push_back(safe_to);
        }
    }

    if (!remote_recipients.empty()) {
        redis_.publish_multicast(remote_recipients, final_json);
        for (const auto& r : remote_recipients) {
            redis_.store_offline_message(r, final_json);
        }
    }
}

// Complex relay for heterogeneous group payloads.
void MessageRelay::relay_group_message(const boost::json::array& targets,
                                      std::shared_ptr<WebSocketSession> sender) {
    size_t target_count = targets.size();
    if (target_count > 100) {
        std::cerr << "[!] Group multicast targets truncated from " << target_count << " to 100\n";
        target_count = 100;
    }

    for (size_t i = 0; i < target_count; ++i) {
        const auto& target_val = targets[i];
        try {
            if (!target_val.is_object()) continue;
            auto& target_obj = target_val.as_object();
            
            if (!target_obj.contains("to") || !target_obj.contains("body")) continue;
            
            std::string to = std::string(target_obj.at("to").as_string());
            std::string safe_to = InputValidator::sanitize_field(to, 256);
            
            json::object clean_msg;
            clean_msg["type"] = "sealed_message";
            clean_msg["body"] = target_obj.at("body");
            clean_msg["sender"] = sender->get_user_data();
            if (target_obj.contains("msg_type")) clean_msg["msg_type"] = target_obj.at("msg_type");
            
            std::string final_json = json::serialize(clean_msg);
            if (final_json.size() < REQUIRED_PACKET_SIZE) {
                TrafficNormalizer::pad_json(clean_msg, REQUIRED_PACKET_SIZE);
                final_json = json::serialize(clean_msg);
            }

            auto conn = conn_manager_.get_connection(safe_to);
            if (conn) {
                try { conn->send_text(final_json); } catch(...) {}
            } else {
                redis_.publish_message(safe_to, final_json);
                redis_.store_offline_message(safe_to, final_json);
            }
        } catch (...) {}
    }
}

// Acknowledges heartbeats/dummies with an equally sized response.
void MessageRelay::handle_dummy(std::shared_ptr<WebSocketSession> sender) {
    auto ack = std::make_shared<json::object>();
    (*ack)["type"] = "dummy_ack";
    (*ack)["timestamp"] = std::time(nullptr);
    TrafficNormalizer::pad_json(*ack, SYSTEM_MSG_PADDING); 
    
    thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<> dis(10, 50);
    
    auto timer = std::make_shared<boost::asio::steady_timer>(sender->get_executor());
    timer->expires_after(std::chrono::milliseconds(dis(gen)));
    
    std::string ack_str = json::serialize(*ack);
    timer->async_wait([sender, ack_str, timer](const boost::system::error_code& ec) {
        if (!ec) {
            sender->send_text(ack_str);
        }
    });
}

// Fetches and drains stored messages from Redis for a newly reconnected user.
void MessageRelay::deliver_pending(const std::string& recipient_hash,
                                   std::shared_ptr<WebSocketSession> recipient) {
    auto raw_messages = redis_.retrieve_offline_messages(recipient_hash);
    if (raw_messages.empty()) return;
    
    int64_t mock_id = 1;
    int message_index = 0;
    const int pacing_interval_ms = 10; // "Media gear" catch-up speed for offline messages
    
    for (const auto& msg_json : raw_messages) {
        try {
            json::object wrapper;
            wrapper["type"] = "queued_message";
            wrapper["id"] = mock_id++; 
            try {
                wrapper["payload"] = InputValidator::safe_parse_json(msg_json);
            } catch(...) {
                wrapper["payload"] = msg_json; 
            }
            
            std::string final_payload = json::serialize(wrapper);
            
            // Apply cumulative delay to space messages out
            auto timer = std::make_shared<boost::asio::steady_timer>(recipient->get_executor());
            int delay_ms = (message_index++) * pacing_interval_ms;
            
            // Add slight jitter to the drip to prevent rhythmic analysis
            thread_local std::mt19937 gen{std::random_device{}()};
            std::uniform_int_distribution<> dis(0, 50);
            timer->expires_after(std::chrono::milliseconds(delay_ms + dis(gen)));
            
            timer->async_wait([recipient, final_payload, timer](const boost::system::error_code& ec) {
                if (!ec) {
                    recipient->send_text(final_payload);
                }
            });
        } catch (const std::exception& e) {
            std::cerr << "[!] Failed to prepare pending message: " << e.what() << "\n";
        }
    }
}

}
