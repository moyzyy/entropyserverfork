#include "message_relay.hpp"
#include "websocket_session.hpp"
#include "traffic_normalizer.hpp"
#include <boost/beast/core/detail/base64.hpp>

#include <boost/json.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>
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

static const size_t SYSTEM_MSG_PADDING = 512;

namespace json = boost::json;

namespace entropy {


MessageRelay::MessageRelay(ConnectionManager& conn_manager, RedisManager& redis, RateLimiter& rate_limiter, const ServerConfig& config)
    : conn_manager_(conn_manager), redis_(redis), rate_limiter_(rate_limiter), config_(config) {}



    MessageRelay::RoutingInfo MessageRelay::extract_routing(std::string_view message_json) {
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

void MessageRelay::relay_message(std::string_view message_json, 
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
    
    try {
        auto json_val = InputValidator::safe_parse_json(message_json);
        if (json_val.is_object()) {
            relay_message(json_val.as_object(), sender);
        }
    } catch (const std::exception& e) {
        std::cerr << "[!] Failed to parse incoming message JSON: " << e.what() << "\nInput: " << message_json << "\n";
    } catch (...) {
        std::cerr << "[!] Failed to parse incoming message JSON or depth limit exceeded.\nInput: " << message_json << "\n";
    }
}

void MessageRelay::relay_message(const json::object& obj,
                                std::shared_ptr<WebSocketSession> sender) {
    std::string type;
    if (obj.contains("type") && obj.at("type").is_string()) {
        type = std::string(obj.at("type").as_string());
    }
    
    std::string to;
    if (obj.contains("to") && obj.at("to").is_string()) {
        to = std::string(obj.at("to").as_string());
    }

    if (type == "ping" || type == "dummy" || type == "dummy_pacing") {
        handle_dummy(sender);
        return;
    }

    if (to.empty()) {
        std::cerr << "[!] Message delivery aborted: No recipient identifier provided\n";
        return;
    }
    
    std::string safe_to = InputValidator::sanitize_field(to, 64);
    if (safe_to.empty()) return;

    json::object clean_msg;
    static const std::vector<std::string> ALLOWED_FIELDS = {
        "type", "payload", "identity_hash", "signature", "req_id", "content", "ts",
        "fragmentId", "index", "total", "data", "bundle", "body", "id", "pow",
        "pq_ciphertext", "sender_identity_key", "ephemeral_key", "target_hash"
    };
    
    for (const auto& field : ALLOWED_FIELDS) {
        if (obj.contains(field)) clean_msg[field] = obj.at(field);
    }
    
    clean_msg["sender"] = sender->get_user_data();
    std::string final_json = json::serialize(clean_msg);

    // Normalize size to config pacing size for traffic analysis resistance
    TrafficNormalizer::pad_serialized_json(final_json, config_.pacing.packet_size);

    bool is_media = (type == "voice" || type == "video" || type == "signal" || type == "msg_fragment");

    // Offload Rate Limiting Check to Blocking Pool to avoid stalling IO threads
    auto blocking_exec = redis_.get_blocking_executor();
    net::post(blocking_exec, [this, safe_to, final_json, sender, is_media]() {
        auto rcv_limit = rate_limiter_.check("rcv:" + safe_to, 1000, 10); 
        
        if (!rcv_limit.allowed) {
            MetricsRegistry::instance().increment_counter("recipient_flood_blocked");
            return; 
        }
        net::post(sender->get_executor(), [this, safe_to, final_json, sender, is_media]() {
            auto recipient = conn_manager_.get_connection(safe_to);
             if (recipient) {
                auto timer = std::make_shared<boost::asio::steady_timer>(sender->get_executor());
                
                static thread_local std::mt19937 gen{std::random_device{}()};
                std::uniform_int_distribution<int> dis(10, 50);
                int delay_ms = dis(gen);
                
                timer->expires_after(std::chrono::milliseconds(delay_ms));
                timer->async_wait([recipient, final_json, is_media, timer](const boost::system::error_code& ec) {
                    if (!ec) {
                        recipient->send_text(std::move(final_json), is_media);
                    }
                });
            } else {
                auto blocking_exec = redis_.get_blocking_executor();
                net::post(blocking_exec, [this, safe_to, final_json, sender]() {
                    bool stored = redis_.store_offline_message(safe_to, final_json);
                    
                    net::post(sender->get_executor(), [this, sender, safe_to, stored]() {
                        json::object response;
                        if (stored) {
                            response["type"] = "delivery_status";
                            response["target"] = safe_to;
                            response["status"] = "relayed";
                        } else {
                            MetricsRegistry::instance().increment_counter("storage_failure");
                            response["type"] = "error";
                            response["code"] = "storage_failed";
                            response["message"] = "Recipient offline and storage unavailable";
                        }
                        
                        std::string res_str = json::serialize(response);
                        TrafficNormalizer::pad_serialized_json(res_str, config_.pacing.packet_size);
                        sender->send_text(std::move(res_str), false); 
                    });
                });
            }
        });
    });
}

void MessageRelay::relay_binary(std::string_view recipient_hash, const void* data, size_t length,
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
            
            std::string delivered_payload;
            size_t required_size = std::max(config_.pacing.packet_size, sender_hash.size() + length);
            delivered_payload.reserve(required_size);
            
            delivered_payload += sender_hash;
            delivered_payload.append(static_cast<const char*>(data), length);
            
            // Binary normalization (padding to multiple of packet_size)
            TrafficNormalizer::pad_binary(delivered_payload, config_.pacing.packet_size);
            
            recipient->send_binary(delivered_payload, true); // Binary is always paced like media
            
            json::object response;
            response["type"] = "relay_success";
            response["status"] = "relayed";
            std::string res_str = json::serialize(response);
            TrafficNormalizer::pad_serialized_json(res_str, config_.pacing.packet_size);
            sender->send_text(std::move(res_str));
        } catch (const std::exception& e) {
            std::cerr << "[!] Binary relay failure: " << e.what() << "\n";
        }
    } else {
        std::string binary_data(static_cast<const char*>(data), length);
        json::object wrapper;
        wrapper["type"] = "binary_payload";
        wrapper["sender"] = sender->get_user_data(); 
        //optimization possible??
        namespace base64 = boost::beast::detail::base64;
        std::string b64_data;
        b64_data.resize(base64::encoded_size(binary_data.size()));
        size_t enc_bytes = base64::encode(b64_data.data(), binary_data.data(), binary_data.size());
        b64_data.resize(enc_bytes);
        
        wrapper["data_b64"] = b64_data;
        std::string wrapper_str = json::serialize(wrapper);
        
        auto exec = redis_.get_blocking_executor();
        net::post(exec, [this, safe_hash, wrapper_str, sender]() {
            redis_.store_offline_message(safe_hash, wrapper_str);
            
            net::post(sender->get_executor(), [this, sender, safe_hash]() {
                json::object response;
                response["type"] = "delivery_status";
                response["target"] = safe_hash;
                response["status"] = "relayed";
                std::string res_str = json::serialize(response);
                TrafficNormalizer::pad_serialized_json(res_str, config_.pacing.packet_size);
                sender->send_text(std::move(res_str), false); // Standard paced ack
            });
        });
    }
}

void MessageRelay::relay_volatile(std::string_view recipient_hash, const void* data, size_t length,
                                   std::shared_ptr<WebSocketSession> sender) {
    std::string safe_hash = InputValidator::sanitize_field(recipient_hash, 256);
    if (safe_hash.empty()) return;

    auto recipient = conn_manager_.get_connection(safe_hash);
    if (recipient) {
        try {
            std::string sender_hash = sender ? sender->get_user_data() : std::string(64, '0');
            std::string delivered_payload = sender_hash + std::string(static_cast<const char*>(data), length);
            TrafficNormalizer::pad_binary(delivered_payload, config_.pacing.packet_size);
            
            recipient->send_binary(delivered_payload, true);
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
    }
}

void MessageRelay::handle_dummy(std::shared_ptr<WebSocketSession> sender) {
    auto ack = std::make_shared<json::object>();
    (*ack)["type"] = "dummy_ack";
    (*ack)["timestamp"] = std::time(nullptr);
    std::string ack_json = json::serialize(*ack);
    TrafficNormalizer::pad_serialized_json(ack_json, SYSTEM_MSG_PADDING);
    sender->send_text(std::move(ack_json), false);
}

void MessageRelay::deliver_pending(const std::string& recipient_hash,
                                   std::shared_ptr<WebSocketSession> recipient) {
    auto exec = redis_.get_blocking_executor();
    net::post(exec, [this, recipient_hash, recipient]() {
        auto raw_messages = redis_.retrieve_offline_messages(recipient_hash);
        if (raw_messages.empty()) return;
        
        int64_t mock_id = 1;
        int message_count = 0;
        
        for (const auto& msg_json : raw_messages) {
            if (message_count >= config_.offline_msg_limit) break; 

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
                recipient->send_text(std::move(final_payload), true); // Batch through pacing queue
            } catch (...) {}
        }
    });
}

}
