#include "pow_verifier.hpp"
#include "http_session.hpp"
#include "websocket_session.hpp"
#include "connection_manager.hpp"
#include "message_relay.hpp"
#include "rate_limiter.hpp"
#include "metrics.hpp"
#include "security_logger.hpp"
#include "input_validator.hpp"
#include "traffic_normalizer.hpp"
#include <boost/json.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include "input_validator.hpp"

namespace json = boost::json;

namespace entropy {



    /**
     * HTTPS Session state (TLS transport).
     * Initializes the encrypted stream and extracts the peer identity for logging.
     */
    HttpSession::HttpSession(
        beast::ssl_stream<beast::tcp_stream>&& stream,
        const ServerConfig& config,
        ConnectionManager& conn_manager,
        MessageRelay& relay,
        RateLimiter& rate_limiter,
        KeyStorage& key_storage,
        RedisManager& redis,
        std::shared_ptr<void> conn_guard
    )
    : stream_(std::move(stream))
    , is_tls_(true)
    , config_(config)
    , conn_manager_(conn_manager)
    , relay_(relay)
    , rate_limiter_(rate_limiter)
    , key_storage_(key_storage)
    , redis_(redis)
    , health_handler_(config, conn_manager)
    , identity_handler_(config, key_storage, redis, rate_limiter)
    , conn_guard_(std::move(conn_guard))
{
    try {
        auto& s = std::get<beast::ssl_stream<beast::tcp_stream>>(stream_);
        auto ep = beast::get_lowest_layer(s).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
}

// Plaintext HTTP Session state (usually behind a local proxy or for testing)
HttpSession::HttpSession(
    beast::tcp_stream&& stream,
    const ServerConfig& config,
    ConnectionManager& conn_manager,
    MessageRelay& relay,
    RateLimiter& rate_limiter,
    KeyStorage& key_storage,
    RedisManager& redis,
    std::shared_ptr<void> conn_guard
)
    : stream_(std::move(stream))
    , is_tls_(false)
    , config_(config)
    , conn_manager_(conn_manager)
    , relay_(relay)
    , rate_limiter_(rate_limiter)
    , key_storage_(key_storage)
    , redis_(redis)
    , health_handler_(config, conn_manager)
    , identity_handler_(config, key_storage, redis, rate_limiter)
    , conn_guard_(std::move(conn_guard))
{
    try {
        auto& s = std::get<beast::tcp_stream>(stream_);
        auto ep = beast::get_lowest_layer(s).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
}

void HttpSession::run() {
    if (is_tls_) {
        auto self = shared_from_this();
        std::get<beast::ssl_stream<beast::tcp_stream>>(stream_).async_handshake(
            ssl::stream_base::server,
            [self](beast::error_code ec) {
                self->on_handshake(ec);
            });
    } else {
        do_read();
    }
}

void HttpSession::on_handshake(beast::error_code ec) {
    if (ec) {
        // Silent closure on handshake failure to prevent resource exhaustion from scanners
        return;
    }
    do_read();
}

void HttpSession::do_read() {
    req_ = {};
    
    if (is_tls_) {
        beast::get_lowest_layer(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_)).expires_after(
            std::chrono::seconds(60)); 
    } else {
        beast::get_lowest_layer(std::get<beast::tcp_stream>(stream_)).expires_after(
            std::chrono::seconds(60)); 
    }
    
    auto self = shared_from_this();
    parser_.emplace();
    parser_->body_limit(config_.max_message_size);

    if (is_tls_) {
        http::async_read(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_), buffer_, *parser_,
            [self](beast::error_code ec, std::size_t bytes) { self->on_read(ec, bytes); });
    } else {
        http::async_read(std::get<beast::tcp_stream>(stream_), buffer_, *parser_,
            [self](beast::error_code ec, std::size_t bytes) { self->on_read(ec, bytes); });
    }
}

void HttpSession::on_read(beast::error_code ec, std::size_t  ) {
    if (ec == http::error::end_of_stream || ec) return;
    
    req_ = parser_->release();
    
    std::string b_ip = blind_ip(remote_addr_);
    auto limit_res = rate_limiter_.check("global:" + b_ip, config_.global_rate_limit, 10);
    if (!limit_res.allowed) {
        send_response(handle_rate_limited(limit_res));
        return;
    }
    
    handle_request();
}

void HttpSession::handle_request() {
    if (websocket::is_upgrade(req_)) {
        upgrade_to_websocket();
        return;
    }
    
    auto target = req_.target();
    auto method = req_.method();
    
    if (method == http::verb::options) {
        send_response(handle_cors_preflight());
        return;
    }
    
    if (target == "/health" && method == http::verb::get) {
        send_response(health_handler_.handle_health(req_.version()));
    } else if (target == "/stats" && method == http::verb::get) {
        bool is_local = (remote_addr_ == "127.0.0.1" || remote_addr_ == "::1");
        if (is_local || health_handler_.verify_admin_request(req_)) {
            send_response(health_handler_.handle_stats(req_));
        } else {
            send_response(handle_not_found());
        }
    } else if (target == "/metrics" && method == http::verb::get) {
         bool is_local = (remote_addr_ == "127.0.0.1" || remote_addr_ == "::1");
         if (is_local || health_handler_.verify_admin_request(req_)) {
            send_response(health_handler_.handle_metrics(req_.version()));
        } else {
            send_response(handle_not_found());
        }
    } else {
        send_response(handle_not_found());
    }
}

std::string HttpSession::blind_ip(const std::string& ip) {
    std::string data = ip + config_.secret_salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Relays a single message to a target recipient.
// Requires PoW bound to the recipient hash to prevent spam-flooding specific accounts.

http::response<http::string_body> HttpSession::handle_cors_preflight() {
    http::response<http::string_body> res{http::status::no_content, req_.version()};
    add_cors_headers(res);
    res.prepare_payload();
    return res;
}

http::response<http::string_body> HttpSession::handle_not_found() {
    SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT, remote_addr_, "404 Not Found: " + std::string(req_.target()));
    json::object response;
    response["error"] = "Not Found";
    
    http::response<http::string_body> res{http::status::not_found, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res);
    
    return res;
}

http::response<http::string_body> HttpSession::handle_rate_limited(const RateLimitResult& res_info) {
    json::object response;
    response["error"] = "Rate limit exceeded";
    response["retry_after"] = res_info.reset_after_sec;
    response["limit"] = res_info.limit;
    
    http::response<http::string_body> res{http::status::too_many_requests, req_.version()};
    res.set(http::field::content_type, "application/json");
    res.set(http::field::retry_after, std::to_string(res_info.reset_after_sec));
    
    
    res.set("X-RateLimit-Limit", std::to_string(res_info.limit));
    res.set("X-RateLimit-Remaining", "0");
    res.set("X-RateLimit-Reset", std::to_string(std::time(nullptr) + res_info.reset_after_sec));
    
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    if (res_info.reset_after_sec >= 60) {
        res.keep_alive(false);
    }
    
    add_security_headers(res);
    add_cors_headers(res); 
    
    return res;
}



template<class Body>
void HttpSession::add_security_headers(http::response<Body>& res) {
    res.set(http::field::server, "Entropy/2.0");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("X-Frame-Options", "DENY");
    res.set("X-XSS-Protection", "1; mode=block");
    res.set("Referrer-Policy", "strict-origin-when-cross-origin");
    res.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    res.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    
    if (config_.enable_tls) {
        res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
}

template<class Body>
void HttpSession::add_cors_headers(http::response<Body>& res) {
    std::string origin;
    auto origin_it = req_.find(http::field::origin);
    if (origin_it != req_.end()) {
        origin = std::string(origin_it->value());
    }
    
    if (!config_.allowed_origins.empty()) {
        bool origin_allowed = false;
        for (const auto& allowed : config_.allowed_origins) {
            if (allowed == "*" || allowed == origin) {
                origin_allowed = true;
                if (allowed == "*" && !origin.empty()) {
                    res.set(http::field::access_control_allow_origin, origin);
                } else {
                    res.set(http::field::access_control_allow_origin, allowed);
                }
                break;
            }
        }
        
        if (origin_allowed) {
            res.set(http::field::access_control_allow_credentials, "true");
        } 
    } 
    
    //for local development and Tauri apps
    if (!res.count(http::field::access_control_allow_origin) && !origin.empty()) {
        if (origin.find("localhost") != std::string::npos || 
            origin.find("tauri://") != std::string::npos || 
            origin.find("127.0.0.1") != std::string::npos) {
            res.set(http::field::access_control_allow_origin, origin);
            res.set(http::field::access_control_allow_credentials, "true");
        } else if (!config_.allowed_origins.empty()) {
            // Only log if we have a whitelist and the origin isn't local either
            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                               remote_addr_, "Disallowed origin: " + origin);
        }
    }
    
    res.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
    res.set(http::field::access_control_allow_headers, "Content-Type,Authorization,X-PoW-Seed,X-PoW-Nonce,x-pow-seed,x-pow-nonce,X-Admin-Token,X-Identity,X-Signature,X-Timestamp");
    res.set(http::field::access_control_max_age, "86400");
    res.set(http::field::vary, "Origin");
}

void HttpSession::send_response(http::response<http::string_body>&& res) {
    auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));
    
    auto self = shared_from_this();
    
    if (is_tls_) {
        http::async_write(
            std::get<beast::ssl_stream<beast::tcp_stream>>(stream_),
            *sp,
            [self, sp](beast::error_code ec, std::size_t bytes) {
                self->on_write(sp->need_eof(), ec, bytes);
            });
    } else {
        http::async_write(
            std::get<beast::tcp_stream>(stream_),
            *sp,
            [self, sp](beast::error_code ec, std::size_t bytes) {
                self->on_write(sp->need_eof(), ec, bytes);
            });
    }
}

void HttpSession::on_write(bool close, beast::error_code ec, std::size_t  ) {
    if (ec) {
        std::cerr << "[!] HTTP write error: " << ec.message() << "\n";
        return;
    }
    
    if (close) {
        
        if (is_tls_) {
            beast::get_lowest_layer(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_)).socket().shutdown(
                tcp::socket::shutdown_send, ec);
        } else {
            beast::get_lowest_layer(std::get<beast::tcp_stream>(stream_)).socket().shutdown(
                tcp::socket::shutdown_send, ec);
        }
        return;
    }
    
    
    do_read();
}


// Transitions the HTTP session to a long-lived WebSocket session.
void HttpSession::upgrade_to_websocket() {
    std::shared_ptr<WebSocketSession> ws_session;
    
    if (is_tls_) {
        ws_session = std::make_shared<WebSocketSession>(
            std::move(std::get<beast::ssl_stream<beast::tcp_stream>>(stream_)),
            conn_manager_,
            config_
        );
    } else {
         ws_session = std::make_shared<WebSocketSession>(
            std::move(std::get<beast::tcp_stream>(stream_)),
            conn_manager_,
            config_
        );
    }
    
    ws_session->set_conn_guard(std::move(conn_guard_));
    
    
    MessageRelay* relay_ptr = &relay_;
    ConnectionManager* conn_mgr_ptr = &conn_manager_;
    RateLimiter* rate_limiter_ptr = &rate_limiter_;
    RedisManager* redis_ptr = &redis_;
    IdentityHandler* identity_handler_ptr = &identity_handler_;
    
    
    size_t max_conns = config_.max_connections_per_ip;
    size_t max_msg_size = 5 * 1024 * 1024; 

    ws_session->set_message_handler(
        [relay_ptr, conn_mgr_ptr, rate_limiter_ptr, redis_ptr, identity_handler_ptr, key_storage_ptr = &key_storage_, max_conns, max_msg_size](
            std::shared_ptr<WebSocketSession> session,
            const std::string& data,
            bool is_binary
        ) {
            auto b_ip = conn_mgr_ptr->blind_id(session->remote_address());
            int max_msgs = session->is_authenticated() ? 1000 : 50;
            auto limit_res = rate_limiter_ptr->check("ws_msg:" + b_ip, max_msgs, 10);
            if (!limit_res.allowed) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT,
                                  session->remote_address(), "WebSocket rate limit exceeded");
                session->close();
                return;
            }

            if (data.size() > max_msg_size) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                                  session->remote_address(), "Message exceeds size limit");
                session->close();
                return;
            }
            
            if (is_binary) {
                if (!session->is_challenge_solved()) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      session->remote_address(), "Unauthenticated binary relay attempt");
                    session->close();
                    return;
                }
                
                if (data.size() > 64) {
                    std::string recipient = data.substr(0, 64);
                    relay_ptr->relay_binary(
                        recipient,
                        data.data() + 64,
                        data.size() - 64,
                        session
                    );
                }
                return;
            }
            
            
            try {
                auto json_val = InputValidator::safe_parse_json(data);
                if (!json_val.is_object()) {
                    SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                                      session->remote_address(), "Invalid JSON structure");
                    return;
                }
                
                auto& obj = json_val.as_object();
                std::string type;
                if (obj.contains("type")) {
                    type = std::string(obj["type"].as_string());
                }
                
                
                if (type == "ping") {
                    json::object pong;
                    pong["type"] = "pong";
                    if (obj.contains("timestamp")) pong["timestamp"] = obj["timestamp"];
                    TrafficNormalizer::pad_json(pong, 1536);
                    session->send_text(json::serialize(pong));
                    return;
                }

                if (type == "pow_challenge") {
                    auto res = identity_handler_ptr->handle_pow_challenge_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "fetch_key_random") {
                    auto res = identity_handler_ptr->handle_keys_random_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "keys_upload") {
                    auto res = identity_handler_ptr->handle_keys_upload_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "fetch_key") {
                    auto res = identity_handler_ptr->handle_keys_fetch_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "nickname_lookup") {
                    auto res = identity_handler_ptr->handle_nickname_lookup_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "nickname_register") {
                    auto res = identity_handler_ptr->handle_nickname_register_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "account_burn") {
                    auto res = identity_handler_ptr->handle_account_burn_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "link_preview") {
                    auto res = identity_handler_ptr->handle_link_preview_ws(obj, session->remote_address());
                    TrafficNormalizer::pad_json(res, 1536);
                    session->send_text(json::serialize(res));
                    return;
                }

                if (type == "dummy" || type == "dummy_pacing") {
                    return; 
                }

                if (type == "auth") {
                    if (obj.contains("payload")) {
                        auto& auth_payload = obj["payload"].as_object();
                        
                        std::string id_hash;
                        if (auth_payload.contains("identity_hash")) id_hash = std::string(auth_payload["identity_hash"].as_string());
                        std::string hash = InputValidator::sanitize_field(id_hash, 256);

                        bool auth_valid = false;

                        
                        if (auth_payload.contains("session_token") && auth_payload["session_token"].is_string()) {
                            std::string token = std::string(auth_payload["session_token"].as_string());
                            if (redis_ptr->verify_session_token(hash, token)) {
                                auth_valid = true;
                            }
                        }

                        
                        if (!auth_valid) {
                            std::string seed;
                            if (auth_payload.contains("seed") && auth_payload["seed"].is_string()) 
                                seed = std::string(auth_payload["seed"].as_string());
                            
                            std::string nonce;
                            if (auth_payload.contains("nonce")) {
                                if (auth_payload["nonce"].is_string()) nonce = std::string(auth_payload["nonce"].as_string());
                                else if (auth_payload["nonce"].is_number()) nonce = std::to_string(auth_payload["nonce"].as_int64());
                            }
                            
                            
                            int intensity_penalty = 0;
                            int intensity = redis_ptr->get_registration_intensity();
                            if (intensity > 10) intensity_penalty = 2;
                            if (intensity > 50) intensity_penalty = 4;
                            if (intensity > 200) intensity_penalty = 8;
                            
                            long long age = redis_ptr->get_account_age(hash);
                            int required_difficulty = ::entropy::PoWVerifier::get_required_difficulty(intensity_penalty, age);

                            if (!seed.empty() && !nonce.empty() && rate_limiter_ptr->consume_challenge(seed) && 
                                ::entropy::PoWVerifier::verify(seed, nonce, hash, required_difficulty)) {
                                auth_valid = true;
                            }
                        }

                        if (!auth_valid || hash.empty()) {
                             SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                               session->remote_address(), "Authentication failed");
                             
                             json::object error;
                             error["type"] = "error";
                             error["code"] = "auth_failed";
                             error["message"] = "Authentication failed. Token may be expired.";
                             TrafficNormalizer::pad_json(error, 1536);
                             session->send_text(json::serialize(error));
                             
                             session->close();
                             return;
                        }
                      
                        if (!conn_mgr_ptr->add_connection_with_limit(hash, session, session->remote_address(), max_conns)) {
                            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT,
                                              session->remote_address(), "Connection limit exceeded for IP");
                            json::object error;
                            error["type"] = "error";
                            error["code"] = "connection_limit";
                            error["message"] = "Too many connections from your IP address";
                            TrafficNormalizer::pad_json(error, 1536);
                            session->send_text(json::serialize(error));
                            session->close();
                            return;
                        }
                        
                        session->set_user_data(hash);
                        session->set_challenge_solved(true);
                        session->set_authenticated(true);
                        
                        relay_ptr->subscribe_user(hash);
                        
                        SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                                          session->remote_address(), "User authenticated");

                        
                        std::string new_token = redis_ptr->create_session_token(hash, 3600);

                        json::object response;
                        response["type"] = "auth_success";
                        response["identity_hash"] = hash;
                        if (!new_token.empty()) response["session_token"] = new_token;
                        
                        
                        response["keys_missing"] = key_storage_ptr->get_bundle(hash).empty();
                        
                        TrafficNormalizer::pad_json(response, 1536);
                        session->send_text(json::serialize(response));
                        
                        relay_ptr->deliver_pending(hash, session);
                    }
                    return;
                }

                if (!session->is_challenge_solved()) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      session->remote_address(), "Unauthenticated message attempt: " + type);
                    session->close();
                    return;
                }

                if (type == "ack") {
                    if (obj.contains("ids") && obj["ids"].is_array()) {
                        std::vector<int64_t> ids;
                        for (const auto& id_val : obj["ids"].as_array()) {
                            if (id_val.is_int64()) {
                                ids.push_back(id_val.as_int64());
                            }
                        }
                        relay_ptr->confirm_delivery(ids);
                    }
                    return;
                }

                if (type == "subscribe_alias") {
                    if (obj.contains("payload")) {
                        try {
                            auto& alias_payload = obj["payload"].as_object();
                            std::string seed;
                            if (alias_payload.contains("seed") && alias_payload["seed"].is_string()) 
                                seed = std::string(alias_payload["seed"].as_string());
                            
                            std::string nonce;
                            if (alias_payload.contains("nonce")) {
                                if (alias_payload["nonce"].is_string()) nonce = std::string(alias_payload["nonce"].as_string());
                                else if (alias_payload["nonce"].is_number()) nonce = std::to_string(alias_payload["nonce"].as_int64());
                            }

                            
                            if (alias_payload.contains("alias") && alias_payload["alias"].is_string()) {
                                std::string alias = std::string(alias_payload["alias"].as_string());
                                std::string safe_alias = InputValidator::sanitize_field(alias, 256);

                                if (seed.empty() || nonce.empty() || !rate_limiter_ptr->consume_challenge(seed) || 
                                    !::entropy::PoWVerifier::verify(seed, nonce, safe_alias)) {
                                     SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::AUTH_FAILURE,
                                                       session->remote_address(), "Alias subscription PoW invalid or unbound: " + safe_alias);
                                     session->close();
                                     return;
                                }

                                if (!safe_alias.empty() && session->can_add_alias()) {
                                    session->add_alias(safe_alias);
                                    conn_mgr_ptr->add_connection(safe_alias, session);
                                    relay_ptr->subscribe_user(safe_alias);
                                    relay_ptr->deliver_pending(safe_alias, session);
                                    
                                    json::object response;
                                    response["type"] = "alias_subscribed";
                                    response["alias"] = safe_alias;
                                    TrafficNormalizer::pad_json(response, 1536);
                                    session->send_text(json::serialize(response));
                                } else if (!safe_alias.empty()) {
                                    json::object error;
                                    error["type"] = "error";
                                    error["message"] = "Maximum alias limit reached";
                                    session->send_text(json::serialize(error));
                                }
                            }
                        } catch (...) {}
                    }
                    return;
                }

                if (type == "volatile_relay") {
                    if (obj.contains("to") && obj.contains("body")) {
                        std::string to = std::string(obj["to"].as_string());
                        std::string body = std::string(obj["body"].as_string());
                        
                        relay_ptr->relay_volatile(to, body.data(), body.size(), session);
                    }
                    return;
                }



                if (type == "group_multicast") {
                    if (!session->is_authenticated()) {
                        json::object err;
                        err["type"] = "error";
                        err["message"] = "Authentication required for multicast";
                        session->send_text(json::serialize(err));
                        return;
                    }
                    if (obj.contains("targets") && obj["targets"].is_array()) {
                        auto& targets = obj["targets"].as_array();
                        int cost = static_cast<int>(targets.size());
                        auto limit_res = rate_limiter_ptr->check("ws_multi:" + b_ip, 500, 60, cost);
                        
                        if (!limit_res.allowed) {
                            json::object err;
                            err["type"] = "error";
                            err["code"] = "rate_limit";
                            err["message"] = "Multicast rate limit exceeded";
                            session->send_text(json::serialize(err));
                            return;
                        }
                        
                        relay_ptr->relay_group_message(targets, session);
                    }
                    return;
                }

                relay_ptr->relay_message(data, session);
                
            } catch (const std::exception& e) {
                std::cerr << "[!] Error processing message: " << e.what() << "\n";
            }
        });
    
    
    ws_session->set_close_handler(
        [conn_mgr_ptr, relay_ptr](WebSocketSession* session) {
            std::string user_data = session->get_user_data();
            if (!user_data.empty()) {
                relay_ptr->unsubscribe_user(user_data);
            }
            for (const auto& alias : session->get_aliases()) {
                relay_ptr->unsubscribe_user(alias);
            }
            conn_mgr_ptr->remove_session(session);
            std::cout << "[*] WebSocket connection closed\n";
        });
    
    
    
    parser_.reset();
    
    ws_session->accept(
        std::move(req_),
        std::move(buffer_),
        [ws_session](beast::error_code ec) {
            if (ec) {
                std::cerr << "[!] WebSocket accept error: " << ec.message() << "\n";
                return;
            }
            std::cout << "[+] WebSocket accepted successfully\n";
            
            ws_session->run();
        });
}


template void ::entropy::HttpSession::add_security_headers(http::response<http::string_body>&);
template void ::entropy::HttpSession::add_cors_headers(http::response<http::string_body>&);



} 
    