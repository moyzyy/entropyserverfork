#include "websocket_session.hpp"
#include "connection_manager.hpp"
#include "security_logger.hpp" 
#include <iostream>
#include "server_config.hpp"
#include <openssl/sha.h>
#include <random>
#include <shared_mutex>
#include "metrics.hpp"
#include <iomanip>
#include <sstream>

#include "traffic_normalizer.hpp"
#include <boost/json.hpp>

namespace http = boost::beast::http;
namespace json = boost::json;

namespace entropy {


    /**
     * Configures the secure stream with optimized timeouts, keep-alive pacing, and compression.
     */
    WebSocketSession::WebSocketSession(
        beast::ssl_stream<beast::tcp_stream>&& stream,
        ConnectionManager& conn_manager,
        const ServerConfig& config
    )
    : ws_(websocket::stream<beast::ssl_stream<beast::tcp_stream>>(std::move(stream)))
    , is_tls_(true)
    , conn_manager_(conn_manager)
    , config_(config)
{
    try {
        auto& tls_ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        auto ep = beast::get_lowest_layer(tls_ws).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
    
    auto& tls_ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
    
    websocket::stream_base::timeout opt{};
    opt.handshake_timeout = std::chrono::seconds(5);
    opt.idle_timeout = std::chrono::seconds(300);
    opt.keep_alive_pings = true;                   
    tls_ws.set_option(opt);
    
    beast::get_lowest_layer(tls_ws).expires_never();
    
    websocket::permessage_deflate pmd;
    pmd.server_enable = true;
    pmd.client_enable = true;
    tls_ws.set_option(pmd);
    tls_ws.read_message_max(config_.max_message_size); 
    read_buffer_.max_size(config_.max_message_size);
    last_activity_time_ = std::chrono::steady_clock::now();
    last_pacing_time_ = last_activity_time_;    
    blinded_ip_ = conn_manager_.blind_id(remote_addr_);
    update_next_dummy_time();
}

WebSocketSession::WebSocketSession(
    beast::tcp_stream&& stream,
    ConnectionManager& conn_manager,
    const ServerConfig& config
)
    : ws_(websocket::stream<beast::tcp_stream>(std::move(stream)))
    , is_tls_(false)
    , conn_manager_(conn_manager)
    , config_(config)
{
    try {
        auto& plain_ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        auto ep = beast::get_lowest_layer(plain_ws).socket().remote_endpoint();
        remote_addr_ = ep.address().to_string();
    } catch (...) {
        remote_addr_ = "unknown";
    }
    
    auto& plain_ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
    
    websocket::stream_base::timeout opt{};
    opt.handshake_timeout = std::chrono::seconds(5);
    opt.idle_timeout = std::chrono::seconds(300);  
    opt.keep_alive_pings = true;                   
    plain_ws.set_option(opt);
    
    // Disable underlying socket-level timeout to let WebSocket layer handle it
    beast::get_lowest_layer(plain_ws).expires_never();
    
    websocket::permessage_deflate pmd;
    pmd.server_enable = true;
    pmd.client_enable = true;
    plain_ws.set_option(pmd);
    
    plain_ws.read_message_max(config_.max_message_size); 
    read_buffer_.max_size(config_.max_message_size);
    last_activity_time_ = std::chrono::steady_clock::now();
    last_pacing_time_ = last_activity_time_;
    
    blinded_ip_ = conn_manager_.blind_id(remote_addr_);
    update_next_dummy_time();
}

WebSocketSession::~WebSocketSession() {
    trigger_close_handler();
}

void WebSocketSession::update_next_dummy_time() {
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<> dis(config_.dummy.min_interval_s, config_.dummy.max_interval_s);
    auto delay = std::chrono::seconds(dis(gen));
    next_dummy_time_ = std::chrono::steady_clock::now() + delay;
}

void WebSocketSession::check_dummy_traffic() {
    if (!config_.dummy.enabled || close_triggered_) return;
    
    auto now = std::chrono::steady_clock::now();
    
    if (now >= next_dummy_time_) {
        static const std::string DUMMY_TYPE = "dummy_random";
        json::object dummy_msg;
        dummy_msg["type"] = DUMMY_TYPE;
        dummy_msg["ts"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        
        std::string payload = json::serialize(dummy_msg);
        TrafficNormalizer::pad_serialized_json(payload, config_.pacing.packet_size);
        
        send_text(std::move(payload), false);
        
        update_next_dummy_time();
    }
}

// Utility to get the appropriate executor from the variant stream
net::any_io_executor WebSocketSession::get_executor() {
    if (is_tls_) {
        return std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_)
            .get_executor();
    } else {
        return std::get<websocket::stream<beast::tcp_stream>>(ws_)
            .get_executor();
    }
}

template<class Body, class Allocator>
void WebSocketSession::accept(
    http::request<Body, http::basic_fields<Allocator>>&& req,
    beast::flat_buffer&& buffer,
    std::function<void(beast::error_code)> on_accept
) {
    auto self = shared_from_this();
    read_buffer_ = std::move(buffer);

    auto req_ptr = std::make_shared<http::request<Body, http::basic_fields<Allocator>>>(std::move(req));
    auto handler = [self, on_accept, req_ptr](beast::error_code ec) {
        if (ec) {
            SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, self->remote_addr_, "WebSocket async_accept error: " + ec.message());
        }
        if (on_accept) on_accept(ec);
    };
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.async_accept(*req_ptr, handler);
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.async_accept(*req_ptr, handler);
    }
}


template void WebSocketSession::accept<http::string_body, std::allocator<char>>(
    http::request<http::string_body, http::basic_fields<std::allocator<char>>>&& req,
    beast::flat_buffer&& buffer,
    std::function<void(beast::error_code)> on_accept
);

void WebSocketSession::set_user_data(std::string_view data) {
    user_data_ = data;
    if (!user_data_.empty()) {
        blinded_user_id_ = conn_manager_.blind_id(user_data_);
    } else {
        blinded_user_id_.clear();
    }
}

void WebSocketSession::run() {
    do_read(); 
}


void WebSocketSession::do_read() {
    auto self = shared_from_this();
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.async_read(
            read_buffer_,
            [self](beast::error_code ec, std::size_t bytes) {
                self->on_read(ec, bytes);
            });
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.async_read(
            read_buffer_,
            [self](beast::error_code ec, std::size_t bytes) {
                self->on_read(ec, bytes);
            });
    }
}

void WebSocketSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    last_activity_time_ = std::chrono::steady_clock::now();
    
    if (ec == websocket::error::closed) {
        trigger_close_handler();
        return;
    }
    
    if (ec) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, 
                           SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                           remote_addr_, 
                           "WS Read Error: " + ec.message());
        trigger_close_handler();
        return;
    }
    
    std::string message = beast::buffers_to_string(beast::buffers_prefix(bytes_transferred, read_buffer_.data()));
    
    bool is_binary = false;
    if (is_tls_) {
        is_binary = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_).got_binary();
    } else {
        is_binary = std::get<websocket::stream<beast::tcp_stream>>(ws_).got_binary();
    }
    
    read_buffer_.consume(bytes_transferred);
    
    // Enforce padded packet sizes
    if (bytes_transferred % config_.pacing.packet_size != 0) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, 
                           SecurityLogger::EventType::INVALID_INPUT,
                           remote_addr_, 
                           "Rejecting unpadded inbound packet: size=" + std::to_string(bytes_transferred));
        trigger_close_handler();
        return;
    }
    
    if (on_message_) {
        on_message_(shared_from_this(), std::move(message), is_binary);
    }
    
    do_read();
    
    // Aggressive Memory Management: Shrink buffer if it's holding onto too much memory
    if (read_buffer_.capacity() > 8192) {
        read_buffer_.shrink_to_fit();
    }
}

void WebSocketSession::send_text(std::string message, bool is_media) {
    auto msg_data = std::make_shared<std::string>(std::move(message));
    size_t msg_size = msg_data->size();
    
    net::post(
        get_executor(),
        [self = shared_from_this(), msg_data, is_media, msg_size]() {
            if (self->is_queue_full(msg_size)) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT, self->remote_addr_, "Outbound queue full. Dropping message.");
                return;
            }
            
            auto now = std::chrono::steady_clock::now();
            if (self->last_pacing_time_ < now) self->last_pacing_time_ = now;
            
            // Apply Micro-Pacing Jitter (10-50ms) to flatten burst spikes
            static thread_local std::mt19937 gen{std::random_device{}()};
            std::uniform_int_distribution<int> jitter_dis(10, 50);
            
            if (!is_media) {
                self->last_pacing_time_ += std::chrono::milliseconds(self->config_.pacing.tick_interval_ms + jitter_dis(gen));
            } else {
                self->last_pacing_time_ += std::chrono::milliseconds(jitter_dis(gen));
            }
            
            self->pacing_queue_.push_back({msg_data, false, is_media, self->last_pacing_time_});
            self->current_queue_bytes_ += msg_size;

        });
}

void WebSocketSession::send_binary(std::string data, bool is_media) {
    auto msg_data = std::make_shared<std::string>(std::move(data));
    size_t msg_size = msg_data->size();
    
    net::post(
        get_executor(),
        [self = shared_from_this(), msg_data, is_media, msg_size]() {
            if (self->is_queue_full(msg_size)) {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::RATE_LIMIT_HIT, self->remote_addr_, "Outbound binary queue full. Dropping message.");
                return;
            }
            
            auto now = std::chrono::steady_clock::now();
            if (self->last_pacing_time_ < now) self->last_pacing_time_ = now;
            
            static thread_local std::mt19937 gen{std::random_device{}()};
            std::uniform_int_distribution<int> jitter_dis(10, 50);

            if (!is_media) {
                self->last_pacing_time_ += std::chrono::milliseconds(self->config_.pacing.tick_interval_ms + jitter_dis(gen));
            } else {
                self->last_pacing_time_ += std::chrono::milliseconds(jitter_dis(gen));
            }
            
            self->pacing_queue_.push_back({msg_data, true, is_media, self->last_pacing_time_});
            self->current_queue_bytes_ += msg_size;
        });
}

void WebSocketSession::flush_pacing_queue() {
    auto now = std::chrono::steady_clock::now();
    bool should_write = false;
    
    // Batch move all "mature" messages to the active write queue
    for (auto it = pacing_queue_.begin(); it != pacing_queue_.end(); ) {
        if (now >= it->ready_time) {
            write_queue_.push(std::move(*it));
            it = pacing_queue_.erase(it);
            should_write = true;
        } else {
            ++it;
        }
    }
    
    if (should_write) {
        do_write();
    }
}

void WebSocketSession::do_write() {
    if (write_queue_.empty() || is_writing_) {
        return;
    }
    
    is_writing_ = true;
    auto item = write_queue_.front();
    write_queue_.pop();
    if (item.data) current_queue_bytes_ -= item.data->size();
    
    auto self = shared_from_this();
    const bool was_media = item.is_media;

    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.binary(item.is_binary);
        ws.async_write(
            net::buffer(*item.data),
            [self, item](beast::error_code ec, std::size_t bytes) {
                self->on_write(ec, bytes);
            });
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.binary(item.is_binary);
        ws.async_write(
            net::buffer(*item.data),
            [self, item](beast::error_code ec, std::size_t bytes) {
                self->on_write(ec, bytes);
            });
    }
    last_activity_time_ = std::chrono::steady_clock::now();
}

void WebSocketSession::on_write(beast::error_code ec, std::size_t  ) {
    is_writing_ = false; 

    if (ec) {
        SecurityLogger::log(SecurityLogger::Level::ERROR, 
                           SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                           remote_addr_, 
                           "WS Write Error: " + ec.message());
        close();
        return;
    }

    do_write();
}

void WebSocketSession::close() {
    if (close_triggered_.exchange(true)) return;
    do_close();
}

void WebSocketSession::do_close() {
    auto self = shared_from_this();
    
    if (is_tls_) {
        auto& ws = std::get<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(ws_);
        ws.async_close(
            websocket::close_code::normal,
            [self, this](beast::error_code ec) {
                if (ec) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, 
                                       SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                                       remote_addr_, 
                                       "WS Close Error: " + ec.message());
                }
                trigger_close_handler();
            });
    } else {
        auto& ws = std::get<websocket::stream<beast::tcp_stream>>(ws_);
        ws.async_close(
            websocket::close_code::normal,
            [self, this](beast::error_code ec) {
                if (ec) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, 
                                       SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                                       remote_addr_, 
                                       "WS Close Error: " + ec.message());
                }
                trigger_close_handler();
            });
    }
}


}
