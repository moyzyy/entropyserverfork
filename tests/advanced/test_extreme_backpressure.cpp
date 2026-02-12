#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <chrono>
#include <thread>
#include <vector>
#include "websocket_session.hpp"
#include "connection_manager.hpp"
#include "server_config.hpp"
#include "message_relay.hpp"
#include "redis_manager.hpp"
#include "security_logger.hpp"
using namespace entropy;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace asio = boost::asio;
class ExtremeAuditTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"extreme_salt"};
    RedisManager redis{config, cm, "extreme_salt"};
    RateLimiter rate_limiter{redis};
    MessageRelay relay{cm, redis, rate_limiter, config};
    asio::io_context ioc;
    void SetUp() override {
        config.max_message_size = 1024 * 1024;
        config.max_connections_per_ip = 5;
    }
};
TEST_F(ExtremeAuditTest, MemoryBackpressureRejection) {
    auto session = std::make_shared<WebSocketSession>(beast::tcp_stream(ioc), cm, config);
    std::string giant_payload(config.max_message_size + 1024, 'a');
    EXPECT_FALSE(relay.validate_message_size(giant_payload.size()));
}
TEST_F(ExtremeAuditTest, IPFloodingRejection) {
    std::string test_ip = "1.2.3.4";
    for (int i = 0; i < (int)config.max_connections_per_ip; ++i) {
        EXPECT_TRUE(cm.increment_ip_count(test_ip, config.max_connections_per_ip));
    }
    EXPECT_FALSE(cm.increment_ip_count(test_ip, config.max_connections_per_ip));
    cm.decrement_ip_count(test_ip);
    EXPECT_TRUE(cm.increment_ip_count(test_ip, config.max_connections_per_ip));
}
TEST_F(ExtremeAuditTest, ProtocolTypeConfusion) {
    auto alice = std::make_shared<WebSocketSession>(beast::tcp_stream(ioc), cm, config);
    alice->set_authenticated(true);
    std::string junk = "\xff\xd8\xff\xe0\x00\x10JFIF";
    EXPECT_NO_THROW({
        relay.relay_message(junk, alice);
    });
}
TEST_F(ExtremeAuditTest, LogInjectionSanitization) {
    std::string malicious = "normal msg\"\n[CRITICAL] msg=\"Fake event\"";
    std::string sanitized = SecurityLogger::sanitize_log_message(malicious);
    EXPECT_TRUE(sanitized.find("\n") == std::string::npos);
    EXPECT_TRUE(sanitized.find("\"") == std::string::npos);
}
TEST_F(ExtremeAuditTest, DistributedNicknameTOCTOU) {
    std::string nick = "shared_gold";
    std::string id1 = std::string(64, '1');
    std::string id2 = std::string(64, '2');
    std::atomic<int> success_count{0};
    auto task = [&](const std::string& id) {
        RedisManager rm{config, cm, "extreme_salt"};
        if (rm.register_nickname(nick, id)) {
            success_count++;
        }
    };
    std::thread t1(task, id1);
    std::thread t2(task, id2);
    t1.join();
    t2.join();
    EXPECT_EQ(success_count.load(), 1);
}
TEST_F(ExtremeAuditTest, LoggerSaturation) {
    std::atomic<int> log_count{0};
    const int threads_count = 10;
    const int logs_per_thread = 200;
    auto task = [&]() {
        for (int i = 0; i < logs_per_thread; ++i) {
            SecurityLogger::log(SecurityLogger::Level::INFO, 
                               SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, 
                               "1.2.3.4", "Saturation test message " + std::to_string(i));
            log_count++;
        }
    };
    std::vector<std::thread> threads;
    for (int i = 0; i < threads_count; ++i) threads.emplace_back(task);
    for (auto& t : threads) t.join();
    EXPECT_EQ(log_count.load(), threads_count * logs_per_thread);
}
TEST_F(ExtremeAuditTest, LargePayloadFlood) {
    std::string large_msg(config.max_message_size - 10, 'x');
    std::atomic<int> valid_count{0};
    auto task = [&]() {
        for (int i = 0; i < 50; ++i) {
            if (relay.validate_message_size(large_msg.size())) {
                valid_count++;
            }
        }
    };
    std::vector<std::thread> threads;
    for (int i = 0; i < 5; ++i) threads.emplace_back(task);
    for (auto& t : threads) t.join();
    EXPECT_EQ(valid_count.load(), 250);
}
