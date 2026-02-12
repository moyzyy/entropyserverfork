#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <boost/beast/core.hpp>
#include <boost/asio.hpp>
#include "message_relay.hpp"
#include "websocket_session.hpp"
using namespace entropy;
class TimingTest : public ::testing::Test {
protected:
    ServerConfig config;
    void SetUp() override {
        config.secret_salt = "time_salt";
    }
};
TEST_F(TimingTest, MessageDeliveryJitter) {
    for (int i = 0; i < 3; ++i) {
        boost::asio::io_context ioc;
        ConnectionManager cm{"time_salt"};
        RedisManager redis{config, cm, "time_salt"};
        RateLimiter rate_limiter{redis};
        MessageRelay relay{cm, redis, rate_limiter, config};
        auto alice = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(ioc), cm, config);
        auto bob = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(ioc), cm, config);
        std::string alice_hash = std::string(64, 'a');
        std::string bob_hash = std::string(64, 'b');
        alice->set_user_data(alice_hash);
        alice->set_authenticated(true);
        cm.add_connection(bob_hash, bob);
        auto start = std::chrono::steady_clock::now();
        json::object msg;
        msg["type"] = "msg";
        msg["to"] = bob_hash;
        msg["body"] = "test";
        relay.relay_message(json::serialize(msg), alice);
        size_t processed = ioc.run_one();
        auto end = std::chrono::steady_clock::now();
        auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        EXPECT_EQ(processed, 1);
        EXPECT_GE(delay, 9);
        EXPECT_LE(delay, 100);
    }
}
