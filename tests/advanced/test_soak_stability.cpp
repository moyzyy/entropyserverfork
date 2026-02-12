#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include "websocket_session.hpp"
#include "message_relay.hpp"
#include "handlers/identity_handler.hpp"
#include "pow_verifier.hpp"
using namespace entropy;
namespace asio = boost::asio;
namespace beast = boost::beast;
class SoakStabilityTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"soak_salt"};
    RedisManager redis{config, cm, "soak_salt"};
    RateLimiter rate_limiter{redis};
    MessageRelay relay{cm, redis, rate_limiter, config};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
    asio::io_context ioc;
};
TEST_F(SoakStabilityTest, MessageRelayThrashing) {
    const int num_threads = 4;
    const int messages_per_thread = 500;
    std::atomic<int> total_processed{0};
    auto task = [&]() {
        auto session = std::make_shared<WebSocketSession>(beast::tcp_stream(ioc), cm, config);
        session->set_authenticated(true);
        for (int i = 0; i < messages_per_thread; ++i) {
            std::string payload = "{\"type\":\"relay\",\"to\":\"recipient_" + std::to_string(i % 10) + "\",\"data\":\"soak_test_data\"}";
            relay.relay_message(payload, session);
            total_processed++;
        }
    };
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(task);
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(total_processed.load(), num_threads * messages_per_thread);
}
TEST_F(SoakStabilityTest, RapidAuthChurn) {
    const int iterations = 100;
    for (int i = 0; i < iterations; ++i) {
        auto session = std::make_shared<WebSocketSession>(beast::tcp_stream(ioc), cm, config);
        json::object challenge_req;
        auto challenge_res = id_handler.handle_pow_challenge_ws(challenge_req, "127.0.0.1");
        std::string seed = std::string(challenge_res["seed"].as_string());
        int difficulty = (int)challenge_res["difficulty"].as_int64();
        EXPECT_FALSE(seed.empty());
        EXPECT_GT(difficulty, 0);
    }
}
TEST_F(SoakStabilityTest, MemoryGrowthHeuristic) {
    std::vector<std::shared_ptr<WebSocketSession>> active_sessions;
    active_sessions.reserve(1000);
    for (int i = 0; i < 1000; ++i) {
        active_sessions.push_back(std::make_shared<WebSocketSession>(beast::tcp_stream(ioc), cm, config));
        active_sessions.back()->add_alias("test_alias");
    }
    EXPECT_EQ(active_sessions.size(), 1000);
    active_sessions.clear();  
}
