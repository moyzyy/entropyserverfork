#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <atomic>
#include <future>
#include "connection_manager.hpp"
#include "redis_manager.hpp"
#include "handlers/identity_handler.hpp"
#include "pow_verifier.hpp"
using namespace entropy;
class ConcurrencyTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"stress_salt"};
    RedisManager redis{config, cm, "stress_salt"};
    RateLimiter rate_limiter{redis};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
    void SetUp() override {
        config.secret_salt = "stress_salt";
    }
};
TEST_F(ConcurrencyTest, ParallelNicknameRegistration) {
    const int num_threads = 20;
    std::string target_nick = "speedster";
    std::atomic<int> success_count{0};
    std::atomic<int> fail_count{0};
    std::vector<std::string> errors;
    std::mutex errors_mutex;
    auto register_task = [&](int id) {
        std::string identity = "user_" + std::to_string(id);
        identity.resize(64, 'a');
        json::object pow_req;
        pow_req["type"] = "pow_challenge";
        pow_req["nickname"] = target_nick;
        auto pow_res = id_handler.handle_pow_challenge_ws(pow_req, "127.0.0.1");
        if (!pow_res.contains("seed")) {
             std::lock_guard<std::mutex> lock(errors_mutex);
             errors.push_back("Thread " + std::to_string(id) + ": No seed in challenge res");
             fail_count++;
             return;
        }
        std::string seed = std::string(pow_res["seed"].as_string());
        int diff = (int)pow_res["difficulty"].as_int64();
        std::string nonce;
        for (int i = 0; i < 1000000; ++i) {
            std::string n = std::to_string(i);
            if (PoWVerifier::verify(seed, n, target_nick, diff)) {
                nonce = n;
                break;
            }
        }
        json::object req;
        req["nickname"] = target_nick;
        req["identity_hash"] = identity;
        req["seed"] = seed;
        req["nonce"] = nonce;
        auto res = id_handler.handle_nickname_register_ws(req, "127.0.0.1");
        if (res.contains("status") && res["status"] == "success") {
            success_count++;
        } else {
            std::string msg = res.contains("message") ? std::string(res["message"].as_string()) : "No message";
            if (msg != "Nickname already taken") {
                std::lock_guard<std::mutex> lock(errors_mutex);
                errors.push_back("Thread " + std::to_string(id) + ": " + msg);
            }
            fail_count++;
        }
    };
    target_nick += std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(register_task, i);
    }
    for (auto& t : threads) {
        t.join();
    }
    if (success_count.load() != 1) {
        for (const auto& err : errors) {
            std::cout << "[!] " << err << "\n";
        }
    }
    EXPECT_EQ(success_count.load(), 1);
    EXPECT_EQ(fail_count.load(), num_threads - 1);
}
TEST_F(ConcurrencyTest, RapidConnectionThrottling) {
    std::string ip = "192.168.1.50";
    size_t limit = 10;
    std::atomic<int> allowed{0};
    std::atomic<int> blocked{0};
    auto connect_task = [&]() {
        if (cm.increment_ip_count(ip, limit)) {
            allowed++;
        } else {
            blocked++;
        }
    };
    std::vector<std::thread> threads;
    for (int i = 0; i < 50; ++i) {
        threads.emplace_back(connect_task);
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(allowed.load(), (int)limit);
    EXPECT_EQ(blocked.load(), 50 - (int)limit);
}
