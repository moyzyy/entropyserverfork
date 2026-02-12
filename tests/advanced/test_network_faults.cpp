#include <gtest/gtest.h>
#include "redis_manager.hpp"
#include "handlers/identity_handler.hpp"
using namespace entropy;
class FaultMockRedis : public RedisManager {
public:
    using RedisManager::RedisManager;
    bool is_failure_mode = false;
    std::string issue_challenge(int ttl) override {
        if (is_failure_mode) return "";
        return RedisManager::issue_challenge(ttl);
    }
    bool store_offline_message(const std::string& h, const std::string& m) override {
        if (is_failure_mode) return false;
        return RedisManager::store_offline_message(h, m);
    }
};
class FaultTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"fault_salt"};
    FaultMockRedis redis{config, cm, "fault_salt"};
    RateLimiter rate_limiter{redis};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
    void SetUp() override {
        config.secret_salt = "fault_salt";
    }
};
TEST_F(FaultTest, RedisOutageGracefulFailure) {
    redis.is_failure_mode = true;
    json::object req;
    auto res = id_handler.handle_pow_challenge_ws(req, "127.0.0.1");
    EXPECT_EQ(res["seed"], "");
    json::object upload_req;
    upload_req["identity_hash"] = std::string(64, 'a');
    upload_req["identityKey"] = "key";
    auto upload_res = id_handler.handle_keys_upload_ws(upload_req, "127.0.0.1");
    EXPECT_EQ(upload_res["type"], "error");
}
