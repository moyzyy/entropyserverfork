#include <gtest/gtest.h>
#include "handlers/identity_handler.hpp"
#include "redis_manager.hpp"
#include "rate_limiter.hpp"
#include "connection_manager.hpp"
#include "server_config.hpp"
#include <boost/json.hpp>
using namespace entropy;
class IdentityHandlerTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"test_salt"};
    RedisManager redis{config, cm, "test_salt"};
    RateLimiter rate_limiter{redis};
    IdentityHandler handler{config, redis, redis, rate_limiter};
    void SetUp() override {
    }
};
TEST_F(IdentityHandlerTest, HandlePoWChallenge) {
    json::object req;
    req["req_id"] = "123";
    auto res = handler.handle_pow_challenge_ws(req, "127.0.0.1");
    EXPECT_EQ(res["type"], "pow_challenge_res");
    EXPECT_EQ(res["req_id"], "123");
    EXPECT_TRUE(res.contains("seed"));
    EXPECT_TRUE(res.contains("difficulty"));
}
TEST_F(IdentityHandlerTest, HandleKeysFetchNotFound) {
    json::object req;
    req["type"] = "fetch_key";
    req["target_hash"] = std::string(64, 'a');
    auto res = handler.handle_keys_fetch_ws(req, "127.0.0.1");
    EXPECT_EQ(res["type"], "fetch_key_res");
    EXPECT_FALSE(res["found"].as_bool());
}
TEST_F(IdentityHandlerTest, HandleNicknameLookupNotFound) {
    json::object req;
    req["name"] = "nonexistent";
    auto res = handler.handle_nickname_lookup_ws(req, "127.0.0.1");
    EXPECT_EQ(res["type"], "nickname_lookup_res");
    EXPECT_TRUE(res.contains("error"));
}
TEST_F(IdentityHandlerTest, HandleLinkPreview) {
    json::object req;
    req["url"] = "https://example.com/page";
    auto res = handler.handle_link_preview_ws(req, "127.0.0.1");
    EXPECT_EQ(res["type"], "link_preview_res");
    EXPECT_EQ(res["url"], "https://example.com/page");
    EXPECT_TRUE(res.contains("title"));
}
