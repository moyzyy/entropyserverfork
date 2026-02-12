#include <gtest/gtest.h>
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <thread>
#include "pow_verifier.hpp"
#include "handlers/health_handler.hpp"
#include "metrics.hpp"
#include "traffic_normalizer.hpp"
#include "security_logger.hpp"
#include "redis_manager.hpp"
#include "handlers/identity_handler.hpp"
#include "message_relay.hpp"
#include "websocket_session.hpp"
using namespace entropy;
namespace http = boost::beast::http;
/* tests/security/test_security_audit.cpp
 * Verifies core security controls: audit logging, admin access, 
 * data sanitization, and forensic resistance.
 */
class SecurityAuditTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"audit_salt"};
    RedisManager redis{config, cm, "audit_salt"};
    RateLimiter rate_limiter{redis};
    HealthHandler health_handler{config, cm};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
    MessageRelay relay{cm, redis, rate_limiter, config};
    boost::asio::io_context ioc;
    void SetUp() override {
        config.admin_token = "prod_admin_secret";
        config.secret_salt = "audit_salt";
        MetricsRegistry::instance().reset();
    }
};
TEST_F(SecurityAuditTest, MetricsIntegrity) {
    // Audit: Ensure metrics wrapper correctly formats Prometheus data
    MetricsRegistry::instance().increment_counter("test_event", 1.0);
    MetricsRegistry::instance().increment_counter("test_event", 5.0);
    MetricsRegistry::instance().set_gauge("active_users", 42.0);
    auto metrics_str = MetricsRegistry::instance().collect_prometheus();
    EXPECT_TRUE(metrics_str.find("test_event 6") != std::string::npos);
    EXPECT_TRUE(metrics_str.find("active_users 42") != std::string::npos);
}
TEST_F(SecurityAuditTest, AdminAccessControl) {
    // Audit: Verify admin token enforcement on sensitive endpoints
    http::request<http::string_body> req{http::verb::get, "/stats", 11};
    auto res_fail = health_handler.handle_stats(req);
    EXPECT_EQ(res_fail.result(), http::status::unauthorized);
    
    // Invalid token check
    req.set("X-Admin-Token", "wrong_token");
    auto res_wrong = health_handler.handle_stats(req);
    EXPECT_EQ(res_wrong.result(), http::status::unauthorized);
    
    // Valid token check
    req.set("X-Admin-Token", "prod_admin_secret");
    auto res_ok = health_handler.handle_stats(req);
    EXPECT_EQ(res_ok.result(), http::status::ok);
    EXPECT_TRUE(res_ok.body().find("\"active_connections\":") != std::string::npos);
}
TEST_F(SecurityAuditTest, TrafficShapeAudit) {
    // Audit: Verify constant-rate padding logic (metadata protection)
    const size_t TARGET_SIZE = 1536;
    json::object small_msg;
    small_msg["type"] = "ping";
    small_msg["id"] = 1;
    TrafficNormalizer::pad_json(small_msg, TARGET_SIZE);
    std::string output = json::serialize(small_msg);
    EXPECT_GE(output.size(), TARGET_SIZE);
    EXPECT_TRUE(small_msg.contains("padding"));
}
TEST_F(SecurityAuditTest, ForensicBurnCompleteness) {
    // Audit: Ensure "burn" command irrevocably deletes nickname and stored messages
    std::string identity = std::string(64, 'f');
    std::string nick = "burnable_user";
    redis.register_nickname(nick, identity);
    redis.store_offline_message(identity, "{\"body\":\"offline_secret\"}");
    redis.burn_account(identity);
    EXPECT_EQ(redis.resolve_nickname(nick), "");
    auto offline = redis.retrieve_offline_messages(identity);
    EXPECT_TRUE(offline.empty());
}
TEST_F(SecurityAuditTest, IPBlindingForwardSecrecy) {
    // Audit: HMAC-based IP blinding must be deterministic but irreversible
    std::string ip = "1.2.3.4";
    std::string blinded1 = cm.blind_id(ip);
    std::string blinded2 = cm.blind_id(ip);
    EXPECT_EQ(blinded1, blinded2);
    EXPECT_NE(blinded1, ip);
    EXPECT_EQ(blinded1.size(), 64);
}
TEST_F(SecurityAuditTest, UnauthorizedBurnAttempt) {
    std::string identity = std::string(64, 'e');
    json::object req;
    req["identity_hash"] = identity;
    req["signature"] = std::string(128, '0');
    req["public_key"] = std::string(64, 'a');
    std::string seed = rate_limiter.issue_challenge(60);
    std::string nonce;
    for (int i = 0; i < 1000; ++i) {
        if (PoWVerifier::verify(seed, std::to_string(i), identity, 4)) {
            nonce = std::to_string(i);
            break;
        }
    }
    req["seed"] = seed;
    req["nonce"] = nonce;
    auto res = id_handler.handle_account_burn_ws(req, "1.2.3.4");
    EXPECT_EQ(res["type"], "error");
    EXPECT_TRUE(res.contains("message"));
}
TEST_F(SecurityAuditTest, RelayRateLimitAudit) {
    auto alice = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(ioc), cm, config);
    alice->set_authenticated(true);
    alice->set_user_data(std::string(64, 'a'));
    json::object msg;
    msg["type"] = "msg";
    msg["to"] = std::string(64, 'b');
    msg["body"] = "spam";
    std::string msg_json = json::serialize(msg);
    for (int i = 0; i < 10; ++i) {
        relay.relay_message(msg_json, alice);
    }
}
TEST_F(SecurityAuditTest, BinaryProtocolRobustness) {
    auto alice = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(ioc), cm, config);
    alice->set_authenticated(true);
    alice->set_user_data(std::string(64, 'a'));
    std::string data = "payload";
    std::string short_hash = "abc";
    relay.relay_binary(short_hash, data.data(), data.size(), alice);
}
