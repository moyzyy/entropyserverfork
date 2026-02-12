#include <gtest/gtest.h>
#include "handlers/health_handler.hpp"
#include "server_config.hpp"
#include "connection_manager.hpp"
#include <boost/json.hpp>
using namespace entropy;
class HealthHandlerTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"test_salt"};
    HealthHandler handler{config, cm};
    void SetUp() override {
        config.admin_token = "secret_admin_token";
    }
};
TEST_F(HealthHandlerTest, HandleHealth) {
    auto res = handler.handle_health(11);
    EXPECT_EQ(res.result(), http::status::ok);
    EXPECT_EQ(res[http::field::content_type], "application/json");
    auto body = boost::json::parse(res.body()).as_object();
    EXPECT_EQ(body["status"], "healthy");
}
TEST_F(HealthHandlerTest, VerifyAdminSuccess) {
    http::request<http::string_body> req{http::verb::get, "/stats", 11};
    req.set("X-Admin-Token", "secret_admin_token");
    EXPECT_TRUE(handler.verify_admin_request(req));
}
TEST_F(HealthHandlerTest, VerifyAdminFailure) {
    http::request<http::string_body> req{http::verb::get, "/stats", 11};
    req.set("X-Admin-Token", "wrong_token");
    EXPECT_FALSE(handler.verify_admin_request(req));
    http::request<http::string_body> req_no_token{http::verb::get, "/stats", 11};
    EXPECT_FALSE(handler.verify_admin_request(req_no_token));
}
TEST_F(HealthHandlerTest, HandleStats) {
    http::request<http::string_body> req{http::verb::get, "/stats", 11};
    req.set("X-Admin-Token", "secret_admin_token");
    auto res = handler.handle_stats(req);
    EXPECT_EQ(res.result(), http::status::ok);
    auto body = boost::json::parse(res.body()).as_object();
    EXPECT_TRUE(body.contains("active_connections"));
}
