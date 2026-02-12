#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "http_session.hpp"
#include "connection_manager.hpp"
#include "server_config.hpp"
#include "handlers/health_handler.hpp"
using namespace entropy;
namespace http = boost::beast::http;
class AdminSecurityTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"admin_salt"};
    HealthHandler handler{config, cm};
    http::request<http::string_body> make_req(const std::string& target) {
        http::request<http::string_body> req{http::verb::get, target, 11};
        return req;
    }
};
TEST_F(AdminSecurityTest, AllowLocalhostStats) {
    auto req = make_req("/stats");
    config.admin_token = "secret_token";
    auto protected_handler = HealthHandler(config, cm);
    req.set("X-Admin-Token", "secret_token");
    EXPECT_TRUE(protected_handler.verify_admin_request(req));
    req.set("X-Admin-Token", "wrong_token");
    EXPECT_FALSE(protected_handler.verify_admin_request(req));
}
TEST_F(AdminSecurityTest, HealthEndpointPublic) {
    auto req = make_req("/health");
    auto res = handler.handle_health(11);
    EXPECT_EQ(res.result(), http::status::ok);
    EXPECT_EQ(res["Content-Type"], "application/json");
}
TEST_F(AdminSecurityTest, StatsEndpointProtected) {
    auto req = make_req("/stats");
    EXPECT_FALSE(handler.verify_admin_request(req));
}
TEST_F(AdminSecurityTest, MetricsEndpointProtected) {
    auto req = make_req("/metrics");
    EXPECT_FALSE(handler.verify_admin_request(req));
}
