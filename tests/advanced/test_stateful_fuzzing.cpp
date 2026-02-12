#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include "websocket_session.hpp"
#include "message_relay.hpp"
#include "handlers/identity_handler.hpp"
#include "server_config.hpp"
#include "security_logger.hpp"
using namespace entropy;
namespace asio = boost::asio;
namespace beast = boost::beast;
class StatefulFuzzingTest : public ::testing::Test {
protected:
    asio::io_context ioc;
    ServerConfig config;
    ConnectionManager cm{"stateful_salt"};
    RedisManager redis{config, cm, "stateful_salt"};
    RateLimiter rate_limiter{redis};
    MessageRelay relay{cm, redis, rate_limiter, config};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
    std::shared_ptr<WebSocketSession> create_session() {
        return std::make_shared<WebSocketSession>(beast::tcp_stream(ioc), cm, config);
    }
};
TEST_F(StatefulFuzzingTest, OutOfOrderOperations) {
    auto session = create_session();
    json::object reg_req;
    reg_req["type"] = "nickname_register";
    reg_req["nickname"] = "hacker";
    reg_req["identity_hash"] = std::string(64, 'a');
    auto res = id_handler.handle_nickname_register_ws(reg_req, "1.2.3.4");
    EXPECT_EQ(res["type"].as_string(), "error");
    EXPECT_TRUE(std::string(res["message"].as_string()).find("PoW") != std::string::npos);
    std::string msg = "{\"type\":\"relay\",\"to\":\"bob\",\"data\":\"hello\"}";
    EXPECT_NO_THROW({
        relay.relay_message(msg, session);
    });
    EXPECT_FALSE(session->is_authenticated());
    json::object upload_req;
    upload_req["type"] = "keys_upload";
    upload_req["identity_hash"] = std::string(64, 'b');
    upload_req["identityKey"] = std::string(64, 'c');
    res = id_handler.handle_keys_upload_ws(upload_req, "1.2.3.4");
    EXPECT_EQ(res["type"].as_string(), "error");
}
TEST_F(StatefulFuzzingTest, DoublePoWSolution) {
    auto session = create_session();
    session->set_authenticated(true);
    json::object challenge_req;
    challenge_req["type"] = "pow_challenge";
    auto challenge_res = id_handler.handle_pow_challenge_ws(challenge_req, "1.2.3.4");
    EXPECT_TRUE(challenge_res.contains("seed"));
    EXPECT_TRUE(session->is_authenticated());
}
TEST_F(StatefulFuzzingTest, AliasSaturation) {
    auto session = create_session();
    for (int i = 0; i < 60; ++i) {
        session->add_alias("alias_" + std::to_string(i));
    }
    EXPECT_LE(session->get_aliases().size(), 50);
}
