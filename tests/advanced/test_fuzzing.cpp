#include <gtest/gtest.h>
#include <boost/beast/core.hpp>
#include <boost/asio/strand.hpp>
#include "websocket_session.hpp"
#include "input_validator.hpp"
#include "message_relay.hpp"
#include "handlers/identity_handler.hpp"
using namespace entropy;
/* tests/advanced/test_fuzzing.cpp
 * Robustness testing against malformed inputs and boundary conditions.
 */
class FuzzTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"fuzz_salt"};
    RedisManager redis{config, cm, "fuzz_salt"};
    RateLimiter rate_limiter{redis};
    MessageRelay relay{cm, redis, rate_limiter, config};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
};
TEST_F(FuzzTest, MalformedJsonHandling) {
    // Parser must handle partial/invalid JSON without crashing
    std::string bad_jsons[] = {
        "{ \"type\": \"unregister\", ",
        "[1, 2, 3]",                 
        "null",                       
        "\"just a string\"",          
        "{ \"type\": 12345 }",        
        "{ \"to\": { \"nested\": 1 } }"
    };
    auto dummy_session = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(boost::asio::make_strand(boost::asio::system_executor())), cm, config);
    for (const auto& json_str : bad_jsons) {
        EXPECT_NO_THROW({
            relay.relay_message(json_str, dummy_session);
        });
    }
}
TEST_F(FuzzTest, PayloadBoundaries) {
    // Verify rejection of payloads exceeding MAX_MESSAGE_SIZE
    std::string huge_data(MessageRelay::MAX_MESSAGE_SIZE + 1024, 'x');
    EXPECT_FALSE(relay.validate_message_size(huge_data.size()));

    // Verify sanitization of extremely long field values
    std::string long_id_json = "{ \"identity_hash\": \"" + std::string(10000, 'a') + "\" }";
    EXPECT_NO_THROW({
        auto val = InputValidator::safe_parse_json(long_id_json);
        if (val.is_object() && val.as_object().contains("identity_hash")) {
            std::string raw = std::string(val.as_object().at("identity_hash").as_string());
            std::string sanitized = InputValidator::sanitize_field(raw, 256);
            EXPECT_LE(sanitized.size(), 256);
        }
    });
}
TEST_F(FuzzTest, BinaryRelayTypeConfusion) {
    // Ensure binary relay handlers safely reject invalid routing metadata
    auto alice = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(boost::asio::make_strand(boost::asio::system_executor())), cm, config);
    std::string garbage = "too_short";
    EXPECT_NO_THROW({
        relay.relay_binary("some_recipient", garbage.data(), garbage.size(), alice);
    });
}
