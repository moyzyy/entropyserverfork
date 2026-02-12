#include <gtest/gtest.h>
#include <boost/beast/core.hpp>
#include <boost/asio.hpp>
#include "connection_manager.hpp"
#include "websocket_session.hpp"
using namespace entropy;
class LifecycleTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"life_salt"};
    boost::asio::io_context ioc;
    void SetUp() override {
        config.secret_salt = "life_salt";
    }
};
TEST_F(LifecycleTest, SessionCleanupAndDraining) {
    const int count = 10;
    std::string id_base = std::string(64, 'a');
    {
        std::vector<std::shared_ptr<WebSocketSession>> sessions;
        for (int i = 0; i < count; ++i) {
            auto session = std::make_shared<WebSocketSession>(boost::beast::tcp_stream(ioc), cm, config);
            std::string id = id_base;
            id[0] = (char)('0' + i);
            cm.add_connection(id, session);
            sessions.push_back(session);
        }
        EXPECT_EQ(cm.connection_count(), count);
        for (int i = 0; i < count; ++i) {
             std::string id = id_base;
             id[0] = (char)('0' + i);
             EXPECT_NE(cm.get_connection(id), nullptr);
        }
    }
    for (int i = 0; i < count; ++i) {
         std::string id = id_base;
         id[0] = (char)('0' + i);
         EXPECT_EQ(cm.get_connection(id), nullptr);
    }
}
