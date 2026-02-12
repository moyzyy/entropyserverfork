#include <gtest/gtest.h>
#include "connection_manager.hpp"
#include "websocket_session.hpp"
using namespace entropy;
class ConnectionManagerTest : public ::testing::Test {
protected:
    ConnectionManager cm{"test_salt"};
};
TEST_F(ConnectionManagerTest, IPCounting) {
    std::string ip = "127.0.0.1";
    size_t limit = 2;
    EXPECT_TRUE(cm.increment_ip_count(ip, limit));
    EXPECT_EQ(cm.connection_count_for_ip(ip), 1);
    EXPECT_TRUE(cm.increment_ip_count(ip, limit));
    EXPECT_EQ(cm.connection_count_for_ip(ip), 2);
    EXPECT_FALSE(cm.increment_ip_count(ip, limit));
    EXPECT_EQ(cm.connection_count_for_ip(ip), 2);
    cm.decrement_ip_count(ip);
    EXPECT_EQ(cm.connection_count_for_ip(ip), 1);
    cm.decrement_ip_count(ip);
    EXPECT_EQ(cm.connection_count_for_ip(ip), 0);
}
TEST_F(ConnectionManagerTest, Blinding) {
    std::string id = "test_user";
    std::string blinded = cm.blind_id(id);
    EXPECT_FALSE(blinded.empty());
    EXPECT_NE(id, blinded);
    EXPECT_EQ(blinded, cm.blind_id(id));
}
