#include <gtest/gtest.h>
#include "pow_verifier.hpp"
#include "metrics.hpp"
#include "connection_manager.hpp"
using namespace entropy;
TEST(DoSTest, DifficultyScalingUnderLoad) {
    auto& metrics = MetricsRegistry::instance();
    double original_conn = metrics.get_gauge("active_connections");
    metrics.set_gauge("active_connections", 2000);
    int high_load_difficulty = PoWVerifier::get_required_difficulty();
    metrics.set_gauge("active_connections", 100);
    int low_load_difficulty = PoWVerifier::get_required_difficulty();
    EXPECT_GT(high_load_difficulty, low_load_difficulty);
    metrics.set_gauge("active_connections", original_conn);
}
TEST(DoSTest, IPConnectionRateLimiting) {
    ConnectionManager cm{"salt"};
    std::string ip = "1.2.3.4";
    size_t limit = 5;
    for(size_t i = 0; i < limit; ++i) {
        EXPECT_TRUE(cm.increment_ip_count(ip, limit));
    }
    EXPECT_FALSE(cm.increment_ip_count(ip, limit));
    EXPECT_TRUE(cm.increment_ip_count("1.2.3.5", limit));
}
TEST(DoSTest, BlindedIdCollisionResistance) {
    ConnectionManager cm{"salt_a"};
    ConnectionManager cm_b{"salt_b"};
    std::string id = "user_identity_hash";
    std::string blinded_a = cm.blind_id(id);
    std::string blinded_b = cm_b.blind_id(id);
    EXPECT_NE(id, blinded_a);
    EXPECT_NE(blinded_a, blinded_b);
    EXPECT_EQ(blinded_a.length(), 64);
}
TEST(DoSTest, PoWDifficultyForShortNames) {
    int diff_3 = PoWVerifier::get_difficulty_for_nickname("abc");
    int diff_10 = PoWVerifier::get_difficulty_for_nickname("abcdefghij");
    EXPECT_GT(diff_3, diff_10);
}
