#include <gtest/gtest.h>
#include "traffic_normalizer.hpp"
#include <boost/json.hpp>
using namespace entropy;
TEST(TrafficNormalizerTest, Padding) {
    boost::json::object obj;
    obj["type"] = "test";
    size_t target_size = 1536;
    TrafficNormalizer::pad_json(obj, target_size);
    std::string serialized = boost::json::serialize(obj);
    EXPECT_GE(serialized.size(), target_size - 20);
    EXPECT_TRUE(obj.contains("padding"));
}
TEST(TrafficNormalizerTest, NoPaddingIfLargeEnough) {
    boost::json::object obj;
    obj["data"] = std::string(2000, 'x');
    size_t target_size = 1536;
    TrafficNormalizer::pad_json(obj, target_size);
    EXPECT_FALSE(obj.contains("padding"));
}
