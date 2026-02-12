#include <gtest/gtest.h>
#include <chrono>
#include "input_validator.hpp"
#include "pow_verifier.hpp"
using namespace entropy;

class BenchmarkTest : public ::testing::Test {};

// Smoke test: Verifies sanitize_field executes without crashing
TEST_F(BenchmarkTest, SanitizeFieldSmoke) {
    std::string input = "This is a long input string with some 12345 _ integers and - symbols.";
    const int iterations = 1000;
    
    for (int i = 0; i < iterations; ++i) {
        auto result = InputValidator::sanitize_field(input, 256);
        EXPECT_FALSE(result.empty());
    }
}

// Smoke test: Verifies PoW verification executes correctly
TEST_F(BenchmarkTest, PoWVerificationSmoke) {
    std::string seed = std::string(64, 'a');
    std::string identity = std::string(64, 'b');
    std::string nonce = "12345";
    const int iterations = 100;
    
    for (int i = 0; i < iterations; ++i) {
        bool result = PoWVerifier::verify(seed, nonce, identity, 4);
        (void)result; // Just verify it doesn't crash
    }
}
