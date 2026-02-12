#include <gtest/gtest.h>
#include <chrono>
#include "input_validator.hpp"
#include "pow_verifier.hpp"
using namespace entropy;
class BenchmarkTest : public ::testing::Test {};
TEST_F(BenchmarkTest, SanitizeFieldBenchmark) {
    std::string input = "This is a long input string with some 12345 _ integers and - symbols. It should be fast.";
    const int iterations = 100000;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        InputValidator::sanitize_field(input, 256);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "[ PERFORMANCE ] SanitizeField " << iterations << " iterations: " << duration << "ms\n";
    EXPECT_LT(duration, 500); 
}
TEST_F(BenchmarkTest, PoWVerificationBenchmark) {
    std::string seed = std::string(64, 'a');
    std::string identity = std::string(64, 'b');
    std::string nonce = "12345";
    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        PoWVerifier::verify(seed, nonce, identity, 4);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "[ PERFORMANCE ] PoWVerify " << iterations << " iterations: " << duration << "ms\n";
    EXPECT_LT(duration, 1000);
}
