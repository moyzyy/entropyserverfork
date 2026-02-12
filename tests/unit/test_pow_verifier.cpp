#include <gtest/gtest.h>
#include "pow_verifier.hpp"
#include "metrics.hpp"
using namespace entropy;
/* unit/test_pow_verifier.cpp
 * Validates Proof-of-Work difficulty scaling and verification logic.
 */
class PoWVerifierTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(PoWVerifierTest, CalculateDifficulty) {
    // Baseline
    EXPECT_EQ(PoWVerifier::get_required_difficulty(0, 0), PoWVerifier::BASE_DIFFICULTY);

    // High connection count lowers per-user difficulty (load shedding logic)
    EXPECT_EQ(PoWVerifier::get_required_difficulty(0, 20000000), PoWVerifier::BASE_DIFFICULTY - 2);
    EXPECT_EQ(PoWVerifier::get_required_difficulty(0, 3000000), PoWVerifier::BASE_DIFFICULTY - 1);

    // Active request load increases difficulty
    EXPECT_EQ(PoWVerifier::get_required_difficulty(2, 0), PoWVerifier::BASE_DIFFICULTY + 2);
}

TEST_F(PoWVerifierTest, NicknameDifficulty) {
    // Short nicknames must cost more to prevent squatting
    EXPECT_GT(PoWVerifier::get_difficulty_for_nickname("abc"), PoWVerifier::get_difficulty_for_nickname("abcdefghijk"));
    EXPECT_EQ(PoWVerifier::get_difficulty_for_nickname("abc", 0, 0), PoWVerifier::BASE_DIFFICULTY + 3);
}

TEST_F(PoWVerifierTest, VerifySolution) {
    std::string seed = "test_seed";
    std::string context = "test_context";
    
    EXPECT_FALSE(PoWVerifier::verify(seed, "wrong_nonce", context, 1));
    EXPECT_FALSE(PoWVerifier::verify("", "nonce", context, 1));
    EXPECT_FALSE(PoWVerifier::verify("seed", "", context, 1));
}

TEST_F(PoWVerifierTest, BruteforceSmallDifficulty) {
    std::string seed = "challenge_123";
    int difficulty = 2;
    std::string found_nonce = "";

    // Verify puzze is solvable
    for (int i = 0; i < 10000; ++i) {
        std::string nonce = std::to_string(i);
        if (PoWVerifier::verify(seed, nonce, "", difficulty)) {
            found_nonce = nonce;
            break;
        }
    }
    EXPECT_FALSE(found_nonce.empty());
    EXPECT_TRUE(PoWVerifier::verify(seed, found_nonce, "", difficulty));
}

