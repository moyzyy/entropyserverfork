#include <gtest/gtest.h>
#include <vector>
#include "input_validator.hpp"
using namespace entropy;
class CryptoExtremesTest : public ::testing::Test {
protected:
    std::vector<unsigned char> msg = {'H', 'e', 'l', 'l', 'o'};
};
TEST_F(CryptoExtremesTest, Ed25519NeutralPoint) {
    std::vector<unsigned char> neutral_pubkey(32, 0);
    neutral_pubkey[0] = 1;
    std::vector<unsigned char> signature(64, 0);
    EXPECT_FALSE(InputValidator::verify_ed25519(neutral_pubkey, msg, signature));
}
TEST_F(CryptoExtremesTest, Ed25519InvalidKeyLength) {
    std::vector<unsigned char> short_pubkey(31, 0xFF);
    std::vector<unsigned char> signature(64, 0);
    EXPECT_FALSE(InputValidator::verify_ed25519(short_pubkey, msg, signature));
}
TEST_F(CryptoExtremesTest, XEdDSALowOrderPoints) {
    std::vector<unsigned char> u0(32, 0);
    std::vector<unsigned char> signature(64, 0xAA);
    EXPECT_FALSE(InputValidator::verify_xeddsa(u0, msg, signature));
    std::vector<unsigned char> u1(32, 0);
    u1[0] = 1;
    EXPECT_FALSE(InputValidator::verify_xeddsa(u1, msg, signature));
}
TEST_F(CryptoExtremesTest, MalformedSignature) {
    std::vector<unsigned char> pubkey(32, 0xEE);
    std::vector<unsigned char> signature(63, 0);  
    EXPECT_FALSE(InputValidator::verify_ed25519(pubkey, msg, signature));
    std::vector<unsigned char> long_signature(65, 0);  
    EXPECT_FALSE(InputValidator::verify_ed25519(pubkey, msg, long_signature));
}
TEST_F(CryptoExtremesTest, NonCanonicalPoints) {
    std::vector<unsigned char> non_canonical(32, 0xFF); 
    std::vector<unsigned char> signature(64, 0);
    EXPECT_FALSE(InputValidator::verify_ed25519(non_canonical, msg, signature));
}
