#include <gtest/gtest.h>
#include "input_validator.hpp"
using namespace entropy;
TEST(InputValidatorTest, HexValidation) {
    EXPECT_TRUE(InputValidator::is_valid_hex("abc123DEF"));
    EXPECT_TRUE(InputValidator::is_valid_hex("0123456789abcdef", 16));
    EXPECT_FALSE(InputValidator::is_valid_hex("gh123"));
    EXPECT_FALSE(InputValidator::is_valid_hex("abc", 4));
}
TEST(InputValidatorTest, HashValidation) {
    std::string valid_hash(64, 'a');
    EXPECT_TRUE(InputValidator::is_valid_hash(valid_hash));
    std::string invalid_hash(63, 'a');
    EXPECT_FALSE(InputValidator::is_valid_hash(invalid_hash));
    EXPECT_FALSE(InputValidator::is_valid_hash("invalid"));
}
TEST(InputValidatorTest, AlphanumericValidation) {
    EXPECT_TRUE(InputValidator::is_valid_alphanumeric("user_123-name"));
    EXPECT_FALSE(InputValidator::is_valid_alphanumeric("user@name"));
    EXPECT_FALSE(InputValidator::is_valid_alphanumeric(""));
}
TEST(InputValidatorTest, Sanitization) {
    EXPECT_EQ(InputValidator::sanitize_field("hello<world>!", 11), "hello world");
    EXPECT_EQ(InputValidator::sanitize_field("valid_123", 20), "valid_123");
}
TEST(InputValidatorTest, URLDecode) {
    EXPECT_EQ(InputValidator::url_decode("hello%20world"), "hello world");
    EXPECT_EQ(InputValidator::url_decode("user+name"), "user name");
    EXPECT_EQ(InputValidator::url_decode("%41%42%43"), "ABC");
}
TEST(InputValidatorTest, Ed25519Basic) {
    std::vector<unsigned char> pubkey(32, 0);
    std::vector<unsigned char> message = {'h', 'e', 'l', 'l', 'o'};
    std::vector<unsigned char> signature(64, 0);
    EXPECT_FALSE(InputValidator::verify_ed25519(pubkey, message, signature));
}
