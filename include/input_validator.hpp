#pragma once

#include <string>
#include <string_view>
#include <charconv>
#include <cctype>
#include <algorithm>
#include <vector>
#include <boost/json.hpp>
#include <openssl/bn.h>
#include <openssl/evp.h>

namespace entropy {

class InputValidator {
public:
    /**
     * Verifies an Ed25519 Edwards-curve signature.
     * Used for authenticating identity uploads and account-burn requests.
     */
    static bool verify_ed25519(const std::vector<unsigned char>& pubkey,
                               const std::vector<unsigned char>& message,
                               const std::vector<unsigned char>& signature) {
        if (pubkey.size() != 32 || signature.size() != 64) return false;

        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey.data(), pubkey.size());
        if (!pkey) return false;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            EVP_PKEY_free(pkey);
            return false;
        }
        
        bool result = false;

        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1) {
            if (EVP_DigestVerify(ctx, signature.data(), signature.size(), message.data(), message.size()) == 1) {
                result = true;
            }
        }

        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return result;
    }

    /**
     * Verifies an XEdDSA signature (Ed25519 signature on an X25519 public key).
     * This converts the Montgomery u-coordinate to a Twisted Edwards y-coordinate.
     */
    static bool verify_xeddsa(const std::vector<unsigned char>& x25519_pubkey,
                             const std::vector<unsigned char>& message,
                             const std::vector<unsigned char>& signature) {
        if (x25519_pubkey.size() != 32 || signature.size() != 64) return false;

        auto bn_deleter = [](BIGNUM* b) { BN_free(b); };
        auto ctx_deleter = [](BN_CTX* c) { BN_CTX_free(c); };
        
        std::unique_ptr<BN_CTX, decltype(ctx_deleter)> ctx(BN_CTX_new(), ctx_deleter);
        if (!ctx) return false;
        
        std::unique_ptr<BIGNUM, decltype(bn_deleter)> u(BN_new(), bn_deleter);
        std::vector<unsigned char> u_be = x25519_pubkey;
        std::reverse(u_be.begin(), u_be.end());
        BN_bin2bn(u_be.data(), 32, u.get());
        
        std::unique_ptr<BIGNUM, decltype(bn_deleter)> p(BN_new(), bn_deleter);
        BN_set_bit(p.get(), 255);
        BN_sub_word(p.get(), 19);
        
        const BIGNUM* one = BN_value_one();
        
        std::unique_ptr<BIGNUM, decltype(bn_deleter)> u_minus_1(BN_new(), bn_deleter);
        BN_sub(u_minus_1.get(), u.get(), one);
        BN_nnmod(u_minus_1.get(), u_minus_1.get(), p.get(), ctx.get());
        
        std::unique_ptr<BIGNUM, decltype(bn_deleter)> u_plus_1(BN_new(), bn_deleter);
        BN_add(u_plus_1.get(), u.get(), one);
        BN_nnmod(u_plus_1.get(), u_plus_1.get(), p.get(), ctx.get());
        
        std::unique_ptr<BIGNUM, decltype(bn_deleter)> inv_u_plus_1(BN_new(), bn_deleter);
        if (!BN_mod_inverse(inv_u_plus_1.get(), u_plus_1.get(), p.get(), ctx.get())) {
            return false;
        }
        
        std::unique_ptr<BIGNUM, decltype(bn_deleter)> y(BN_new(), bn_deleter);
        BN_mod_mul(y.get(), u_minus_1.get(), inv_u_plus_1.get(), p.get(), ctx.get());
        
        std::vector<unsigned char> ed_pubkey(32, 0);
        BN_bn2binpad(y.get(), ed_pubkey.data(), 32);
        
        std::reverse(ed_pubkey.begin(), ed_pubkey.end());
        ed_pubkey[31] &= 0x7F; 
        
        return verify_ed25519(ed_pubkey, message, signature);
    }

    static bool is_valid_hex(std::string_view str, size_t expected_length = 0) {
        if (str.empty()) return false;
        if (expected_length > 0 && str.length() != expected_length) return false;
        
        return std::all_of(str.begin(), str.end(), [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c));
        });
    }
    
    static bool is_valid_hash(std::string_view hash) {
        // Support both standard 32-byte hashes (64-char hex) 
        // and 33-byte identity keys (66-char hex starting with 05).
        return is_valid_hex(hash, 64) || is_valid_hex(hash, 66);
    }
    
    static bool is_valid_alphanumeric(std::string_view str) {
        if (str.empty()) return false;
        return std::all_of(str.begin(), str.end(), [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-';
        });
    }

    static std::string sanitize_field(std::string_view input, size_t max_length = 256) {
        if (input.empty()) return std::string();
        
        std::string result;
        result.reserve(std::min(input.size(), max_length));
        
        for (size_t i = 0; i < input.size() && result.size() < max_length; ++i) {
            char c = input[i];
            
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == ' ') {
                result += c;
            } else {
                result += ' '; // Replace invalid chars with space to maintain length but sanitize
            }
        }
        
        return result;
    }
    
    static bool is_within_size_limit(size_t size, size_t max_size) {
        return size <= max_size;
    }

    /**
     * Authenticated JSON Parsing with recursion depth limits to prevent stack-exhaustion.
     */
    static boost::json::value safe_parse_json(std::string_view input) {
        boost::json::parse_options opt;
        opt.max_depth = 8; 
        return boost::json::parse(input, {}, opt);
    }

    static std::string url_decode(std::string_view str) {
        std::string result;
        result.reserve(str.length());
        
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '%' && i + 2 < str.length()) {
                int hex_val = 0;
                auto hex_str = str.substr(i + 1, 2);
                auto [ptr, ec] = std::from_chars(hex_str.data(), hex_str.data() + hex_str.size(), hex_val, 16);
                if (ec == std::errc()) {
                    result += static_cast<char>(hex_val);
                    i += 2;
                } else {
                    result += '%';
                }
            } else if (str[i] == '+') {
                result += ' ';
            } else {
                result += str[i];
            }
        }
        return result;
    }
};

}
