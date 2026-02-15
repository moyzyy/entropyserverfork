#pragma once

#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <iomanip>
#include <sstream>
#include <chrono>
#include "metrics.hpp"
#include <algorithm>
#include <cstring>


namespace entropy {

class PoWVerifier {
public:
    static constexpr int BASE_DIFFICULTY = 4; // number of required leading hex zeros
    
    /**
     * Rewards older accounts with lower difficulty; high load increases difficulty.
     */
    static int get_required_difficulty(int intensity_penalty = 0, long long account_age = 0) {
        size_t connections = static_cast<size_t>(MetricsRegistry::instance().get_gauge("active_connections"));
        int base = BASE_DIFFICULTY + intensity_penalty;
        
        // Reward long-term accounts (>180 days and >30 days)
        if (account_age > 15552000) base -= 2; 
        else if (account_age > 2592000) base -= 1; 
        
        // Ensure difficulty never drops below a safe minimum
        base = std::max(BASE_DIFFICULTY - 2, base);

        // Scale difficulty based on active connection count (Server Load)
        if (connections > 5000) return base + 3; 
        if (connections > 1000) return base + 2; 
        
        return base;
    }

    /**
     * Shorter nicknames require higher work to prevent squatting.
     */
    static int get_difficulty_for_nickname(const std::string& nickname, int intensity_penalty = 0, long long account_age = 0) {
        int base = get_required_difficulty(intensity_penalty, account_age);
        if (nickname.length() <= 5) return base + 3; 
        if (nickname.length() <= 7) return base + 2; 
        if (nickname.length() <= 9) return base + 1;
        return base;
    }

    /**
     * Verifies PoW solution for given difficulty.
     */
    static bool verify(std::string_view seed, std::string_view nonce, std::string_view context = "", int target_difficulty = -1) {
        if (seed.empty() || nonce.empty()) return false;
        
        if (target_difficulty == -1) {
            target_difficulty = get_required_difficulty();
        }

        std::string input;
        input.reserve(seed.size() + context.size() + nonce.size());
        input += seed;
        input += context;
        input += nonce;
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

        // Count leading hex zeros
        int zeros = 0;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            unsigned char byte = hash[i];
            if (byte == 0) {
                zeros += 2;
            } else {
                if ((byte & 0xF0) == 0) zeros += 1;
                break;
            }
        }

        return zeros >= target_difficulty;
    }
};

}
