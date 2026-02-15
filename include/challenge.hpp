#pragma once

#include <string>
#include <random>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>

namespace entropy {

class ChallengeGenerator {
public:
    static std::string generate_seed() {
        unsigned char buffer[32];
        if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
            throw std::runtime_error("CSPRNG Failure - Entropy Exhausted");
        }
        
        std::stringstream ss;
        for (int i = 0; i < 32; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
        }
        return ss.str();
    }
};

} 
