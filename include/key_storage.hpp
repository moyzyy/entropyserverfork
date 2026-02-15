#pragma once

#include <string>
#include <map>
#include <mutex>
#include <vector>

namespace entropy {

class KeyStorage {
public:
    virtual ~KeyStorage() = default;
    
    // stores a public key bundle.

    virtual bool store_bundle(const std::string& user_hash, const std::string& bundle_json) = 0;

    virtual std::string get_bundle(const std::string& user_hash) = 0;
};

} 
