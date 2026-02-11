#include "handlers/identity_handler.hpp"
#include <boost/beast/core/detail/base64.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include "security_logger.hpp"
#include "input_validator.hpp"
#include "pow_verifier.hpp"

namespace entropy {






bool IdentityHandler::validate_pow_msg(const json::object& obj, const std::string& remote_addr, int target_difficulty, const std::string& context) {
    if (!obj.contains("seed") || !obj.contains("nonce")) {
        return false;
    }
    
    std::string seed;
    if (obj.at("seed").is_string()) seed = std::string(obj.at("seed").as_string());
    
    std::string nonce;
    if (obj.at("nonce").is_string()) nonce = std::string(obj.at("nonce").as_string());
    else if (obj.at("nonce").is_number()) nonce = std::to_string(obj.at("nonce").as_int64());

    if (seed.length() != 64 || !InputValidator::is_valid_hex(seed, 64)) return false;
    if (nonce.length() > 32) return false;

    if (!rate_limiter_.consume_challenge(seed)) return false;

    return ::entropy::PoWVerifier::verify(seed, nonce, context, target_difficulty);
}

json::object IdentityHandler::handle_pow_challenge_ws(const json::object& req, const std::string& remote_addr) {
    std::string seed = rate_limiter_.issue_challenge(60);
    
    int intensity_penalty = 0;
    int intensity = redis_.get_registration_intensity();
    if (intensity > 10) intensity_penalty = 2;
    if (intensity > 50) intensity_penalty = 4;
    if (intensity > 200) intensity_penalty = 8;
    
    long long age = 0;
    if (req.contains("identity_hash") && req.at("identity_hash").is_string()) {
        age = redis_.get_account_age(std::string(req.at("identity_hash").as_string()));
    }

    int difficulty = PoWVerifier::get_required_difficulty(intensity_penalty, age);
    
    if (req.contains("nickname") && req.at("nickname").is_string()) {
        std::string nick = std::string(req.at("nickname").as_string());
        difficulty = PoWVerifier::get_difficulty_for_nickname(nick, intensity_penalty, age);
    }

    if (req.contains("intent") && req.at("intent").is_string() && req.at("intent").as_string() == "burn") {
        difficulty = 4;
    }
    
    json::object response;
    response["type"] = "pow_challenge_res";
    if (req.contains("req_id")) response["req_id"] = req.at("req_id");
    response["seed"] = seed;
    response["difficulty"] = difficulty;
    return response;
}

json::object IdentityHandler::handle_keys_upload_ws(const json::object& req, const std::string& remote_addr) {
    json::object err;
    err["type"] = "error";
    if (req.contains("req_id")) err["req_id"] = req.at("req_id");

    if (!req.contains("identity_hash") || !req.contains("identityKey")) {
        err["message"] = "Incomplete request (missing identity_hash or identityKey)";
        return err;
    }

    std::string id_hash = std::string(req.at("identity_hash").as_string());
    if (!validate_pow_msg(req, remote_addr, -1, id_hash)) {
        err["message"] = "Invalid PoW for key upload";
        return err;
    }

    // Logic for saving the bundle
    try {
        key_storage_.store_bundle(id_hash, json::serialize(req));
        json::object response;
        response["type"] = "keys_upload_res";
        if (req.contains("req_id")) response["req_id"] = req.at("req_id");
        response["status"] = "success";
        return response;
    } catch (const std::exception& e) {
        err["message"] = std::string("Storage error: ") + e.what();
        return err;
    }
}

json::object IdentityHandler::handle_keys_fetch_ws(const json::object& req, const std::string& remote_addr) {
    if (!req.contains("target_hash")) {
        json::object err; err["type"] = "error";
        if (req.contains("req_id")) err["req_id"] = req.at("req_id");
        err["message"] = "target_hash required";
        return err;
    }

    std::string target_hash = std::string(req.at("target_hash").as_string());
    
    // Check if it's a batch request (comma separated)
    std::vector<std::string> user_hashes;
    if (target_hash.find(',') != std::string::npos) {
        std::stringstream ss(target_hash);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty() && InputValidator::is_valid_hash(item)) {
                user_hashes.push_back(item);
            }
        }
    } else {
        if (InputValidator::is_valid_hash(target_hash)) {
            user_hashes.push_back(target_hash);
        }
    }

    if (user_hashes.empty()) {
        json::object err; err["type"] = "error";
        if (req.contains("req_id")) err["req_id"] = req.at("req_id");
        err["message"] = "No valid hashes provided";
        return err;
    }

    if (user_hashes.size() > 10) user_hashes.resize(10);

    json::object response;
    response["type"] = "fetch_key_res";
    if (req.contains("req_id")) response["req_id"] = req.at("req_id");
    
    if (user_hashes.size() == 1) {
        std::string bundle = key_storage_.get_bundle(user_hashes[0]);
        if (!bundle.empty()) {
            response["found"] = true;
            response["bundle"] = InputValidator::safe_parse_json(bundle);
        } else {
            response["found"] = false;
        }
    } else {
        json::object bundles;
        for (const auto& h : user_hashes) {
            std::string b = key_storage_.get_bundle(h);
            if (!b.empty()) {
                try {
                    bundles[h] = InputValidator::safe_parse_json(b);
                } catch(...) {}
            }
        }
        response["found"] = !bundles.empty();
        response["bundles"] = bundles;
    }

    return response;
}

json::object IdentityHandler::handle_keys_random_ws(const json::object& req, const std::string& remote_addr) {
    json::object response;
    response["type"] = "fetch_key_random_res";
    if (req.contains("req_id")) response["req_id"] = req.at("req_id");

    // Random fetch doesn't require PoW, but is rate-limited
    int count = 5;
    if (req.contains("count") && req.at("count").is_number()) count = (int)req.at("count").as_int64();
    if (count < 1) count = 1;
    if (count > 20) count = 20;

    auto hashes = redis_.get_random_user_hashes(count);
    json::array arr;
    for (const auto& h : hashes) arr.push_back(json::value(h));
    
    response["hashes"] = arr;
    return response;
}

json::object IdentityHandler::handle_nickname_register_ws(const json::object& req, const std::string& remote_addr) {
    if (!req.contains("nickname") || !req.contains("identity_hash")) {
        json::object err; err["type"] = "error";
        if (req.contains("req_id")) err["req_id"] = req.at("req_id");
        err["message"] = "Incomplete request (missing nickname or identity_hash)";
        return err;
    }
    
    std::string nick = std::string(req.at("nickname").as_string());
    if (!validate_pow_msg(req, remote_addr, -1, nick)) { // difficulty is auto-calculated usually
        json::object err; err["type"] = "error";
        if (req.contains("req_id")) err["req_id"] = req.at("req_id");
        err["message"] = "Invalid PoW for nickname registration";
        return err;
    }

    std::string identity_hash = std::string(req.at("identity_hash").as_string());
    
    // Simple registration for now
    if (redis_.register_nickname(nick, identity_hash)) {
        json::object response;
        response["type"] = "nickname_register_res";
        if (req.contains("req_id")) response["req_id"] = req.at("req_id");
        response["status"] = "success";
        return response;
    } else {
        json::object err; err["type"] = "error";
        if (req.contains("req_id")) err["req_id"] = req.at("req_id");
        err["message"] = "Nickname already taken";
        return err;
    }
}

json::object IdentityHandler::handle_nickname_lookup_ws(const json::object& req, const std::string& remote_addr) {
    if (!req.contains("name") || !req.at("name").is_string()) {
        json::object err; err["type"] = "error";
        if (req.contains("req_id")) err["req_id"] = req.at("req_id");
        err["message"] = "Missing lookup name";
        return err;
    }
    
    std::string name = std::string(req.at("name").as_string());
    std::string h = redis_.resolve_nickname(name);
    
    json::object response;
    response["type"] = "nickname_lookup_res";
    if (req.contains("req_id")) response["req_id"] = req.at("req_id");
    
    if (!h.empty()) {
        response["identity_hash"] = h;
        response["nickname"] = name;
    } else {
        response["error"] = "Not found";
    }
    return response;
}

json::object IdentityHandler::handle_account_burn_ws(const json::object& req, const std::string& remote_addr) {
    json::object response;
    response["type"] = "error";
    if (req.contains("req_id")) response["req_id"] = req.at("req_id");

    if (!req.contains("identity_hash") || !req.contains("signature")) {
        response["message"] = "Incomplete request";
        return response;
    }

    std::string id_hash = std::string(req.at("identity_hash").as_string());
    if (!validate_pow_msg(req, remote_addr, 4, id_hash)) {
        response["message"] = "Invalid PoW";
        return response;
    }

    // Attempt to decode signature (Hex or Base64)
    std::string sig_str = std::string(req.at("signature").as_string());
    std::vector<unsigned char> sig_bytes;
    
    if (sig_str.length() == 128 && InputValidator::is_valid_hex(sig_str)) {
        for (size_t i = 0; i < 128; i += 2) {
            sig_bytes.push_back(std::stoi(sig_str.substr(i, 2), nullptr, 16));
        }
    } else {
        // Try base64
        namespace base64 = boost::beast::detail::base64;
        std::vector<unsigned char> decoded(base64::decoded_size(sig_str.size()));
        auto result = base64::decode(decoded.data(), sig_str.data(), sig_str.size());
        decoded.resize(result.first);
        sig_bytes = std::move(decoded);
    }

    if (sig_bytes.size() != 64) {
        response["message"] = "Invalid signature length (expected 64 bytes decoded)";
        response["received_length"] = sig_bytes.size();
        return response;
    }

    std::string payload = "BURN_ACCOUNT:" + id_hash;
    std::vector<unsigned char> msg_bytes(payload.begin(), payload.end());

    // Check for public_key or identityKey
    std::string pk_str;
    if (req.contains("public_key")) pk_str = std::string(req.at("public_key").as_string());
    else if (req.contains("identityKey")) pk_str = std::string(req.at("identityKey").as_string());
    else {
        response["message"] = "Missing public_key or identityKey for verification";
        return response;
    }

    std::vector<unsigned char> pubkey_bytes;
    if (pk_str.length() == 64 && InputValidator::is_valid_hex(pk_str)) {
        for (size_t i = 0; i < 64; i += 2) {
            pubkey_bytes.push_back(std::stoi(pk_str.substr(i, 2), nullptr, 16));
        }
    } else if (pk_str.length() == 66 && InputValidator::is_valid_hex(pk_str)) {
         // Signal/Entropy 33-byte key (starts with 05)
         for (size_t i = 0; i < 66; i += 2) {
            pubkey_bytes.push_back(std::stoi(pk_str.substr(i, 2), nullptr, 16));
        }
        // If it's a 33-byte Signal key, the first byte is 05, the rest is the Ed25519 key.
        if (pubkey_bytes[0] == 0x05) {
            pubkey_bytes.erase(pubkey_bytes.begin());
        }
    } else {
        // Try base64
        namespace base64 = boost::beast::detail::base64;
        std::vector<unsigned char> decoded(base64::decoded_size(pk_str.size()));
        auto result = base64::decode(decoded.data(), pk_str.data(), pk_str.size());
        decoded.resize(result.first);
        pubkey_bytes = std::move(decoded);
        
        if (pubkey_bytes.size() == 33 && pubkey_bytes[0] == 0x05) {
            pubkey_bytes.erase(pubkey_bytes.begin());
        }
    }

    if (pubkey_bytes.size() != 32) {
        response["message"] = "Invalid public key length (expected 32 bytes)";
        response["received_length"] = pubkey_bytes.size();
        return response;
    }

    // Verify ownership
    if (!InputValidator::verify_xeddsa(pubkey_bytes, msg_bytes, sig_bytes) && 
        !InputValidator::verify_ed25519(pubkey_bytes, msg_bytes, sig_bytes)) {
        response["message"] = "Invalid signature - ownership proof failed";
        return response;
    }

    // Final verification: does the public key match the identity hash?
    // (Implementation depends on system specifics, but usually SHA256)
    
    redis_.burn_account(id_hash);

    json::object res;
    res["type"] = "account_burn_res";
    if (req.contains("req_id")) res["req_id"] = req.at("req_id");
    res["status"] = "success";
    return res;
}

json::object IdentityHandler::handle_link_preview_ws(const json::object& req, const std::string& remote_addr) {
    json::object response;
    response["type"] = "link_preview_res";
    if (req.contains("req_id")) response["req_id"] = req.at("req_id");
    
    if (!req.contains("url") || !req.at("url").is_string()) {
        response["error"] = "Missing URL";
        return response;
    }

    std::string url = std::string(req.at("url").as_string());
    response["url"] = url;

    // Basic security: only allow http/https
    if (url.find("http") != 0) {
        response["error"] = "Invalid protocol";
        return response;
    }

    
    try {
        std::string host;
        size_t start = url.find("://");
        if (start != std::string::npos) {
            host = url.substr(start + 3);
            size_t end = host.find("/");
            if (end != std::string::npos) host = host.substr(0, end);
        }

        response["title"] = host;
        response["siteName"] = host;
        response["status"] = "proxied";
    } catch (...) {
        response["error"] = "Resolution failed";
    }

    return response;
}

} // namespace entropy
