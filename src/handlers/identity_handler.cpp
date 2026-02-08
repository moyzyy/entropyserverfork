#include "handlers/identity_handler.hpp"
#include <boost/beast/core/detail/base64.hpp>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include "security_logger.hpp"
#include "input_validator.hpp"
#include "pow_verifier.hpp"

namespace entropy {

// Blinds an IP address using SHA-256.
std::string IdentityHandler::blind_ip(const std::string& ip, const std::string& salt) {
    std::string data = ip + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Validates the Proof-of-Work (PoW) solution.
bool IdentityHandler::validate_pow(const http::request<http::string_body>& req, RateLimiter& rate_limiter, const std::string& remote_addr, int target_difficulty, const std::string& context) {
    auto seed_it = req.find("X-PoW-Seed");
    auto nonce_it = req.find("X-PoW-Nonce");
    
    if (seed_it == req.end() || nonce_it == req.end()) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "Missing PoW headers");
        return false;
    }
    
    std::string seed(seed_it->value());
    std::string nonce(nonce_it->value());

    
    if (seed.length() != 64 || !InputValidator::is_valid_hex(seed, 64)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "Invalid PoW seed format");
        return false;
    }
    
    if (nonce.length() > 32 || !std::all_of(nonce.begin(), nonce.end(), ::isdigit)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "Invalid PoW nonce format");
        return false;
    }

    if (seed.empty() || !rate_limiter.consume_challenge(seed)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::REPLAY_ATTEMPT,
                          remote_addr, "Challenge seed already consumed or invalid");
        return false;
    }

    
    if (!::entropy::PoWVerifier::verify(seed, nonce, context, target_difficulty)) {
        SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::POW_FAILURE,
                          remote_addr, "PoW verification failed (incorrect solution or difficulty mismatch)");
        return false;
    }
    
    return true;
}

http::response<http::string_body> IdentityHandler::handle_rate_limited(const RateLimitResult& res_info, unsigned version) {
    json::object response;
    response["error"] = "Rate limit exceeded";
    response["retry_after"] = res_info.reset_after_sec;
    response["limit"] = res_info.limit;
    
    http::response<http::string_body> res{http::status::too_many_requests, version};
    res.set(http::field::content_type, "application/json");
    res.set(http::field::retry_after, std::to_string(res_info.reset_after_sec));
    
    res.set("X-RateLimit-Limit", std::to_string(res_info.limit));
    res.set("X-RateLimit-Remaining", "0");
    res.set("X-RateLimit-Reset", std::to_string(std::time(nullptr) + res_info.reset_after_sec));
    
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    if (res_info.reset_after_sec >= 60) {
        res.keep_alive(false);
    }
    
    add_security_headers(res);
    add_cors_headers(res); 
    
    return res;
}

http::response<http::string_body> IdentityHandler::handle_keys_upload(const http::request<http::string_body>& req, const std::string& remote_addr) {
    if (req.body().size() > 64 * 1024) { 
        json::object error;
        error["error"] = "Payload too large";
        http::response<http::string_body> res{http::status::payload_too_large, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }

    try {
        auto json_val = InputValidator::safe_parse_json(req.body());
        if (!json_val.is_object()) throw std::runtime_error("Not an object");
        
        auto& obj = json_val.as_object();
        
        // Enforce resource quotas to prevent exhaustion.
        if (obj.contains("preKeys") && obj["preKeys"].is_array()) {
            if (obj["preKeys"].as_array().size() > config_.max_prekeys_per_upload) {
                json::object error;
                error["error"] = "Too many pre-keys per upload (Max: " + std::to_string(config_.max_prekeys_per_upload) + ")";
                http::response<http::string_body> res{http::status::bad_request, req.version()};
                res.set(http::field::content_type, "application/json");
                res.body() = json::serialize(error);
                res.prepare_payload();
                add_security_headers(res);
                add_cors_headers(res, &req);
                return res;
            }
        }

        std::string user_hash;
        if (obj.contains("identity_hash") && obj["identity_hash"].is_string()) {
             user_hash = std::string(obj["identity_hash"].as_string());
        }

        // Validate presence of required cryptographic keys.
        if (!obj.contains("pq_identityKey") || !obj.contains("signedPreKey") || !obj.at("signedPreKey").as_object().contains("pq_publicKey")) {
             json::object error;
             error["error"] = "Post-Quantum Handshake Keys Required";
             http::response<http::string_body> res{http::status::bad_request, req.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res, &req);
             return res;
        }
        
        if (!InputValidator::is_valid_hash(user_hash)) {
             json::object error;
             error["error"] = "Invalid identity_hash format";
             http::response<http::string_body> res{http::status::bad_request, req.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res, &req);
             return res;
        }

        int intensity_penalty = 0;
        int intensity = redis_.get_registration_intensity();
        if (intensity > 10) intensity_penalty = 2;
        if (intensity > 50) intensity_penalty = 4;
        if (intensity > 200) intensity_penalty = 8;
        
        long long age = redis_.get_account_age(user_hash);
        int required_difficulty = PoWVerifier::get_required_difficulty(intensity_penalty, age);

        // Verify PoW is bound to the identity_hash.
        if (!validate_pow(req, rate_limiter_, remote_addr, required_difficulty, user_hash)) {
             SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                remote_addr, "Keys upload rejected: invalid PoW or context binding");
             json::object error;
             error["error"] = "Invalid or Missing Proof-of-Work (Unbound)";
             http::response<http::string_body> res{http::status::unauthorized, req.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res, &req);
             return res;
        }

        // Verify identity hash matches the identity key.
        if (obj.contains("identityKey") && obj["identityKey"].is_string()) {
            std::string ik_b64 = std::string(obj["identityKey"].as_string());
            
            std::vector<unsigned char> decoded_key;
            decoded_key.resize(boost::beast::detail::base64::decoded_size(ik_b64.size()));
            auto result = boost::beast::detail::base64::decode(decoded_key.data(), ik_b64.c_str(), ik_b64.size());
            decoded_key.resize(result.first);
            
            if (result.first > 0) {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(decoded_key.data(), decoded_key.size(), hash);
                std::stringstream ss;
                for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                
                if (ss.str() != user_hash) {
                    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                      remote_addr, "Keys upload: identity_hash mismatch with identityKey");
                    json::object error;
                    error["error"] = "Cryptographic identity mismatch";
                    http::response<http::string_body> res{http::status::forbidden, req.version()};
                    res.set(http::field::content_type, "application/json");
                    res.body() = json::serialize(error);
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res, &req);
                    return res;
                }

                // Verify self-signed bundle signature if provided (Zero-Knowledge Ownership)
                if (obj.contains("bundle_signature") && obj["bundle_signature"].is_string()) {
                    std::string sig_b64 = std::string(obj["bundle_signature"].as_string());
                    std::vector<unsigned char> decoded_sig;
                    decoded_sig.resize(boost::beast::detail::base64::decoded_size(sig_b64.size()));
                    auto sig_res = boost::beast::detail::base64::decode(decoded_sig.data(), sig_b64.c_str(), sig_b64.size());
                    decoded_sig.resize(sig_res.first);
     
                    json::object sign_obj;
                    sign_obj["identityKey"] = obj["identityKey"];
                    sign_obj["pq_identityKey"] = obj["pq_identityKey"];
                    sign_obj["signedPreKey"] = obj["signedPreKey"];
                    sign_obj["preKeys"] = obj["preKeys"];
                    
                    std::string sign_data = json::serialize(sign_obj);
                    std::vector<unsigned char> msg_vec(sign_data.begin(), sign_data.end());

                    if (!InputValidator::verify_ed25519(decoded_key, msg_vec, decoded_sig)) {
                        SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE,
                                          remote_addr, "Keys upload: Invalid bundle signature");
                        json::object error;
                        error["error"] = "Invalid bundle signature";
                        http::response<http::string_body> res{http::status::forbidden, req.version()};
                        res.set(http::field::content_type, "application/json");
                        res.body() = json::serialize(error);
                        res.prepare_payload();
                        add_security_headers(res);
                        add_cors_headers(res, &req);
                        return res;
                    }
                }
            }
        }
        
        if (!key_storage_.store_bundle(user_hash, req.body())) {
             json::object error;
             error["error"] = "Storage Unavailable";
             http::response<http::string_body> res{http::status::service_unavailable, req.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res, &req);
             return res;
        }
        
        json::object response;
        response["status"] = "success";
        
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(response);
        res.prepare_payload();
        
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
        
    } catch (const std::exception& e) {
        json::object error;
        error["error"] = "Invalid JSON";
        
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }
}

http::response<http::string_body> IdentityHandler::handle_keys_fetch(const http::request<http::string_body>& req, const std::string& remote_addr) {
    std::string target = std::string(req.target());
    std::string users_param;
    
    // Parse 'user' comma-separated list from query parameters
    size_t user_pos = target.find("user=");
    if (user_pos != std::string::npos) {
        users_param = std::string(target.substr(user_pos + 5));
        size_t amp_pos = users_param.find('&');
        if (amp_pos != std::string::npos) users_param = users_param.substr(0, amp_pos);
        users_param = InputValidator::url_decode(users_param);
    }

    SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                       remote_addr, "Key fetch request for: " + users_param);

    std::vector<std::string> user_hashes;
    std::stringstream ss(users_param);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty() && InputValidator::is_valid_hash(item)) {
            user_hashes.push_back(item);
        }
    }

    if (user_hashes.empty()) {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        add_security_headers(res);
        add_cors_headers(res, &req);
        res.prepare_payload();
        return res;
    }

    // Limit batch size to prevent excessive resource consumption.
    if (user_hashes.size() > 10) user_hashes.resize(10);

    // Optimized single-user fetch
    if (user_hashes.size() == 1) {
        std::string bundle = key_storage_.get_bundle(user_hashes[0]);
        if (bundle.empty()) {
            SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                               remote_addr, "Key bundle NOT FOUND for: " + user_hashes[0]);
            http::response<http::string_body> res{http::status::not_found, req.version()};
            add_security_headers(res);
            add_cors_headers(res, &req);
            res.prepare_payload();
            return res;
        }

        SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                           remote_addr, "Key bundle retrieved for: " + user_hashes[0] + " (Size: " + std::to_string(bundle.size()) + ")");
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = bundle;
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    } else {
        // Multi-user batch fetch
        json::object results;
        for (const auto& h : user_hashes) {
            std::string b = key_storage_.get_bundle(h);
            if (!b.empty()) {
                try {
                    results[h] = InputValidator::safe_parse_json(b);
                } catch(...) {}
            }
        }
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(results);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }
}

http::response<http::string_body> IdentityHandler::handle_keys_random(const http::request<http::string_body>& req, const std::string& remote_addr) {
    if (!validate_pow(req, rate_limiter_, remote_addr, 2)) {
        json::object error;
        error["error"] = "Proof-of-Work required for decoy discovery (Difficulty: 2)";
        http::response<http::string_body> res{http::status::unauthorized, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }

    std::string target = std::string(req.target());
    int count = 5;
    
    size_t count_pos = target.find("count=");
    if (count_pos != std::string::npos) {
        try {
            std::string sub = target.substr(count_pos + 6);
            size_t amp = sub.find('&');
            if (amp != std::string::npos) sub = sub.substr(0, amp);
            count = std::stoi(sub);
        } catch(...) {}
    }

    if (count < 1) count = 1;
    if (count > 10) count = 10;

    auto hashes = redis_.get_random_user_hashes(count);
    json::array arr;
    for (const auto& h : hashes) arr.push_back(json::value(h));
    
    json::object response;
    response["hashes"] = arr;

    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    add_security_headers(res);
    add_cors_headers(res, &req);
    return res;
}

http::response<http::string_body> IdentityHandler::handle_nickname_register(const http::request<http::string_body>& req, const std::string& remote_addr) {
    try {
        auto json_val = InputValidator::safe_parse_json(req.body());
        if (!json_val.is_object()) throw std::runtime_error("Not an object");
        auto& obj = json_val.as_object();
        
        std::string nickname;
        if (obj.contains("nickname") && obj["nickname"].is_string()) {
            nickname = std::string(obj["nickname"].as_string());
        }
        
        std::string user_hash;
        if (obj.contains("identity_hash") && obj["identity_hash"].is_string()) {
            user_hash = std::string(obj["identity_hash"].as_string());
        }
        
        if (!InputValidator::is_valid_alphanumeric(nickname) || nickname.length() < 3 || nickname.length() > config_.max_nickname_length) {
            json::object error;
            error["error"] = "Invalid nickname: 3-" + std::to_string(config_.max_nickname_length) + " alphanumeric chars only";
            http::response<http::string_body> res{http::status::bad_request, req.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res, &req);
            return res;
        }

        if (!InputValidator::is_valid_hash(user_hash)) {
             json::object error;
             error["error"] = "Invalid identity_hash";
             http::response<http::string_body> res{http::status::bad_request, req.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res, &req);
             return res;
        }

        // Signature verification skipped for plaintext mode

        int intensity_penalty = 0;
        int intensity = redis_.get_registration_intensity();
        if (intensity > 10) intensity_penalty = 2;
        if (intensity > 50) intensity_penalty = 4;
        if (intensity > 200) intensity_penalty = 8;
        
        long long age = redis_.get_account_age(user_hash);

        int required_difficulty = PoWVerifier::get_difficulty_for_nickname(nickname, intensity_penalty, age);
        if (!validate_pow(req, rate_limiter_, remote_addr, required_difficulty, nickname)) {
             json::object error;
             error["error"] = "Invalid or Missing Proof-of-Work (Target: " + std::to_string(required_difficulty) + ")";
             http::response<http::string_body> res{http::status::unauthorized, req.version()};
             res.set(http::field::content_type, "application/json");
             res.body() = json::serialize(error);
             res.prepare_payload();
             add_security_headers(res);
             add_cors_headers(res, &req);
             return res;
        }

        SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                           remote_addr, "Registering nickname: " + nickname + " for hash: " + user_hash);

        if (redis_.register_nickname(nickname, user_hash)) {
            json::object response;
            response["status"] = "success";
            response["nickname"] = nickname;
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(response);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res, &req);
            return res;
        } else {
            json::object error;
            error["error"] = "Nickname already taken";
            http::response<http::string_body> res{http::status::conflict, req.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res, &req);
            return res;
        }

    } catch (...) {
        json::object error;
        error["error"] = "Invalid JSON";
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }
}

http::response<http::string_body> IdentityHandler::handle_nickname_lookup(const http::request<http::string_body>& req, const std::string& remote_addr) {
    std::string target = std::string(req.target());
    std::string names_param;
    
    size_t name_pos = target.find("name=");
    if (name_pos != std::string::npos) {
        names_param = std::string(target.substr(name_pos + 5));
        size_t amp_pos = names_param.find('&');
        if (amp_pos != std::string::npos) names_param = names_param.substr(0, amp_pos);
    }

    std::vector<std::string> nicknames;
    {
        std::stringstream ss(names_param);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty()) nicknames.push_back(item);
        }
    }

    SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                       remote_addr, "Nickname lookup requested for: " + names_param);

    names_param = InputValidator::url_decode(names_param);

    if (nicknames.empty()) {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        add_security_headers(res);
        add_cors_headers(res, &req);
        res.prepare_payload();
        return res;
    }

    if (nicknames.size() > 10) nicknames.resize(10);

    if (nicknames.size() == 1) {
        std::string user_hash = redis_.resolve_nickname(nicknames[0]);
        if (user_hash.empty()) {
            // Fallback: If not found as nickname, check if it's already a valid hash
            if (InputValidator::is_valid_hash(nicknames[0])) {
                user_hash = nicknames[0];
            } else {
                SecurityLogger::log(SecurityLogger::Level::WARNING, SecurityLogger::EventType::INVALID_INPUT,
                                   remote_addr, "Nickname not found in Redis: " + nicknames[0]);
                http::response<http::string_body> res{http::status::not_found, req.version()};
                add_security_headers(res);
                add_cors_headers(res, &req);
                res.prepare_payload();
                return res;
            }
        }
        SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS,
                           remote_addr, "Nickname resolved: " + nicknames[0] + " -> " + user_hash);
        json::object response;
        response["identity_hash"] = user_hash;
        response["nickname"] = nicknames[0];
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(response);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    } else {
        json::object results;
        for (const auto& nick : nicknames) {
            std::string h = redis_.resolve_nickname(nick);
            if (!h.empty()) results[nick] = h;
        }
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(results);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }
}

http::response<http::string_body> IdentityHandler::handle_pow_challenge(const http::request<http::string_body>& req, const std::string& remote_addr) {
    std::string seed = rate_limiter_.issue_challenge(60);
    std::string target = std::string(req.target());
    
    int intensity_penalty = 0;
    int intensity = redis_.get_registration_intensity();
    if (intensity > 10) intensity_penalty = 2;
    if (intensity > 50) intensity_penalty = 4;
    if (intensity > 200) intensity_penalty = 8;
    
    long long age = 0;
    size_t hash_pos = target.find("identity_hash=");
    if (hash_pos != std::string::npos) {
        std::string id_hash = std::string(target.substr(hash_pos + 14));
        size_t amp_pos = id_hash.find('&');
        if (amp_pos != std::string::npos) id_hash = id_hash.substr(0, amp_pos);
        if (!id_hash.empty()) {
            id_hash = InputValidator::url_decode(id_hash);
            age = redis_.get_account_age(id_hash);
        }
    }

    int difficulty = PoWVerifier::get_required_difficulty(intensity_penalty, age);
    
    size_t nick_pos = target.find("nickname=");
    if (nick_pos != std::string::npos) {
        std::string nick = std::string(target.substr(nick_pos + 9));
        size_t amp_pos = nick.find('&');
        if (amp_pos != std::string::npos) nick = nick.substr(0, amp_pos);
        if (!nick.empty()) {
            nick = InputValidator::url_decode(nick);
            difficulty = PoWVerifier::get_difficulty_for_nickname(nick, intensity_penalty, age);
        }
    }
    
    json::object response;
    response["seed"] = seed;
    response["difficulty"] = difficulty;
    
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::content_type, "application/json");
    res.body() = json::serialize(response);
    res.prepare_payload();
    
    add_security_headers(res);
    add_cors_headers(res, &req);
    
    return res;
}

http::response<http::string_body> IdentityHandler::handle_account_burn(const http::request<http::string_body>& req, const std::string& remote_addr) {
    try {
        auto json_val = InputValidator::safe_parse_json(req.body());
        if (!json_val.is_object()) throw std::runtime_error("Invalid payload");
        auto& obj = json_val.as_object();
        
        std::string user_hash;
        if (obj.contains("identity_hash") && obj["identity_hash"].is_string()) {
            user_hash = std::string(obj["identity_hash"].as_string());
        }

        // Verify PoW (difficulty 5) for burn request.
        if (!validate_pow(req, rate_limiter_, remote_addr, 5, user_hash)) { 
            json::object error;
            error["error"] = "Invalid PoW for burn request";
            http::response<http::string_body> res{http::status::unauthorized, req.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(error);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res, &req);
            return res;
        }

        // Verify signature over "BURN:<user_hash>" using the identity key.
        if (obj.contains("identityKey") && obj["identityKey"].is_string()) {
            std::string ik_b64 = std::string(obj["identityKey"].as_string());
            
            std::vector<unsigned char> decoded_key;
            decoded_key.resize(boost::beast::detail::base64::decoded_size(ik_b64.size()));
            auto result = boost::beast::detail::base64::decode(decoded_key.data(), ik_b64.c_str(), ik_b64.size());
            decoded_key.resize(result.first);

            if (result.first > 0) {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(decoded_key.data(), decoded_key.size(), hash);
                std::stringstream ss;
                for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                if (ss.str() != user_hash) {
                    http::response<http::string_body> res{http::status::forbidden, req.version()};
                    res.prepare_payload();
                    add_security_headers(res);
                    add_cors_headers(res, &req);
                    return res;
                }

                if (!obj.contains("signature") || !obj["signature"].is_string()) throw std::runtime_error("Signature missing");
                
                std::string sig_b64 = std::string(obj.at("signature").as_string());
                std::vector<unsigned char> decoded_sig;
                decoded_sig.resize(boost::beast::detail::base64::decoded_size(sig_b64.size()));
                auto sig_res = boost::beast::detail::base64::decode(decoded_sig.data(), sig_b64.c_str(), sig_b64.size());
                decoded_sig.resize(sig_res.first);

                std::string msg = "BURN:" + user_hash;
                std::vector<unsigned char> msg_vec(msg.begin(), msg.end());
                if (!InputValidator::verify_ed25519(decoded_key, msg_vec, decoded_sig)) {
                      throw std::runtime_error("Invalid signature");
                }
            }
        } else {
            throw std::runtime_error("identityKey required");
        }

        // Atomically purge account.
        if (redis_.burn_account(user_hash)) {
            SecurityLogger::log(SecurityLogger::Level::CRITICAL, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY,
                                remote_addr, "Account burned and purged: " + user_hash);
            json::object ok;
            ok["status"] = "account_purged";
            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::content_type, "application/json");
            res.body() = json::serialize(ok);
            res.prepare_payload();
            add_security_headers(res);
            add_cors_headers(res, &req);
            return res;
        }

        http::response<http::string_body> res{http::status::internal_server_error, req.version()};
        res.prepare_payload();
        return res;
    } catch (const std::exception& e) {
        json::object error;
        error["error"] = e.what();
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::content_type, "application/json");
        res.body() = json::serialize(error);
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    } catch (...) {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.prepare_payload();
        add_security_headers(res);
        add_cors_headers(res, &req);
        return res;
    }
}


} // namespace entropy
