#include "traffic_normalizer.hpp"
#include <boost/json.hpp>
#include <random>
#include <chrono>

namespace entropy {

void TrafficNormalizer::pad_json(boost::json::object& obj, size_t target_size) {
    if (target_size == 0) target_size = 512;
    
    std::string current = boost::json::serialize(obj);
    if (current.size() >= target_size) return;
    
    size_t needed = target_size - current.size();
    if (needed < 25) return; 
    
    if (needed < 13) return;
    obj["padding"] = std::string(needed - 13, ' ');
}

void TrafficNormalizer::pad_serialized_json(std::string& json_str, size_t target_size) {
    if (json_str.empty() || target_size == 0) return;
    
    // So it can be multiples
    size_t current_size = json_str.size();
    size_t remainder = current_size % target_size;
    
    if (remainder == 0) return;
    
    size_t pad_needed = target_size - remainder;
    
    if (pad_needed < 15) {
        pad_needed += target_size;
    }
    
    if (json_str.back() == '}') {
        json_str.pop_back();
        json_str += ",\"padding\":\"";
        
        if (pad_needed >= 13) {
            json_str.append(pad_needed - 13, ' ');
        }
        json_str += "\"}";
    }
}

void TrafficNormalizer::pad_binary(std::string& data, size_t target_size) {
    if (target_size == 0) return;
    
    size_t remainder = data.size() % target_size;
    if (remainder == 0) return;
    
    size_t pad_needed = target_size - remainder;
    
    // Use padding to prevent traffic analysis
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int> dis(0, 255);
    
    for (size_t i = 0; i < pad_needed; ++i) {
        data.push_back(static_cast<char>(dis(gen)));
    }
}

}
