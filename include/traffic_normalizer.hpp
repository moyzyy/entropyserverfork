#pragma once

#include <string>
#include <boost/json.hpp>

namespace entropy {

class TrafficNormalizer {
public:
    static void pad_json(boost::json::object& obj, size_t target_size);
    static void pad_serialized_json(std::string& json_str, size_t target_size);
    static void pad_binary(std::string& data, size_t target_size);
};

}
