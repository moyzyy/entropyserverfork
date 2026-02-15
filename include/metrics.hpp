#pragma once

#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <sstream>

namespace entropy {

class MetricsRegistry {
public:
    static MetricsRegistry& instance() {
        static MetricsRegistry instance;
        return instance;
    }

    void increment_counter(const std::string& name, double value = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        counters_[name] += value;
    }

    void set_gauge(const std::string& name, double value) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] = value;
    }
    
    void increment_gauge(const std::string& name, double value = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] += value;
    }
    
    void decrement_gauge(const std::string& name, double value = 1.0) {
        std::lock_guard<std::mutex> lock(mutex_);
        gauges_[name] -= value;
    }

    double get_gauge(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = gauges_.find(name);
        return (it != gauges_.end()) ? it->second : 0.0;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        counters_.clear();
        gauges_.clear();
    }

    /**
     * Serializes metrics into Prometheus exposition format.
     */
    std::string collect_prometheus() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::stringstream ss;
        
        for (const auto& [name, val] : counters_) {
            ss << "# TYPE " << name << " counter\n";
            ss << name << " " << val << "\n";
        }
        
        for (const auto& [name, val] : gauges_) {
            ss << "# TYPE " << name << " gauge\n";
            ss << name << " " << val << "\n";
        }
        
        return ss.str();
    }

private:
    MetricsRegistry() = default;
    
    std::map<std::string, double> counters_;
    std::map<std::string, double> gauges_;
    std::mutex mutex_; // Ensures consistency across high-concurrency threads
};

} 
