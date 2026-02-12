#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <sstream>
#include <iostream>
#include "security_logger.hpp"
using namespace entropy;
class LoggingAuditTest : public ::testing::Test {
protected:
    std::streambuf* old_cout;
    std::streambuf* old_cerr;
    std::stringstream captured_cout;
    std::stringstream captured_cerr;
    void SetUp() override {
        old_cout = std::cout.rdbuf(captured_cout.rdbuf());
        old_cerr = std::cerr.rdbuf(captured_cerr.rdbuf());
    }
    void TearDown() override {
        std::cout.rdbuf(old_cout);
        std::cerr.rdbuf(old_cerr);
    }
};
TEST_F(LoggingAuditTest, ThreadSafeLogging) {
    const int num_threads = 10;
    const int logs_per_thread = 50;
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([i]() {
            for (int j = 0; j < logs_per_thread; ++j) {
                SecurityLogger::log(SecurityLogger::Level::INFO, 
                                  SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, 
                                  "1.2.3." + std::to_string(i), 
                                  "Thread " + std::to_string(i) + " log " + std::to_string(j));
            }
        });
    }
    for (auto& t : threads) t.join();
    std::string output = captured_cout.str();
    int line_count = 0;
    std::stringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty()) line_count++;
    }
    EXPECT_GE(line_count, num_threads * logs_per_thread);
}
TEST_F(LoggingAuditTest, LogLevelFiltering) {
    SecurityLogger::set_min_level(SecurityLogger::Level::ERROR);
    SecurityLogger::log(SecurityLogger::Level::INFO, SecurityLogger::EventType::AUTH_SUCCESS, "1.1.1.1", "Should hide");
    SecurityLogger::log(SecurityLogger::Level::ERROR, SecurityLogger::EventType::AUTH_FAILURE, "2.2.2.2", "Should show");
    EXPECT_TRUE(captured_cout.str().empty());
    EXPECT_FALSE(captured_cerr.str().empty());
    EXPECT_TRUE(captured_cerr.str().find("Should show") != std::string::npos);
    SecurityLogger::set_min_level(SecurityLogger::Level::INFO);
}
TEST_F(LoggingAuditTest, MandatoryFormatIntegrity) {
    SecurityLogger::log(SecurityLogger::Level::CRITICAL, SecurityLogger::EventType::SUSPICIOUS_ACTIVITY, "8.8.8.8", "audit_msg");
    std::string output = captured_cerr.str();
    EXPECT_TRUE(output.find("UTC") != std::string::npos);
    EXPECT_TRUE(output.find("[CRIT]") != std::string::npos);
    EXPECT_TRUE(output.find("[SUSPICIOUS]") != std::string::npos);
    EXPECT_TRUE(output.find("ip=anon_") != std::string::npos);
    EXPECT_TRUE(output.find("msg=\"audit_msg\"") != std::string::npos);
}
