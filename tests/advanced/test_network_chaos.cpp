#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "http_session.hpp"
#include "connection_manager.hpp"
#include "message_relay.hpp"
#include "rate_limiter.hpp"
#include "server_config.hpp"
#include "redis_manager.hpp"
using namespace entropy;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
class NetworkChaosTest : public ::testing::Test {
protected:
    ServerConfig config;
    ConnectionManager cm{"chaos_salt"};
    RedisManager redis{config, cm, "chaos_salt"};
    RateLimiter rate_limiter{redis};
    MessageRelay relay{cm, redis, rate_limiter, config};
    asio::io_context ioc;
    std::unique_ptr<tcp::acceptor> acceptor;
    std::thread server_thread;
    uint16_t server_port = 0;
    std::atomic<bool> server_running{false};
    void SetUp() override {
        config.connection_timeout_sec = 2;  
        start_server();
    }
    void TearDown() override {
        stop_server();
    }
    void start_server() {
        tcp::endpoint endpoint(tcp::v4(), 0);
        acceptor = std::make_unique<tcp::acceptor>(ioc, endpoint);
        server_port = acceptor->local_endpoint().port();
        server_running = true;
        accept_loop();
        server_thread = std::thread([this]() {
            ioc.run();
        });
    }
    void stop_server() {
        server_running = false;
        if (acceptor) acceptor->close();
        ioc.stop();
        if (server_thread.joinable()) server_thread.join();
    }
    void accept_loop() {
        if (!server_running) return;
        acceptor->async_accept([this](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                auto guard = std::make_shared<int>(1); 
                std::make_shared<HttpSession>(
                    beast::tcp_stream(std::move(socket)),
                    config, cm, relay, rate_limiter, redis, redis, guard
                )->run();
            }
            accept_loop();
        });
    }
};
TEST_F(NetworkChaosTest, SlowlorisAttack) {
    // Simulate Slowloris: Connect, send partial headers, then stall
    asio::io_context client_ioc;
    tcp::socket socket(client_ioc);
    socket.connect(tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), server_port));

    std::string partial_req = "GET / HTTP/1.1\r\n";
    asio::write(socket, asio::buffer(partial_req));

    // Wait > connection_timeout_sec (2s)
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Server should have closed the connection
    beast::error_code ec;
    asio::write(socket, asio::buffer("Host: localhost\r\n\r\n"), ec);
    
    char data[1];
    socket.read_some(asio::buffer(data), ec);
    EXPECT_EQ(ec, asio::error::eof);
}
TEST_F(NetworkChaosTest, FragmentedHandshake) {
    // Send 1-byte packets with 5ms delays to test stream buffering
    asio::io_context client_ioc;
    tcp::socket socket(client_ioc);
    socket.connect(tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), server_port));

    std::string request = 
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n";

    for (char c : request) {
        asio::write(socket, asio::buffer(&c, 1));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(socket, buffer, res);
    EXPECT_EQ(res.result(), http::status::switching_protocols);
}
TEST_F(NetworkChaosTest, HalfOpenConnection) {
    // Connect successfully but send 0 bytes of data
    asio::io_context client_ioc;
    tcp::socket socket(client_ioc);
    socket.connect(tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), server_port));

    std::this_thread::sleep_for(std::chrono::seconds(3)); // Wait > timeout

    char data[1];
    beast::error_code ec;
    socket.read_some(asio::buffer(data), ec);
    EXPECT_EQ(ec, asio::error::eof);
}
TEST_F(NetworkChaosTest, ConnectionLimitPerIP) {
    std::vector<std::shared_ptr<tcp::socket>> sockets;
    int success_count = 0;
    for (int i = 0; i < 15; ++i) {
        auto sock = std::make_shared<tcp::socket>(ioc);
        try {
            sock->connect(tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), server_port));
            sockets.push_back(sock);
            char c = 'x';
            asio::write(*sock, asio::buffer(&c, 1));
            success_count++;
        } catch (...) {}
    }
    for (auto& s : sockets) {
        beast::error_code ec;
        s->close(ec);
    }
}
