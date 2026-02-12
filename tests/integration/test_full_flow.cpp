#include <gtest/gtest.h>
#include <boost/beast/_experimental/test/stream.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "websocket_session.hpp"
#include "connection_manager.hpp"
#include "redis_manager.hpp"
#include "message_relay.hpp"
#include "rate_limiter.hpp"
#include "handlers/identity_handler.hpp"
#include "pow_verifier.hpp"
#include "input_validator.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
using namespace entropy;
namespace net = boost::asio;
namespace beast = boost::beast;
namespace test = beast::test;
class FullFlowTest : public ::testing::Test {
protected:
    net::io_context ioc;
    ServerConfig config;
    ConnectionManager cm{"test_salt"};
    RedisManager redis{config, cm, "test_salt"};
    RateLimiter rate_limiter{redis};
    MessageRelay relay{cm, redis, rate_limiter, config};
    IdentityHandler id_handler{config, redis, redis, rate_limiter};
    void SetUp() override {
        config.secret_salt = "test_salt";
        config.admin_token = "admin_secret";
    }
    std::shared_ptr<WebSocketSession> create_session() {
        auto session = std::make_shared<WebSocketSession>(
            beast::tcp_stream(ioc), 
            cm, 
            config
        );
        return session;
    }
    std::string solve_pow(const std::string& seed, const std::string& bhash, int difficulty) {
        std::cout << "[*] Solving PoW (diff=" << difficulty << ") for seed: " << seed << "\n";
        for (int i = 0; i < 2000000; ++i) {
            std::string nonce = std::to_string(i);
            if (PoWVerifier::verify(seed, nonce, bhash, difficulty)) {
                return nonce;
            }
        }
        return "";
    }
};
TEST_F(FullFlowTest, AuthAndMessagingFlow) {
    auto alice = create_session();
    auto bob = create_session();
    std::string alice_hash = std::string(64, 'a');
    std::string bob_hash = std::string(64, 'b');
    json::object pow_req;
    pow_req["type"] = "pow_challenge";
    pow_req["identity_hash"] = alice_hash;
    auto pow_res = id_handler.handle_pow_challenge_ws(pow_req, "127.0.0.1");
    ASSERT_TRUE(pow_res.contains("seed"));
    std::string seed = std::string(pow_res["seed"].as_string());
    int diff = (int)pow_res["difficulty"].as_int64();
    std::string nonce = solve_pow(seed, alice_hash, diff);
    ASSERT_FALSE(nonce.empty());
    alice->set_user_data(alice_hash);
    alice->set_authenticated(true);
    alice->set_challenge_solved(true);
    cm.add_connection(alice_hash, alice);
    bob->set_user_data(bob_hash);
    bob->set_authenticated(true);
    bob->set_challenge_solved(true);
    cm.add_connection(bob_hash, bob);
    json::object msg;
    msg["type"] = "msg";
    msg["to"] = bob_hash;
    msg["body"] = "Hello Bob!";
    relay.relay_message(json::serialize(msg), alice);
    EXPECT_TRUE(cm.is_online(bob_hash));
}
TEST_F(FullFlowTest, NicknameFlow) {
    auto alice = create_session();
    std::string alice_hash = std::string(64, 'a');
    alice->set_user_data(alice_hash);
    alice->set_authenticated(true);
    json::object reg_req;
    reg_req["nickname"] = "alice_nick";
    reg_req["identity_hash"] = alice_hash;
    json::object lookup_req;
    lookup_req["name"] = "alice_nick";
    auto lookup_res = id_handler.handle_nickname_lookup_ws(lookup_req, "127.0.0.1");
    EXPECT_EQ(lookup_res["type"], "nickname_lookup_res");
}
TEST_F(FullFlowTest, SignatureVerificationFlow) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    size_t pub_len = 32;
    uint8_t pub[32];
    EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
    std::string message_str = "BURN_ACCOUNT:some_hash";
    std::vector<uint8_t> message(message_str.begin(), message_str.end());
    size_t sig_len = 64;
    uint8_t sig[64];
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey);
    EVP_DigestSign(md_ctx, sig, &sig_len, message.data(), message.size());
    std::vector<uint8_t> pub_vec(pub, pub + 32);
    std::vector<uint8_t> sig_vec(sig, sig + 64);
    EXPECT_TRUE(InputValidator::verify_ed25519(pub_vec, message, sig_vec));
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
}
TEST_F(FullFlowTest, LinkPreviewFlow) {
    json::object req;
    req["url"] = "https://github.com/entropy_project";
    auto res = id_handler.handle_link_preview_ws(req, "1.1.1.1");
    EXPECT_EQ(res["type"], "link_preview_res");
    EXPECT_EQ(res["status"], "proxied");
    EXPECT_EQ(res["title"], "github.com");
}
TEST_F(FullFlowTest, MulticastFlow) {
    auto sender = create_session();
    std::vector<std::string> recipients = { std::string(64, '1'), std::string(64, '2') };
    json::object msg;
    msg["type"] = "multicast";
    msg["body"] = "Mass ping";
    relay.relay_multicast(recipients, json::serialize(msg));
}
