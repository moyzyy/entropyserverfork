# 🌌 Entropy Server

[![Status](https://img.shields.io/badge/status-active-green?style=for-the-badge&logo=statuspage)](https://github.com/Moyzy/entropy)
[![License](https://img.shields.io/badge/license-AGPLv3-blue?style=for-the-badge&logo=gnu)](./LICENSE)
[![Protocol](https://img.shields.io/badge/Architecture-Distributed-orange?style=for-the-badge)](./SPECS.md)

**Entropy Server** is a high-performance, stateless relay designed for sovereign messaging. It functions as a "Zero-Knowledge" backbone, ensuring that metadata is never stored and routing remains blinded to the network operator.

---

## ✨ What the Server Does

The Entropy Server routes encrypted messages between clients without knowing their identities or reading message contents.  

### Core Functionality
- **WebSocket Message Routing**: Routes encrypted messages to recipients using only cryptographic hash identifiers
- **Offline Message Queue**: Stores messages in Redis for offline users with automatic deletion after delivery
- **Public Key Storage**: Manages X3DH key bundles (identity keys, signed pre-keys, one-time pre-keys)
- **Nickname Registry**: Maps human-readable names to identity hashes with PoW-based anti-squatting
- **Session Tokens**: Issues reusable auth tokens to reduce repeated PoW challenges
- **Account Deletion**: Atomically purges all user data (keys, messages, nicknames) on authenticated burn requests

### Anti-Spam Protection
- **Dynamic PoW**: SHA-256 challenges scale with server load and account age
- **Rate Limiting**: Token-bucket (global) + sliding window (per-endpoint) limits
- **Flood Protection**: Per-recipient message rate limits prevent targeted spam
- **IP Blinding**: Logs use `HMAC(IP, Salt)` to enable abuse mitigation without tracking users

### Privacy Features
- **Traffic Padding**: All responses normalized to 1536 bytes to hide message sizes
- **Timing Jitter**: Random 10-50ms delays prevent correlation attacks
- **Dummy Packets**: Automatic background traffic maintains constant session profile

---

## 🛠️ Technical Stack

- **Language**: C++23 with Boost.Asio (event-driven I/O)
- **Protocols**: HTTP/REST + WebSockets over TLS 1.2+
- **Storage**: Redis 6+ (Pub/Sub for distributed routing + volatile message queues)
- **Crypto**: OpenSSL 3.0+ (Ed25519 verification, SHA-256)
- **Security**: Forward-secret TLS ciphers, HSTS/CSP headers, recursive JSON depth limits

### How It Works
1. Clients connect via WebSocket and authenticate with PoW or session tokens
2. Messages arrive as JSON envelopes with a recipient hash
3. Server routes to local connections or publishes to Redis for cross-instance delivery
4. Offline messages stored in Redis lists with TTL, deleted immediately after retrieval
5. All traffic padded and jittered to resist metadata analysis

---

## 🚀 Quick Start

### 1. Prerequisites
- **GCC 13+** or **Clang 16+**
- **Boost** 1.75+
- **OpenSSL** 3.0+
- **Redis** 6+

### 2. Build
```bash
git clone https://github.com/Moyzy/entropy.git
cd entropy/server
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 3. Deploy (Docker)
```bash
export ENTROPY_SECRET_SALT=$(openssl rand -hex 32)
docker-compose up -d
```

---

## ⚙️ Configuration

Set these environment variables before launching:

| Variable | Description | Default |
|----------|-------------|---------|
| `ENTROPY_PORT` | Port to listen on | `8080` |
| `ENTROPY_SECRET_SALT`| **CRITICAL**: The salt used for routing obfuscation. | (Required) |
| `ENTROPY_REDIS_URL` | Redis connection endpoint | `tcp://127.0.0.1:6379` |
| `ENTROPY_ALLOWED_ORIGINS`| CORS origin policy | `*` |

---

---

## 📄 License

This project is licensed under the **AGPLv3**.

---

