# 🌌 Entropy Server

[![Status](https://img.shields.io/badge/status-active-green?style=for-the-badge&logo=statuspage)](https://github.com/Moyzy/entropy)
[![License](https://img.shields.io/badge/license-AGPLv3-blue?style=for-the-badge&logo=gnu)](./LICENSE)
[![Protocol](https://img.shields.io/badge/Architecture-Distributed-orange?style=for-the-badge)](./SPECS.md)

**Entropy Server** is a high-performance, stateless relay designed for sovereign messaging. It functions as a "Zero-Knowledge" backbone, ensuring that metadata is never stored and routing remains blinded to the network operator via cryptographic salts and aggressive traffic normalization.

---

## ✨ Core Features

### 🔐 Zero-Knowledge Routing
- **WebSocket Message Relay**: Routes encrypted messages between clients using identity hashes.
- **Offline Message Queue**: Temporarily stores messages in Redis for offline users with automatic 24h expiration.
- **Public Key Storage**: Manages X3DH key bundles (identity keys, pre-keys, etc.).
- **Nickname Registry**: Maps human-readable names to identity hashes with PoW-based anti-squatting.
- **Account Deletion (Burn)**: Atomically purges all user data (keys, messages, nicknames) upon a signed burn request.

### 🛡️ Aggressive Anti-Analysis & Security
- **Dynamic Proof-of-Work (PoW)**: SHA-256 challenges scale difficulty based on server load and account maturity to prevent spam.
- **Traffic Padding**: Every JSON response is normalized to exactly **1536 bytes** to hide message metadata.
- **Timing Jitter**: Random **10-50ms delays** on delivery prevent correlation attacks at network boundaries.
- **Dummy Pacing**: Automatic background traffic maintains a constant traffic profile even when the user is idle.
- **Token-Bucket Rate Limiting**: Global (per-IP) and per-identity limits backed by Redis-Lua GCRA scripts.
- **IP Blinding**: Logs and rate-limit keys use `HMAC(IP, ServerSalt)` to protect user privacy from the operator.

---

## 🛠️ Technical Stack

- **Language**: C++20/C++23
- **Primary Framework**: [Boost.Asio](https://www.boost.org/doc/libs/release/libs/asio/) & [Boost.Beast](https://www.boost.org/doc/libs/release/libs/beast/) (Event-driven I/O)
- **Networking**: WebSockets + HTTP/REST over TLS 1.2+ (OpenSSL 3.0+)
- **Storage**: Redis 6.2+ (using `redis-plus-plus` for Pub/Sub and volatile state)
- **JSON**: Boost.JSON with recursion depth protection

---

## 🚀 Getting Started

### 1. Prerequisites
- **Compiler**: GCC 13+ or Clang 16+
- **Build System**: CMake 3.20+
- **Libraries**:
  - **Boost** 1.83+ (system, thread, json)
  - **OpenSSL** 3.0+
  - **hiredis** & **redis-plus-plus** (Redis C++ client)

### 2. Build Instructions
```bash
git clone https://github.com/entropy-messenger/entropy-server.git
cd server
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### 3. Quick Run (Development)
```bash
# Run with default settings
export ENTROPY_SECRET_SALT="super_secret_deployment_salt"
./server
```

---

## ⚙️ Configuration

The server is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ENTROPY_PORT` | Port to listen on | `8080` |
| `ENTROPY_SECRET_SALT` | **CRITICAL**: The salt used for routing/IP obfuscation. | (Required) |
| `ENTROPY_REDIS_URL` | Redis connection endpoint | `tcp://127.0.0.1:6379` |
| `ENTROPY_ALLOWED_ORIGINS`| CORS origin policy (comma-separated) | `localhost,tauri://` |
| `ENTROPY_ADMIN_TOKEN` | Token for `/stats` and `/metrics` access | (None) |
| `ENTROPY_MAX_CONNS_PER_IP`| Max WebSocket connections per IP address | `10` |

### Tuning Rate Limits
You can override default rate limits (hits per 60s) via:
- `ENTROPY_LIMIT_GLOBAL`: Global request limit per IP.
- `ENTROPY_LIMIT_RELAY`: Message relay frequency.
- `ENTROPY_LIMIT_KEYS_UPLOAD`: Identity bundle upload frequency.
- `ENTROPY_LIMIT_NICK_REGISTER`: Nickname registration frequency.

---

## 📄 License

This project is licensed under the **AGPLv3**.
