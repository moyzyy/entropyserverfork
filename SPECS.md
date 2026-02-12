# ⚙️ Entropy Server Architectural Specification

The Entropy Relay is a C++23, high-concurrency node designed with a **Zero-Knowledge** and **Stateless** philosophy.

## 1. DoS Protection (PoW + Token Bucket)

The server implements a two-tier protection system:
1.  **Computation Barrier**: Expensive write operations (like key uploads) require a CPU-bound Proof-of-Work solution.
2.  **Rate Limiting**: Uses a Redis-backed **Token Bucket** algorithm.
    - Limits are per-IP (global) and per-IdentityHash (specific).
    - Bursts are allowed but sustained flooding triggers a temporary ignore.

## 2. Sender-Revealed Routing

Clients communicate using **Identity Hashes** (SHA256 of their public key). In the current implementation, the server operates in a **Sender-Revealed** flow: when a user sends a message, the server attaches that user's identity hash to the package before it is relayed to the recipient. This allows the recipient to verify the sender and enables the server to enforce per-user rate limits.

## 4. Traffic Normalization (Anti-Analysis)

To prevent metadata leakage through packet sizes and timing patterns, the server implements aggressive traffic normalization:

### 4.1 Packet Padding
- **Fixed Size**: All JSON responses are padded to exactly **1536 bytes** using random whitespace
- **Binary Normalization**: Binary WebSocket messages are zero-padded to the same size threshold
- **Purpose**: Prevents observers from distinguishing message types or inferring content based on size

### 4.2 Timing Jitter
- **Random Delays**: Every message delivery includes a random **10-50ms delay** before transmission
- **Prevents Correlation**: Makes it harder to correlate incoming and outgoing messages at network boundaries
- **Implementation**: Uses `Boost.Asio` steady timers with per-message randomization

### 4.3 Dummy Traffic (Pacing)
- **Automatic Background Packets**: WebSocket sessions send `dummy_pacing` JSON packets every **500ms** during idle periods
- **Idle Threshold**: Dummy traffic only triggers if the session has been idle for less than **5 seconds**
- **Constant Profile**: Maintains a steady traffic rate to mask when real messages are being sent/received
- **Response**: Server replies with equally-sized `dummy_ack` packets

### 4.4 Implementation Details
```cpp
// From message_relay.cpp
static const size_t REQUIRED_PACKET_SIZE = 1536;
static const size_t SYSTEM_MSG_PADDING = 1536;

// Random jitter (10-50ms)
std::uniform_int_distribution<> dis(10, 50);
timer->expires_after(std::chrono::milliseconds(dis(gen)));
```

---

## 5. Forensic Burn

The server supports a true "Nuclear Option."
- Upon a validated `burn` request, the server executes a Lua script on the Redis cluster.
- This script atomically deletes every trace of the identity:
  1. Key bundles.
  2. Queued (offline) messages.
  3. Active session state.
  4. Rate limit counters.

## 6. Zero Persistence

By design, the Entropy Server does not use a persistent disk database for user data.
- **Volatile Storage**: All ephemeral state is stored in RAM (via Redis).
- **TTL Enforcement**: Key bundles and offline messages have a strict TTL (e.g., 30 days). If a user doesn't check in, their data is naturally recycled.
- **Log Blinding**: IP addresses in logs are SHA-256 hashed with a rotating daily salt to ensure forward secrecy for connection metadata.

## 7. Network Stack

- **I/O Engine**: `Boost.Asio` with a multi-threaded `io_context` pool.
- **Encryption**: TLS 1.3 is enforced for all traffic.
- **Memory Safety**: Uses C++ shared pointers and RAII to ensure zero leaks in high-uptime environments.

## 8. REST API Endpoints

The server exposes HTTP endpoints for identity and key management:

- **`GET /pow/challenge`**: Issues a Proof-of-Work challenge with dynamic difficulty based on load
- **`POST /keys/upload`**: Accepts X3DH key bundles (requires valid PoW solution in headers)
- **`GET /keys/fetch?user=<hash>`**: Returns public key bundles for one or more identity hashes
- **`GET /keys/random?count=N`**: Returns N random identity hashes for decoy traffic
- **`POST /nickname/register`**: Registers a human-readable nickname (requires PoW with difficulty based on nickname length)
- **`GET /nickname/lookup?nick=<name>`**: Resolves a nickname to its identity hash
- **`POST /account/burn`**: Permanently deletes all server-side data for an identity (requires Ed25519 signature)

## 9. WebSocket Message Protocol

Once authenticated, clients maintain a persistent WebSocket connection for real-time messaging:

### Message Types (Client → Server)
- **`auth`**: Authenticates with PoW or session token
- **`relay`**: Sends an encrypted envelope to a recipient hash
- **`ping`**: Keepalive/dummy traffic for timing resistance

### Message Types (Server → Client)
- **`msg`**: Encrypted message from another user
- **`delivery_status`**: Confirmation that a message was relayed or queued
- **`queued_message`**: Offline message being delivered from storage
- **`dummy_ack`**: Response to keepalive pings

## 10. Cross-Instance Routing (Redis Pub/Sub)

Multiple server instances coordinate via Redis:

1. When a message arrives for `recipient_hash`, the server checks if that user is connected locally
2. If not, it publishes to the Redis channel `msg:recipient_hash`
3. All instances subscribe to channels for their locally connected users
4. Whichever instance has that user delivers the message over WebSocket
5. If no instance has the user online, the message is stored in a Redis list `offline:recipient_hash`
