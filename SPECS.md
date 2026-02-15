# ⚙️ Entropy Server Architectural Specification

The Entropy Relay is a C++20/23, high-concurrency node designed with a **Zero-Knowledge** and **Stateless** philosophy.

## 1. DoS Protection (PoW + GCRA)

The server implements a multi-tier protection system:
1.  **Computation Barrier**: Expensive operations (key uploads, new identities, authentication) require a CPU-bound Proof-of-Work solution.
2.  **Global Rate Limiting**: Uses a Redis-Lua implementation of the **Generic Cell Rate Algorithm (GCRA)**.
3.  **Jail State**: Repeat protocol violators are temporarily "jailed" (banned by IP) for 5 minutes.

## 2. Sender-Authenticated Routing

Entropy operates in a **Sender-Authenticated** flow:
- When a user sends a message, the server attaches the `sender` identity hash to the package.
- This allows recipients to verify the source via their local address book.
- Authentication is verified via **Ed25519** (or XEdDSA) signatures during session setup and sensitive actions.

## 3. Traffic Normalization (Anti-Analysis)

To prevent metadata leakage through packet sizes and timing patterns:

### 3.1 Packet Padding
- **Fixed Size**: All JSON responses are padded to exactly **256 bytes** (configurable) using random whitespace.
- **Binary Normalization**: Binary WebSocket messages are zero-padded to the same threshold.
- **Rationale**: Prevents observers from distinguishing a "Key Upload" from a "Chat Message" based on packet length.

### 3.2 Timing Jitter
- **Random Delays**: Every message delivery includes a random **10-50ms delay**.
- **Implementation**: Uses `boost::asio::steady_timer` to prevent correlation between "Packet In" and "Packet Out" events.

### 3.3 Dummy Pacing
- **Constant Traffic Profile**: WebSocket sessions send `dummy_pacing` packets every **500ms** during idle periods.
- **Pacing Speed**: When delivering offline messages or media fragments, the server switches to a high-speed "10ms" tick interval to clear the buffer quickly while appearing as a steady stream.

---

## 4. Forensic Security

### 4.1 "Account Burn"
- Upon a validated `burn_account` request (requires Ed25519 signature proof of ownership), the server atomically purges:
  1. Key bundles.
  2. Queued (offline) messages.
  3. Session tokens and metadata.
  4. Nickname registry entries.

### 4.2 Zero-Knowledge Storage
- **Identity Blinding**: All Redis keys are HMAC-hashed with a **Server Salt**. The operator cannot list users or map real public keys to stored data without the salt.
- **Volatile Only**: Offline messages and keys have strict TTLs (24 hours to 30 days).

---

## 5. Network Protocol

### 5.1 REST Interface
- **`GET /health`**: Health check.
- **`GET /stats`**: Real-time throughput (Admin only).
- **`GET /metrics`**: Prometheus-style metrics (Admin only).

### 5.2 WebSocket Message Types
- **`pow_challenge`**: Fetches a new SHA-256 challenge.
- **`auth`**: Authenticates the session using PoW or token.
- **`keys_upload`**: Submits an X3DH key bundle.
- **`fetch_key`**: Retrieves key bundles for target hashes (supports batching).
- **`nickname_register`**: Maps a name to a hash (requires PoW).
- **`relay_message`**: Routes an encrypted envelope.
- **`volatile_relay`**: Low-overhead relay for ephemeral signaling (e.g., typing).

### 5.3 Group Messaging
Group communication is implemented via **Client-Side Fan-out**. To prevent the relay node from identifying group memberships, the client encrypts and sends individual messages to each member. This ensures that to the server, group traffic is indistinguishable from standard P2P messages.

