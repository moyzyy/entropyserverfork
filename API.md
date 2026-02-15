# 🌐 Entropy Server API Reference

The Entropy Server uses **REST** for health monitoring and **WebSockets** for all cryptographic and messaging operations.

---

## 1. REST API

Strictly for health, metrics, and administration.

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/health` | `GET` | Node operational status. | No |
| `/stats` | `GET` | Active users and throughput. | Yes (Local/Admin) |
| `/metrics` | `GET` | Prometheus-compatible metrics. | Yes (Local/Admin) |

---

## 2. WebSocket Protocol (`/ws`)

### 🔑 Authentication Flow

1. **`pow_challenge`**: Client requests a seed.
   - Payload: `{ "type": "pow_challenge", "identity_hash": "...", "nickname": "..." (Optional), "intent": "..." (Optional) }`
2. **`auth`**: Solve the challenge and authenticate.
   - Payload: `{ "type": "auth", "payload": { "identity_hash": "...", "seed": "...", "nonce": "..." } }`
   - *Result*: Responds with `auth_success` and a `session_token`.

### 🗄️ Identity & Discovery

- **`keys_upload`**: Upload X3DH bundle.
  - Payload: `{ "type": "keys_upload", "identity_hash": "...", "identityKey": "...", "signedPreKey": "...", ... }`
- **`fetch_key`**: Retrieve a bundle. Supports batching via comma-separated hashes.
  - Payload: `{ "type": "fetch_key", "target_hash": "hash1,hash2" }`
- **`fetch_key_random`**: Get random hashes for decoy traffic.
  - Payload: `{ "type": "fetch_key_random", "count": 10 }`
- **`nickname_register`**: Map a name to a hash.
  - Payload: `{ "type": "nickname_register", "nickname": "...", "identity_hash": "...", "seed": "...", "nonce": "..." }`
- **`account_burn`**: Atomic data purge. Requires Ed25519 signature.
  - Payload: `{ "type": "account_burn", "identity_hash": "...", "signature": "...", "identityKey": "..." }`

### 💬 Messaging

- **`relay_message`**: Standard encrypted delivery (Sender identities are attached by server).
  - Payload: `{ "to": "recipient_hash", "type": "...", "data": "..." }`
- **`volatile_relay`**: Fast, unreliable relay for ephemeral state (pings, typing indicators).
  - Payload: `{ "type": "volatile_relay", "to": "hash", "body": "..." }`
- **`ack`**: Confirms receipt of queued messages.
  - Payload: `{ "type": "ack", "ids": [1, 2, 3] }`

### 🛡️ Privacy & Utils

- **`link_preview`**: Proxied metadata resolution to prevent IP exposure.
  - Payload: `{ "type": "link_preview", "url": "..." }`
- **`subscribe_alias`**: Register an additional recipient to the current session.
  - Payload: `{ "type": "subscribe_alias", "payload": { "alias": "...", "seed": "...", "nonce": "..." } }`
- **`ping`**: Trigger `dummy_ack` and keepalive.

---

## 3. Error Codes

| Code | Meaning |
|------|---------|
| `auth_failed` | Seed/Nonce or Token is invalid or expired. |
| `auth_required` | Operation attempted without successful `auth` frame. |
| `rate_limit` | Too many requests for this IP or identity. |
| `storage_failed` | Redis offline or message too large for queue. |
