# 🌐 Entropy Server API Reference

The Entropy Server provides a high-performance, stateless relay for decentralized messaging. It uses a combination of REST for setup and WebSockets for real-time delivery.

## 1. REST API

The REST API is strictly limited to health monitoring and administrative statistics. All cryptographic operations and identity management occur over WebSockets for performance and state consistency.

### `GET /health`
Returns the operational status of the relay node.

### `GET /stats`
Returns anonymized server performance metrics (Total users, message throughput). *Note: Requires Admin Token headers or local loopback access.*

### `GET /metrics`
Exposes Prometheus-compatible metrics for monitoring clusters.

---

## 2. WebSocket Protocol (`/ws`)

The primary protocol for both identity management and messaging.

### Connection
Clients must upgrade their connection via the `/ws` endpoint.

### Identity & Signaling (Client → Server)
These messages can be sent after a WebSocket connection is established but *before* or *during* authentication.

- **`pow_challenge`**: Fetch a new SHA-256 challenge.
  - Payload: `{ "identity_hash": "...", "nickname": "..." (Optional), "intent": "..." (Optional) }`
- **`keys_upload`**: Standard X3DH/Kyber bundle upload. Requires solved PoW.
- **`fetch_key`**: Retrieve key bundle for a `target_hash`.
- **`fetch_key_random`**: Fetch random key bundles for decoy traffic.
- **`nickname_register`**: Map a nickname to an identity hash.
- **`nickname_lookup`**: Resolve a name to a hash.
- **`account_burn`**: Pure all server-side data (requires owner signature).

### Authentication
- **`auth`**: Authenticate using a solved PoW challenge or a `session_token`.
  - On success, the server responds with `auth_success` and a fresh token.

### Messaging
- **`relay_message`**: Sends an encrypted envelope.
- **`ack`**: Confirms receipt of offline messages.
- **`ping`**: Dummy/Keepalive traffic.

---

## 3. Error Codes

| Code | Meaning | Action |
| --- | --- | --- |
| `ERR_POW_INVALID` | Nonce did not solve challenge. | Re-calculate or fetch new seed. |
| `ERR_RATE_LIMIT` | Too many requests from this IP/ID. | Wait 60 seconds. |
| `ERR_EXPIRED` | Seed has expired. | Fetch new challenge. |
| `ERR_MALFORMED` | Invalid JSON or binary header. | Check client implementation. |
