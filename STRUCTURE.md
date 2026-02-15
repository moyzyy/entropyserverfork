# 📂 Server Project Structure

Summary of the Entropy Relay Server codebase organization.

```text
.
├── include/                 # Header Files (.hpp)
│   ├── handlers/            # REST & WS endpoint logic (Health, Identity)
│   ├── http_session.hpp     # REST & WebSocket upgrade handler
│   ├── websocket_session.hpp# WebSocket state machine & Pacing
│   ├── connection_manager.hpp# Active client & IP tracking
│   ├── redis_manager.hpp    # Redis storage & Pub/Sub
│   ├── input_validator.hpp  # Crypto & JSON sanitization
│   ├── pow_verifier.hpp     # SHA256 challenge logic
│   ├── traffic_normalizer.hpp# JSON padding utilities
│   ├── metrics.hpp          # Prometheus/Gauge registry
│   └── rate_limiter.hpp     # DoS protection (GCRA)
│
├── src/                     # Implementation (.cpp)
│   ├── main.cpp             # Entry point & SSL Setup
│   ├── message_relay.cpp    # Routing & Jitter logic
│   ├── redis_manager.cpp    # Lua scripting & Redis I/O
│   ├── http_session.cpp     # HTTP Route table
│   └── handlers/            # Endpoint implementation
│
├── tests/                   # Test Suite
│   ├── unit/                # Component logic tests
│   ├── integration/         # Multi-component flows
│   └── security/            # DoS, Crypto, and Audit tests
│
├── scripts/                 # Utility scripts (Certs, etc.)
├── cmake/                   # Build system modules
├── Dockerfile               # Containerization
├── SPECS.md                 # Architecture & Protocols
└── API.md                   # Endpoint documentation
```

## 🏗️ Execution Flow

1.  **Listener**: Accepts raw TCP connections and performs the TLS handshake.
2.  **HTTP Session**: Dispatches REST calls or negotiates the WebSocket upgrade.
3.  **WebSocket Session**: Manages the connection lifecycle, including **Traffic Pacing** (dummy packets).
4.  **Identity Handler**: Processes PoW challenges, key uploads, and nickname registrations.
5.  **Message Relay**: Handles the routing, jittering, and normalization of encrypted envelopes.
6.  **Redis Manager**: Manages offline message queues, nickname registry, and persistent state.
