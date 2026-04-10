# Stage 1: Chef (Prepare recipe)
FROM lukemathwalker/cargo-chef:latest-rust-1.80-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev openssl-dev perl make

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Builder (Compile)
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Stage 3: Runtime (Final Image)
FROM alpine:latest AS runtime
WORKDIR /app

# Install production-only dependencies
RUN apk add --no-cache libgcc openssl ca-certificates curl

# Create non-root user for security
RUN addgroup -S entropy && adduser -S entropy -G entropy

# Copy binary
COPY --from=builder /app/target/release/entropy-rs /app/entropy-server
RUN chown entropy:entropy /app/entropy-server && chmod +x /app/entropy-server

USER entropy

# Production Defaults (Overridden by Docker Compose)
ENV ENTROPY_ADDR=0.0.0.0
ENV ENTROPY_PORT=8080
ENV RUST_LOG=info

EXPOSE 8080

# Healthcheck to monitor relay status
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/entropy-server"]
