FROM lukemathwalker/cargo-chef:latest-rust-1.80-alpine AS chef
WORKDIR /app
RUN apk add --no-cache musl-dev openssl-dev

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release
FROM alpine:latest AS runtime
WORKDIR /app

RUN apk add --no-cache libgcc openssl ca-certificates

RUN addgroup -S entropy && adduser -S entropy -G entropy
USER entropy

COPY --from=builder /app/target/release/entropy-rs /app/entropy-server
COPY --from=builder /app/.env.example /app/.env

ENV ENTROPY_ADDR=0.0.0.0
ENV ENTROPY_PORT=8080
ENV RUST_LOG=info

EXPOSE 8080

ENTRYPOINT ["/app/entropy-server"]
