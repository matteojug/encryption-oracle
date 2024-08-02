FROM rust:1.80 as builder

# Create dummy project with the actual deps to cache them first
RUN cargo new --bin app
WORKDIR /app

COPY ./Cargo.lock ./Cargo.toml ./
RUN cargo build --release
RUN rm src/*.rs

# Build the real src
COPY ./src ./src
RUN cargo build --release


FROM rust:1.80 as runner
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/encryption-oracle /app/encryption-oracle

HEALTHCHECK --retries=10 --interval=2s --timeout=2s --start-period=2s CMD curl -fkLsS -m 2 http://localhost:3000/ping 2>> /proc/1/fd/1

CMD ["/app/encryption-oracle"]
