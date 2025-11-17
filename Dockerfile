# Build stage
FROM rust:1.91.1 AS builder

# Install cargo-chef for dependency caching
RUN cargo install cargo-chef

WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

# Build dependencies - this is the caching Docker layer
RUN cargo chef prepare --recipe-path recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --release --bin oauth-server

# Runtime stage
FROM debian:bookworm-slim

# Install CA certificates for HTTPS requests
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -r -s /bin/false -m -d /var/lib/oauth-server oauth-server

# Copy the binary
COPY --from=builder /app/target/release/oauth-server /usr/local/bin/oauth-server

# Set ownership
RUN chown oauth-server:oauth-server /usr/local/bin/oauth-server

# Switch to non-root user
USER oauth-server

EXPOSE 3000

ENTRYPOINT ["oauth-server"]