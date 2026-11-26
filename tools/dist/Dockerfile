FROM rust:1.100-slim
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
# The base image has no default toolchain override: pin the one it ships, so rust-toolchain.toml
# does not make rustup look for another one offline.
ENV RUSTUP_TOOLCHAIN=1.100.0-x86_64-unknown-linux-gnu
