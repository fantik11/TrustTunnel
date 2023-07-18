# syntax=docker/dockerfile:1
FROM python:3.11-slim-bullseye

ARG CERTS_DIR="certs"
ARG CONFIG_FILE="vpn.toml"
ARG CREDENTIALS_FILE="credentials.toml"
ARG ENDPOINT_DIR="vpn-libs-endpoint"
ARG CONFIG_DIR="config"
ARG HOSTS_CONFIG_FILE="hosts.toml"
ARG LOG_LEVEL="info"
ARG RUST_CHANNEL=1.67

RUN apt update && \
    apt install -y build-essential cmake curl make

# Install Rust and Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_CHANNEL
ENV PATH="/root/.cargo/bin:$PATH"

COPY "$ENDPOINT_DIR" "/$ENDPOINT_DIR"
WORKDIR "$ENDPOINT_DIR"

RUN make endpoint/build

COPY "$CONFIG_DIR" "/$ENDPOINT_DIR/$CONFIG_DIR"
WORKDIR "/$ENDPOINT_DIR/$CONFIG_DIR"

ENV LOG_LEVEL="$LOG_LEVEL" \
    CONFIG_FILE="$CONFIG_FILE" \
    HOSTS_CONFIG_FILE="$HOSTS_CONFIG_FILE" \
    RUST_BACKTRACE=1
ENTRYPOINT make -f ../Makefile endpoint/run \
    LOG_LEVEL="$LOG_LEVEL" \
    CONFIG_FILE="$CONFIG_FILE" \
    HOSTS_CONFIG_FILE="$HOSTS_CONFIG_FILE" \
    >>/tmp/vpn.log 2>&1
