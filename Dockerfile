# syntax=docker/dockerfile:1
FROM python:3.11-slim-bullseye AS build
ARG ENDPOINT_DIR_NAME="VpnLibsEndpoint"
ARG RUST_DEFAULT_VERSION="1.77"
WORKDIR /home
# Install needed packets
RUN apt update && \
    apt install -y build-essential cmake curl make git
# Install Rust and Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain $RUST_DEFAULT_VERSION -y
ENV PATH="/root/.cargo/bin:$PATH"
# Copy source files
WORKDIR $ENDPOINT_DIR_NAME
COPY endpoint/ ./endpoint
COPY lib/ ./lib
COPY macros/ ./macros
COPY tools/ ./tools
COPY Cargo.toml Cargo.lock rust-toolchain.toml Makefile ./
# Build
RUN make endpoint/build
RUN make endpoint/build-wizard

# Copy binaries
FROM debian AS vpn-endpoint
ARG ENDPOINT_DIR_NAME="VpnLibsEndpoint"
ARG LOG_LEVEL="info"
COPY --from=build /home/$ENDPOINT_DIR_NAME/target/release/setup_wizard /bin/
COPY --from=build /home/$ENDPOINT_DIR_NAME/target/release/vpn_endpoint /bin/
COPY --chmod=755  /docker-entrypoint.sh /scripts/
WORKDIR /vpn_endpoint
VOLUME /vpn_endpoint/
ENTRYPOINT ["sh", "/scripts/docker-entrypoint.sh"]

