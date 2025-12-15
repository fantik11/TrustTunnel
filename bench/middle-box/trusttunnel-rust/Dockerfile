# syntax=docker/dockerfile:1
FROM bench-common

ARG ENDPOINT_DIR="TrustTunnel"
ARG ENDPOINT_HOSTNAME="endpoint.bench"
ARG CONFIG_FILE="vpn.conf"
ARG TLS_HOSTS_SETTINGS_FILE="tls_hosts.conf"
ARG LOG_LEVEL="info"

COPY $ENDPOINT_DIR/lib/Cargo.toml /tmp/Cargo.toml

COPY $ENDPOINT_DIR /bench/$ENDPOINT_DIR

WORKDIR /bench/
RUN cd "$ENDPOINT_DIR" && \
    cargo build --release --bin setup_wizard && \
    cargo build --release --bin vpn_endpoint && \
    mv ./target/release/setup_wizard ./target/release/vpn_endpoint /bench/

RUN ./setup_wizard --mode non-interactive  \
    --address [::]:4433 \
    --creds premium:premium  \
    --hostname "$ENDPOINT_HOSTNAME"  \
    --lib-settings "$CONFIG_FILE"  \
    --hosts-settings "$TLS_HOSTS_SETTINGS_FILE"

ENV LOG_LEVEL=$LOG_LEVEL \
    CONFIG_FILE=$CONFIG_FILE \
    TLS_HOSTS_SETTINGS_FILE=$TLS_HOSTS_SETTINGS_FILE \
    RUST_BACKTRACE=1
ENTRYPOINT ./vpn_endpoint -l "$LOG_LEVEL" "$CONFIG_FILE" "$TLS_HOSTS_SETTINGS_FILE" >>/tmp/vpn.log 2>&1
