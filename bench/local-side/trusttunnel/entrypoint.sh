#!/usr/bin/env bash

set -e -x

ENDPOINT_HOSTNAME="$1"
ENDPOINT_IP="$2"
PROTOCOL="$3"
MODE="$4"
if [[ "$MODE" == "socks" ]]; then
  SOCKS_PORT_FIRST="$5"
  SOCKS_PORT_LAST="$6"
fi

COMMON_CONFIG=$(
  cat <<-END
loglevel = "debug"
vpn_mode = "general"
killswitch_enabled = true
exclusions = [
  "example.org",
  "cloudflare-dns.com",
]

[endpoint]
hostname = "$ENDPOINT_HOSTNAME"
addresses = ["$ENDPOINT_IP:4433"]
username = "premium"
password = "premium"
skip_verification = true
upstream_protocol = "$PROTOCOL"
upstream_fallback_protocol = "$PROTOCOL"
END
)

iptables -I OUTPUT -o eth0 -d "$ENDPOINT_IP" -j ACCEPT || echo "Failed to allow connections to endpoint via iptables"
iptables -A OUTPUT -o eth0 -j DROP || echo "Failed to set iptables firewall"

if [[ "$MODE" == "tun" ]]; then
  cat >>trusttunnel_client.toml <<EOF
$COMMON_CONFIG

[listener.tun]
bound_if = "eth0"
included_routes = [
    "0.0.0.0/0",
    "2000::/3",
]
excluded_routes = []
mtu_size = 1500
EOF
  ./trusttunnel_client >>/tmp/vpn.log 2>&1
else
  for port in $(seq "$SOCKS_PORT_FIRST" "$SOCKS_PORT_LAST"); do
    cat >>"trusttunnel_client-$port.conf" <<EOF
$COMMON_CONFIG

[listener.socks]
address = "127.0.0.1:$port"
EOF
    ./trusttunnel_client --config "./trusttunnel_client-$port.conf" >>"/tmp/vpn-$port.log" 2>&1 &
  done

  wait
fi
