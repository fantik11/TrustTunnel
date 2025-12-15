<p align="center">
<picture>
<source media="(prefers-color-scheme: dark)" srcset="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_dark.svg" width="300px" alt="TrustTunnel" />
<img src="https://cdn.adguardcdn.com/website/github.com/TrustTunnel/logo_light.svg" width="300px" alt="TrustTunnel" />
</picture>
</p>

<p align="center"><a href="https://github.com/TrustTunnel/TrustTunnelClient">Console client</a>
  · <a href="https://github.com/TrustTunnel/TrustTunnelFlutterClient">Flutter-based app</a>
  · <a href="https://agrd.io/ios_trusttunnel">App store</a>
  · <a href="https://agrd.io/android_trusttunnel">Play store</a>
</p>

---

## Table of Contents

- [Introduction](#introduction)
- [Server Features](#server-features)
- [Client Features](#client-features)
- [Getting Started with the endpoint](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Building](#building)
- [Usage](#usage)
    - [Quick Start](#quick-start)
    - [Customized Configuration](#customized-configuration)
    - [Generate client config](#generate-client-config)
- [Companion Client Repository](#companion-client-repository)
- [Roadmap](#roadmap)
- [License](#license)

---

## Introduction

Welcome to the TrustTunnel repository!

TrustTunnel is free, fast secure and fully self-hosted VPN solution powered by its own unique VPN protocol.

TrustTunnel project includes VPN endpoint (this repository), [library and CLI for client](https://github.com/TrustTunnel/TrustTunnelClient) and [GUI application](https://github.com/TrustTunnelFlutterClient)

## Server Features

- **VPN Protocol**: The library implements the VPN protocol compatible
  with HTTP/1.1, HTTP/2, and QUIC.
  By mimicking regular network traffic, it becomes more difficult for government regulators to
  detect and block.

- **Flexible Traffic Tunneling**: TrustTunnel can tunnel TCP, UDP, and ICMP traffic to and
  from the client.

- **Platform Compatibility**: Server is compatible with Linux and macOS systems. Client exists for Android, Apple, Windows and Linux platforms.

---

## Client Features

- **Traffic Tunneling**: The library is capable of tunneling TCP, UDP, and ICMP traffic from the
  client to the endpoint and back.

- **Cross-Platform Support**: It supports Linux, macOS, and Windows platforms, providing a
  consistent experience across different operating systems.

- **System-Wide Tunnel and SOCKS5 Proxy**: It can be set up as a system-wide tunnel, utilizing a
  virtual network interface, as well as a SOCKS5 proxy.

- **Split Tunneling**: The library supports split tunneling, allowing users to exclude connections
  to certain domains or hosts from routing through the VPN endpoint, or vice versa, only routing
  connections to specific domains or hosts through the endpoint based on an exclusion list.

- **Custom DNS Upstream**: Users can specify a custom DNS upstream, which is used for DNS queries
  routed through the VPN endpoint.

---

## Getting Started with the endpoint

### Prerequisites

Before proceeding, ensure that you have Rust installed on your system.
Visit the [Rust installation page](https://www.rust-lang.org/tools/install) for
detailed instructions.
The minimum supported version of the Rust compiler is 1.85.
`libclang` library 9.0 or higher is also required.
This project is compatible with Linux and macOS systems.

### Building

To install TrustTunnel Endpoint, follow these steps:

1. Clone the repository:

   ```shell
   git clone https://github.com/TrustTunnel/TrustTunnel.git
   cd TrustTunnel
   ```

2. Build the binaries using Cargo:

   ```shell
   cargo build --bins --release
   ```

   This command will generate the executables in the `target/release` directory.

## Usage

### Quick Start

To quickly configure and launch the VPN endpoint, run the following commands:

```shell
make ENDPOINT_HOSTNAME="example.org" endpoint/setup  # You can skip it if you have already configured the endpoint earlier
make endpoint/run
```

Check `Makefile` for available configuration variables.

These commands perform the following actions:

1. Build the wizard and endpoint binaries.

2. Configure the endpoint to listen to all network interfaces for TCP/UDP packets on
   port number 443.

3. Generate self-signed certificate/private key pair in the current directory under `certs/`.

4. Store all the required settings in `vpn.toml` and `hosts.toml` files.

5. Start the endpoint.

Alternatively, you can run the endpoint in a docker container:

```shell
docker build -t vpn-endpoint:latest . # build an image

docker run -it vpn-endpoint:latest --name vpn-endpoint # create docker container and start it in an interactive mode

docker start -i vpn-endpoint # if you need to start your vpn endpoint again
```

The generated certificate (by default, it resides in `certs/cert.pem` or `/TrustTunnel/certs/cert.pem` inside your docker volume) should be delivered to the client-side in some way. See the [Companion Client Repository](#companion-client-repository) for
details.

### Customized Configuration

For a more customized configuration experience, run the following commands:

```shell
make endpoint/build-wizard  # If you skipped the previous chapter
cargo run --bin setup_wizard  # Launches a dialogue session allowing you to tweak the settings
cargo run --bin vpn_endpoint -- <lib-settings> <hosts-settings>  # File names depend on the previous step
```

For additional details about the binary, refer to the [endpoint/README.md](./endpoint/README.md)
file.

> The settings files created by the Setup Wizard contain almost all available settings,
> including descriptions.
> You can freely customize them if you are confident in your understanding of the configuration.

### Generate client config

The endpoint binary is capable of generating the client configuration for a particular user.

This configuration contains all necessary information that is required to connect to the endpoint.

To generate the configuration run the following command:

```shell
# <client_name> - name of the client those credentials will be included in the configuration
# <public_ip_and_port> - `ip:port` that the user will use to connect to the endpoint
cargo run --bin vpn_endpoint -- <lib-settings> <host-settings> -c <client_name> -a <public_ip_and_port>
# or
make endpoint/gen_client_config CLIENT_NAME="<client_name>" ENDPOINT_ADDRESS="<public_ip_and_port"
```

This will print the configuration with the credentials for client with name <client_name> 

## Companion Client Repository

To connect to your newly set-up VPN server, you need a client.
You have a choice to use a [CLI client](https://github.com/TrustTunnel/TrustTunnelClient.git) or a [GUI client](https://github.com/TrustTunnel/TrustTunnelFlutterClient.git)

## Roadmap

While our VPN currently supports tunneling TCP/UDP/ICMP traffic, we plan to add support for
peer-to-peer communication between clients.
Stay tuned for this feature in upcoming releases.

## License

This project is licensed under the Apache 2.0 License. See [LICENSE.md](LICENSE.md) for details.
