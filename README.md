# AdGuard VPN Endpoint

[![AdGuardVPN.com](https://img.shields.io/badge/AdGuardVPN.com-Visit-007BFF)](https://adguard-vpn.com/)

Free, fast, open-source, and secure self-hosted VPN server.

---

## Table of Contents

- [Introduction](#introduction)
- [Why AdGuard VPN?](#why-adguard-vpn)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Building](#building)
- [Usage](#usage)
    - [Quick Start](#quick-start)
    - [Customized Configuration](#customized-configuration)
- [Companion Client Repository](#companion-client-repository)
- [Roadmap](#roadmap)
- [License](#license)

---

## Introduction

Welcome to the AdGuard VPN Endpoint repository!
This comprehensive and efficient solution allows you to set up and manage your own VPN server.
The repository includes the following components:

1. **VPN Endpoint Library**: A highly efficient, versatile, and reliable Rust library that
   implements the VPN endpoint.

2. **VPN Endpoint Binary**: A standalone application that makes it easy for any user to set
   up their own VPN server.

3. **Setup-Wizard Tool**: A user-friendly tool that simplifies the configuration process by guiding
   you through the necessary steps.

## Why AdGuard VPN?

- **AdGuard Protocol**: AdGuard VPN utilizes
  [the AdGuard protocol](https://adguard-vpn.com/kb/general/adguard-vpn-protocol/),
  which is compatible with HTTP/1.1, HTTP/2, and QUIC.
  By mimicking regular network traffic, it becomes more difficult for government regulators to
  detect and block.

- **Flexible Traffic Tunneling**: AdGuard VPN can tunnel TCP, UDP, and ICMP traffic to and
  from the client.

- **Platform Compatibility**: It is compatible with Linux and macOS systems.

- **Companion Client Repository**: An accompanying client is available in a separate repository,
  allowing you to connect to your VPN server seamlessly.

## Getting Started

### Prerequisites

Before proceeding, ensure that you have Rust installed on your system.
Visit the [Rust installation page](https://www.rust-lang.org/tools/install) for
detailed instructions.
The minimum supported version of the Rust compiler is 1.67.
This project is compatible with Linux and macOS systems.

### Building

To install AdGuard VPN Endpoint, follow these steps:

1. Clone the repository:

   ```shell
   git clone https://github.com/AdguardTeam/VpnLibsEndpoint.git
   cd VpnLibsEndpoint
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
make endpoint/setup  # You can skip it if you have already configured the endpoint earlier
make endpoint/run
```

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

The generated certificate (by default, it resides in `certs/cert.pem` or `/VpnLibsEndpoint/certs/cert.pem` inside your docker volume) should be delivered to the client-side in some way. See the [Companion Client Repository](#companion-client-repository) for
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

## Companion Client Repository

To connect to your newly set-up VPN server, you need a client.
The companion client's code can be found
in [this repository](https://github.com/AdguardTeam/VpnLibs.git).

## Roadmap

While our VPN currently supports tunneling TCP/UDP/ICMP traffic, we plan to add support for
peer-to-peer communication between clients.
Stay tuned for this feature in upcoming releases.

## License

This project is licensed under the Apache 2.0 License. See [LICENSE.md](LICENSE.md) for details.
