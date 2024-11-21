BUILD_TYPE ?= release
ifeq ($(BUILD_TYPE), release)
	CARGO_BUILD_TYPE = --release
endif
LOG_LEVEL ?= trace
CONFIG_FILE ?= vpn.toml
HOSTS_CONFIG_FILE ?= hosts.toml
DOCKER_IMAGE_NAME ?= adguard-vpn-endpoint
ENDPOINT_URL ?= git@github.com:AdguardTeam/VpnLibsEndpointPrivate.git
ENDPOINT_VERSION ?= master
ENDPOINT_HOSTNAME ?= vpn.endpoint
DOCKER_DIR = docker
DOCKER_ENDPOINT_DIR = vpn-libs-endpoint
DOCKER_ENDPOINT_CONFIG_DIR = config
LISTEN_ADDRESS ?= 0.0.0.0
LISTEN_PORT ?= 443


.PHONY: endpoint/build-wizard
## Build the setup wizard
endpoint/build-wizard:
	cargo build $(CARGO_BUILD_TYPE) --bin setup_wizard

.PHONY: endpoint/setup
## Run the setup wizard to create all the required configuration files
endpoint/setup: endpoint/build-wizard
	cargo run $(CARGO_BUILD_TYPE) --bin setup_wizard -- \
		--hostname "$(ENDPOINT_HOSTNAME)" \
		--address "$(LISTEN_ADDRESS):$(LISTEN_PORT)" \
		--lib-settings "$(CONFIG_FILE)" \
		--hosts-settings "$(HOSTS_CONFIG_FILE)"

.PHONY: endpoint/build
## Build the endpoint
endpoint/build:
	cargo build $(CARGO_BUILD_TYPE) --bin vpn_endpoint

.PHONY: endpoint/run
## Run the endpoint with the existing configuration files
endpoint/run: endpoint/build
	cargo run $(CARGO_BUILD_TYPE) --bin vpn_endpoint -- \
		-l "$(LOG_LEVEL)" "$(CONFIG_FILE)" "$(HOSTS_CONFIG_FILE)"

.PHONY: endpoint/clean
## Clean cargo artifacts
endpoint/clean:
	cargo clean