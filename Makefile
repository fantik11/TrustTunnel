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

.PHONY: docker/-checkout-repo
docker/-checkout-repo:
	@if [ ! -d "$(DOCKER_DIR)/$(DOCKER_ENDPOINT_DIR)" ]; then \
		git clone "$(ENDPOINT_URL)" "$(DOCKER_DIR)/$(DOCKER_ENDPOINT_DIR)" && \
			git checkout "$(ENDPOINT_VERSION)"; \
	fi

.PHONY: docker/build
## Build a docker image with the configured endpoint instance
docker/build: docker/-checkout-repo
	docker build -t "$(DOCKER_IMAGE_NAME)" \
		--build-arg LOG_LEVEL="$(LOG_LEVEL)" \
		--build-arg CONFIG_FILE="$(CONFIG_FILE)" \
		--build-arg HOSTS_CONFIG_FILE="$(HOSTS_CONFIG_FILE)" \
		--build-arg ENDPOINT_DIR="$(DOCKER_ENDPOINT_DIR)" \
		./docker

.PHONY: docker/run
## Run the docker image
docker/run: docker/build
	docker run -d \
		-p $(LISTEN_PORT):$(LISTEN_PORT) \
		-p $(LISTEN_PORT):$(LISTEN_PORT)/udp \
		"$(DOCKER_IMAGE_NAME)"

.PHONY: docker/setup-and-run
## Create an endpoint setup, build a docker image containing that setup and run the image.
## That is, it is a shorthand for the `endpoint/setup + docker/build + docker/run`.
docker/setup-and-run:
	mkdir -p "$(DOCKER_DIR)/$(DOCKER_ENDPOINT_CONFIG_DIR)"
	cd "$(DOCKER_DIR)/$(DOCKER_ENDPOINT_CONFIG_DIR)" && make -f ../../Makefile endpoint/setup
	make docker/run

.PHONY: docker/clean
## Clean docker image
docker/clean:
	docker image rm -f "$(DOCKER_IMAGE_NAME)"
	rm -rf "$(DOCKER_DIR)/$(DOCKER_ENDPOINT_DIR)"
	rm -rf "$(DOCKER_DIR)/$(DOCKER_ENDPOINT_CONFIG_DIR)"
