#!/bin/bash

check_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "Configuration file '$file' not found"
        return 1
    fi
    return 0
}

verify_configs() {
    local missing=0

    check_file "credentials.toml" || missing=1
    check_file "vpn.toml" || missing=1

    return $missing
}

main() {
    is_interactive=0
    [ ! -t 0 ] || is_interactive=1
    if [ ! verify_configs ] && [ ! -t 0 ]; then
        echo "Missing configuration file(s). Run this containter in an interactive mode to complete setup."
        exit 1
    else
        echo "Missing configuration file(s). Launching setup wizard."
        setup_wizard
    fi
    vpn_endpoint vpn.toml hosts.toml
}

main