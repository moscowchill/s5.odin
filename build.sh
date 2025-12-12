#!/bin/bash
# Build script for SOCKS5 Proxy Server

set -e

ODIN="${ODIN:-odin}"

echo "==================================="
echo "SOCKS5 Proxy Build Script"
echo "==================================="
echo

# Check if Odin is available
if ! command -v $ODIN &> /dev/null; then
    echo "Error: Odin compiler not found"
    echo "Please install from https://odin-lang.org/"
    exit 1
fi

echo "Odin version:"
$ODIN version
echo

# Build Client
echo "==================================="
echo "Building Client"
echo "==================================="

echo "[1/2] Building client (debug)..."
$ODIN build s5_proxy.odin -file -out:s5proxy_dev
echo "[OK] s5proxy_dev"

echo "[2/2] Building client (release)..."
$ODIN build s5_proxy.odin -file -o:speed -no-bounds-check -out:s5proxy
echo "[OK] s5proxy"

echo
# Build Server
echo "==================================="
echo "Building Server"
echo "==================================="

echo "[1/2] Building server (debug)..."
$ODIN build cmd/server -out:backconnect_server_dev
echo "[OK] backconnect_server_dev"

echo "[2/2] Building server (release)..."
$ODIN build cmd/server -o:speed -no-bounds-check -out:backconnect_server
echo "[OK] backconnect_server"

echo
echo "==================================="
echo "Done"
echo "==================================="
echo
echo "  s5proxy                - Client (release)"
echo "  s5proxy_dev            - Client (debug)"
echo "  backconnect_server     - Server (release)"
echo "  backconnect_server_dev - Server (debug)"
echo
