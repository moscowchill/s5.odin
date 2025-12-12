#!/bin/bash
# Build script for SOCKS5 Proxy Server

set -e

ODIN="${ODIN:-odin}"
CLIENT_PROJECT="s5_proxy.odin"
SERVER_PROJECT="cmd/server"

echo "==================================="
echo "SOCKS5 Proxy Build Script"
echo "==================================="
echo

# Check if Odin is available
if ! command -v $ODIN &> /dev/null; then
    echo "Error: Odin compiler not found"
    echo "Please install from https://odin-lang.org/ or set ODIN environment variable"
    exit 1
fi

echo "Odin version:"
$ODIN version
echo

# Security Note
echo "==================================="
echo "SECURITY NOTE"
echo "==================================="
echo "Some builds use -no-bounds-check for performance."
echo "For security-sensitive deployments, use s5proxy_linux_secure"
echo "which maintains runtime bounds checking."
echo
echo "WARNING: Never log credentials or run in verbose mode in production!"
echo "==================================="
echo

# Build Client (s5_proxy)
echo "==================================="
echo "Building Client (s5_proxy)"
echo "==================================="

echo "[1/5] Building client for Linux (development)..."
$ODIN build $CLIENT_PROJECT -file -out:s5proxy_linux_dev
echo "[OK] Built: s5proxy_linux_dev"

echo "[2/5] Building client for Linux (optimized)..."
$ODIN build $CLIENT_PROJECT -file -o:speed -no-bounds-check -out:s5proxy_linux
echo "[OK] Built: s5proxy_linux"

echo "[3/5] Building client for Linux (security-hardened)..."
$ODIN build $CLIENT_PROJECT -file -o:speed -out:s5proxy_linux_secure
echo "[OK] Built: s5proxy_linux_secure (with bounds checking)"

echo "[4/5] Building client for Linux (minimal size)..."
$ODIN build $CLIENT_PROJECT -file -o:size -no-bounds-check -out:s5proxy_linux_tiny
echo "[OK] Built: s5proxy_linux_tiny"

# Windows build (only on Windows or with proper cross-compilation setup)
echo "[5/5] Attempting client Windows build..."
if $ODIN build $CLIENT_PROJECT -file -target:windows_amd64 -o:speed -no-bounds-check -out:s5proxy.exe 2>/dev/null; then
    echo "[OK] Built: s5proxy.exe"
else
    echo "[WARN] Windows cross-compilation not supported on this platform"
    echo "  To build for Windows:"
    echo "  - Build on Windows directly, or"
    echo "  - Use a Windows VM/container"
fi

echo
# Build Server (backconnect_server)
echo "==================================="
echo "Building Server (backconnect_server)"
echo "==================================="

echo "[1/4] Building server for Linux (development)..."
$ODIN build $SERVER_PROJECT -out:backconnect_server_linux_dev
echo "[OK] Built: backconnect_server_linux_dev"

echo "[2/4] Building server for Linux (optimized)..."
$ODIN build $SERVER_PROJECT -o:speed -no-bounds-check -out:backconnect_server_linux
echo "[OK] Built: backconnect_server_linux"

echo "[3/4] Building server for Linux (security-hardened)..."
$ODIN build $SERVER_PROJECT -o:speed -out:backconnect_server_linux_secure
echo "[OK] Built: backconnect_server_linux_secure (with bounds checking)"

echo "[4/4] Attempting server Windows build..."
if $ODIN build $SERVER_PROJECT -target:windows_amd64 -o:speed -no-bounds-check -out:backconnect_server.exe 2>/dev/null; then
    echo "[OK] Built: backconnect_server.exe"
else
    echo "[WARN] Windows cross-compilation not supported on this platform"
fi

echo
echo "==================================="
echo "Build Summary"
echo "==================================="
echo
echo "Client binaries:"
ls -lh s5proxy* 2>/dev/null | grep -v ".odin" || echo "  (none built)"
echo
echo "Server binaries:"
ls -lh backconnect_server* 2>/dev/null || echo "  (none built)"
echo
echo "Client build variants:"
echo "  s5proxy_linux_dev    - Development (with debug info)"
echo "  s5proxy_linux        - Optimized (fastest, no bounds check)"
echo "  s5proxy_linux_secure - Security-hardened (with bounds check)"
echo "  s5proxy_linux_tiny   - Minimal size"
echo
echo "Server build variants:"
echo "  backconnect_server_linux_dev    - Development (with debug info)"
echo "  backconnect_server_linux        - Optimized (fastest, no bounds check)"
echo "  backconnect_server_linux_secure - Security-hardened (with bounds check)"
echo
echo "Recommended for production:"
echo "  Client: s5proxy_linux_secure"
echo "  Server: backconnect_server_linux_secure"
echo
echo "For maximum performance:"
echo "  Client: s5proxy_linux"
echo "  Server: backconnect_server_linux"
echo
echo "For testing/debugging:"
echo "  Client: s5proxy_linux_dev"
echo "  Server: backconnect_server_linux_dev"
