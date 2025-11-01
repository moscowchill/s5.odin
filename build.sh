#!/bin/bash
# Build script for SOCKS5 Proxy Server

set -e

ODIN="${ODIN:-odin}"
PROJECT="s5_proxy.odin"

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

# Build Linux
echo "[1/4] Building for Linux (development)..."
$ODIN build $PROJECT -file -out:s5proxy_linux_dev
echo "[OK] Built: s5proxy_linux_dev"

echo "[2/4] Building for Linux (optimized)..."
$ODIN build $PROJECT -file -o:speed -no-bounds-check -out:s5proxy_linux
echo "[OK] Built: s5proxy_linux"

echo "[3/4] Building for Linux (minimal size)..."
$ODIN build $PROJECT -file -o:size -no-bounds-check -out:s5proxy_linux_tiny
echo "[OK] Built: s5proxy_linux_tiny"

# Windows build (only on Windows or with proper cross-compilation setup)
echo "[4/4] Attempting Windows build..."
if $ODIN build $PROJECT -file -target:windows_amd64 -o:speed -no-bounds-check -out:s5proxy.exe 2>/dev/null; then
    echo "[OK] Built: s5proxy.exe"
else
    echo "[WARN] Windows cross-compilation not supported on this platform"
    echo "  To build for Windows:"
    echo "  - Build on Windows directly, or"
    echo "  - Use a Windows VM/container"
fi

echo
echo "==================================="
echo "Build Summary"
echo "==================================="
ls -lh s5proxy* 2>/dev/null | grep -v ".odin"
echo
echo "Recommended for deployment: s5proxy_linux (optimized)"
echo "For testing/debugging: s5proxy_linux_dev"
echo "For size-constrained environments: s5proxy_linux_tiny"
