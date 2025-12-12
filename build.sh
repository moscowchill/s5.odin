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

# Build Linux
echo "[1/5] Building for Linux (development)..."
$ODIN build $PROJECT -file -out:s5proxy_linux_dev
echo "[OK] Built: s5proxy_linux_dev"

echo "[2/5] Building for Linux (optimized)..."
$ODIN build $PROJECT -file -o:speed -no-bounds-check -out:s5proxy_linux
echo "[OK] Built: s5proxy_linux"

echo "[3/5] Building for Linux (security-hardened)..."
$ODIN build $PROJECT -file -o:speed -out:s5proxy_linux_secure
echo "[OK] Built: s5proxy_linux_secure (with bounds checking)"

echo "[4/5] Building for Linux (minimal size)..."
$ODIN build $PROJECT -file -o:size -no-bounds-check -out:s5proxy_linux_tiny
echo "[OK] Built: s5proxy_linux_tiny"

# Windows build (only on Windows or with proper cross-compilation setup)
echo "[5/5] Attempting Windows build..."
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
echo "Build variants:"
echo "  s5proxy_linux_dev    - Development (with debug info)"
echo "  s5proxy_linux        - Optimized (fastest, no bounds check)"
echo "  s5proxy_linux_secure - Security-hardened (with bounds check)"
echo "  s5proxy_linux_tiny   - Minimal size"
echo
echo "Recommended for production: s5proxy_linux_secure"
echo "For maximum performance: s5proxy_linux"
echo "For testing/debugging: s5proxy_linux_dev"
