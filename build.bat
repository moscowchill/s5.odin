@echo off
REM Build script for Stealth SOCKS5 Proxy Server (Windows)

setlocal enabledelayedexpansion

echo ===================================
echo Stealth SOCKS5 Proxy Build Script
echo ===================================
echo.

REM Check if Odin is available
where odin >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Odin compiler not found in PATH
    echo Please install from https://odin-lang.org/
    exit /b 1
)

echo Odin version:
odin version
echo.

REM Build Windows binaries
echo [1/3] Building for Windows (development)...
odin build s5_proxy.odin -file -out:s5proxy_dev.exe
if %ERRORLEVEL% EQU 0 (
    echo √ Built: s5proxy_dev.exe
) else (
    echo × Build failed: s5proxy_dev.exe
    exit /b 1
)

echo [2/3] Building for Windows (optimized)...
odin build s5_proxy.odin -file -o:speed -no-bounds-check -out:s5proxy.exe
if %ERRORLEVEL% EQU 0 (
    echo √ Built: s5proxy.exe
) else (
    echo × Build failed: s5proxy.exe
    exit /b 1
)

echo [3/3] Building for Windows (minimal size)...
odin build s5_proxy.odin -file -o:size -no-bounds-check -out:s5proxy_tiny.exe
if %ERRORLEVEL% EQU 0 (
    echo √ Built: s5proxy_tiny.exe
) else (
    echo × Build failed: s5proxy_tiny.exe
    exit /b 1
)

echo.
echo ===================================
echo Build Summary
echo ===================================
dir s5proxy*.exe
echo.
echo Recommended for deployment: s5proxy.exe (optimized)
echo For testing/debugging: s5proxy_dev.exe
echo For size-constrained environments: s5proxy_tiny.exe
