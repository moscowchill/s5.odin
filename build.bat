@echo off
REM Build script for SOCKS5 Proxy Server (Windows)

setlocal enabledelayedexpansion

echo ===================================
echo SOCKS5 Proxy Build Script
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

REM Build Client (s5_proxy)
echo ===================================
echo Building Client (s5_proxy)
echo ===================================
echo.

echo [1/4] Building client for Windows (development)...
odin build s5_proxy.odin -file -out:s5proxy_dev.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: s5proxy_dev.exe
) else (
    echo [FAIL] Build failed: s5proxy_dev.exe
    exit /b 1
)

echo [2/4] Building client for Windows (optimized)...
odin build s5_proxy.odin -file -o:speed -no-bounds-check -out:s5proxy.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: s5proxy.exe
) else (
    echo [FAIL] Build failed: s5proxy.exe
    exit /b 1
)

echo [3/4] Building client for Windows (security-hardened)...
odin build s5_proxy.odin -file -o:speed -out:s5proxy_secure.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: s5proxy_secure.exe - with bounds checking
) else (
    echo [FAIL] Build failed: s5proxy_secure.exe
    exit /b 1
)

echo [4/4] Building client for Windows (minimal size)...
odin build s5_proxy.odin -file -o:size -no-bounds-check -out:s5proxy_tiny.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: s5proxy_tiny.exe
) else (
    echo [FAIL] Build failed: s5proxy_tiny.exe
    exit /b 1
)

echo.
REM Build Server (backconnect_server)
echo ===================================
echo Building Server (backconnect_server)
echo ===================================
echo.

echo [1/3] Building server for Windows (development)...
odin build cmd/server -out:backconnect_server_dev.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: backconnect_server_dev.exe
) else (
    echo [FAIL] Build failed: backconnect_server_dev.exe
    exit /b 1
)

echo [2/3] Building server for Windows (optimized)...
odin build cmd/server -o:speed -no-bounds-check -out:backconnect_server.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: backconnect_server.exe
) else (
    echo [FAIL] Build failed: backconnect_server.exe
    exit /b 1
)

echo [3/3] Building server for Windows (security-hardened)...
odin build cmd/server -o:speed -out:backconnect_server_secure.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] Built: backconnect_server_secure.exe - with bounds checking
) else (
    echo [FAIL] Build failed: backconnect_server_secure.exe
    exit /b 1
)

echo.
echo ===================================
echo Build Summary
echo ===================================
echo.
echo Client binaries:
dir /b s5proxy*.exe 2>nul || echo   (none built)
echo.
echo Server binaries:
dir /b backconnect_server*.exe 2>nul || echo   (none built)
echo.
echo Client build variants:
echo   s5proxy_dev.exe    - Development (with debug info)
echo   s5proxy.exe        - Optimized (fastest, no bounds check)
echo   s5proxy_secure.exe - Security-hardened (with bounds check)
echo   s5proxy_tiny.exe   - Minimal size
echo.
echo Server build variants:
echo   backconnect_server_dev.exe    - Development (with debug info)
echo   backconnect_server.exe        - Optimized (fastest, no bounds check)
echo   backconnect_server_secure.exe - Security-hardened (with bounds check)
echo.
echo Recommended for production:
echo   Client: s5proxy_secure.exe
echo   Server: backconnect_server_secure.exe
echo.
echo For maximum performance:
echo   Client: s5proxy.exe
echo   Server: backconnect_server.exe
echo.
echo For testing/debugging:
echo   Client: s5proxy_dev.exe
echo   Server: backconnect_server_dev.exe
