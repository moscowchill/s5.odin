@echo off
REM Build script for SOCKS5 Proxy Server (Windows)

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

REM Build Client
echo ===================================
echo Building Client
echo ===================================
echo.

echo [1/2] Building client (debug)...
odin build s5_proxy.odin -file -out:s5proxy_dev.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] s5proxy_dev.exe
) else (
    echo [FAIL] s5proxy_dev.exe
    exit /b 1
)

echo [2/2] Building client (release)...
odin build s5_proxy.odin -file -o:speed -no-bounds-check -out:s5proxy.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] s5proxy.exe
) else (
    echo [FAIL] s5proxy.exe
    exit /b 1
)

echo.
REM Build Server
echo ===================================
echo Building Server
echo ===================================
echo.

echo [1/2] Building server (debug)...
odin build cmd/server -out:backconnect_server_dev.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] backconnect_server_dev.exe
) else (
    echo [FAIL] backconnect_server_dev.exe
    exit /b 1
)

echo [2/2] Building server (release)...
odin build cmd/server -o:speed -no-bounds-check -out:backconnect_server.exe
if %ERRORLEVEL% EQU 0 (
    echo [OK] backconnect_server.exe
) else (
    echo [FAIL] backconnect_server.exe
    exit /b 1
)

echo.
echo ===================================
echo Done
echo ===================================
echo.
echo   s5proxy.exe           - Client (release)
echo   s5proxy_dev.exe       - Client (debug)
echo   backconnect_server.exe     - Server (release)
echo   backconnect_server_dev.exe - Server (debug)
echo.
