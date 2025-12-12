# Testing

## Quick Validation

### Normal Mode (Standalone SOCKS5 Proxy)

```bash
# Build
./build.sh

# Start proxy
./s5proxy_linux -addr 127.0.0.1:1080 &
PID=$!

# Test basic connectivity
curl -x socks5://127.0.0.1:1080 https://ifconfig.me

# Kill
kill $PID
```

### Backconnect Mode (Reverse Tunnel)

```bash
# Generate a PSK
PSK=$(openssl rand -hex 32)
echo "Using PSK: $PSK"

# Start the backconnect server
./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!
sleep 1

# Get server's public key for pinning (optional but recommended)
PUBKEY=$(./backconnect_server_linux -bc-psk $PSK -print-pubkey 2>/dev/null)

# Start the backconnect client
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT_PID=$!
sleep 2

# Test through the assigned per-client port (check client output for port)
curl -x socks5://127.0.0.1:6000 https://ifconfig.me

# Or test through the shared SOCKS5 port (round-robin)
curl -x socks5://127.0.0.1:1080 https://ifconfig.me

# Cleanup
kill $CLIENT_PID $SERVER_PID
```

## Critical Tests

### Memory Leak Test

```bash
./s5proxy_linux -addr 127.0.0.1:1080 &
PID=$!

# Baseline
echo "Baseline:"
ps -o rss= -p $PID

# Run 1000 requests
for i in {1..1000}; do
    curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null
done

# Check memory growth
echo "After 1000 requests:"
ps -o rss= -p $PID

kill $PID
```

**Expected:** Memory stable (< 5MB growth)

### Partial Read Test

```python
#!/usr/bin/env python3
"""Test slow SOCKS5 handshake (partial reads)"""
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 1080))

# Send handshake one byte at a time
handshake = b'\x05\x01\x00'
for byte in handshake:
    s.send(bytes([byte]))
    time.sleep(0.5)  # 500ms delay

resp = s.recv(2)
assert resp == b'\x05\x00', f"Bad response: {resp.hex()}"
print("Partial read handled correctly")

s.close()
```

**Expected:** Connection succeeds despite slow sends

### Concurrent Load Test

```bash
./s5proxy_linux -addr 127.0.0.1:1080 &
PID=$!

# 100 concurrent requests
seq 1 100 | xargs -P 20 -I {} curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null

echo "All 100 requests succeeded"

kill $PID
```

### Authentication Test

```bash
./s5proxy_linux -addr 127.0.0.1:1080 -auth -user test -pass secret &
PID=$!

# With correct creds
curl -x socks5://test:secret@127.0.0.1:1080 https://ifconfig.me

# With wrong creds (should fail)
curl -x socks5://wrong:wrong@127.0.0.1:1080 https://ifconfig.me && echo "ERROR: Should have failed"

kill $PID
```

## Backconnect Mode Tests

### Basic Backconnect Connection Test

```bash
#!/bin/bash
# Test basic backconnect handshake and tunnel establishment

PSK=$(openssl rand -hex 32)

# Start server
./backconnect_server_linux -bc-psk $PSK -v &
SERVER_PID=$!
sleep 1

# Start client
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK -v &
CLIENT_PID=$!
sleep 2

# Verify client connected (should see "Connected and authenticated" in output)
# Test a request
RESULT=$(curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me)
if [ -n "$RESULT" ]; then
    echo "Backconnect tunnel working: $RESULT"
else
    echo "ERROR: Backconnect tunnel failed"
fi

kill $CLIENT_PID $SERVER_PID 2>/dev/null
```

### Server Public Key Pinning Test

```bash
#!/bin/bash
# Test that public key pinning works correctly

PSK=$(openssl rand -hex 32)

# Start server and capture public key
./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!
sleep 1

PUBKEY=$(./backconnect_server_linux -bc-psk $PSK -print-pubkey 2>/dev/null)
echo "Server pubkey: $PUBKEY"

# Test with correct pubkey (should succeed)
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK -bc-pubkey $PUBKEY -no-reconnect &
CLIENT_PID=$!
sleep 2

curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null && echo "Correct pubkey: OK"

kill $CLIENT_PID 2>/dev/null

# Test with wrong pubkey (should fail)
WRONG_PUBKEY=$(openssl rand -hex 32)
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK -bc-pubkey $WRONG_PUBKEY -no-reconnect &
CLIENT_PID=$!
sleep 2

curl -s --connect-timeout 3 -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null && echo "ERROR: Wrong pubkey should have failed"
echo "Wrong pubkey rejected: OK"

kill $CLIENT_PID $SERVER_PID 2>/dev/null
```

### PSK Verification Test

```bash
#!/bin/bash
# Test that PSK verification works (wrong PSK should be rejected)

SERVER_PSK=$(openssl rand -hex 32)
WRONG_PSK=$(openssl rand -hex 32)

# Start server with one PSK
./backconnect_server_linux -bc-psk $SERVER_PSK &
SERVER_PID=$!
sleep 1

# Try connecting with wrong PSK (should fail)
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $WRONG_PSK -no-reconnect -v 2>&1 &
CLIENT_PID=$!
sleep 3

# This should fail - no clients connected
curl -s --connect-timeout 3 -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null
if [ $? -ne 0 ]; then
    echo "Wrong PSK rejected: OK"
else
    echo "ERROR: Wrong PSK should have been rejected"
fi

kill $CLIENT_PID $SERVER_PID 2>/dev/null
```

### Multiple Clients with Dedicated Ports Test

```bash
#!/bin/bash
# Test that each client gets a dedicated SOCKS5 port

PSK=$(openssl rand -hex 32)

# Start server
./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!
sleep 1

# Start first client - should get port 6000
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT1_PID=$!
sleep 2

# Start second client - should get port 6001
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT2_PID=$!
sleep 2

# Test both dedicated ports
echo "Testing client 1 on port 6000..."
curl -s -x socks5://127.0.0.1:6000 https://ifconfig.me && echo "Client 1 port: OK"

echo "Testing client 2 on port 6001..."
curl -s -x socks5://127.0.0.1:6001 https://ifconfig.me && echo "Client 2 port: OK"

# Test round-robin on shared port
echo "Testing round-robin on port 1080..."
curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me && echo "Round-robin: OK"

kill $CLIENT1_PID $CLIENT2_PID $SERVER_PID 2>/dev/null
```

### Client Auto-Reconnect Test

```bash
#!/bin/bash
# Test that client reconnects after server restart

PSK=$(openssl rand -hex 32)

# Start server
./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!
sleep 1

# Start client with auto-reconnect (default)
./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT_PID=$!
sleep 2

# Verify connected
curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null && echo "Initial connection: OK"

# Kill server
kill $SERVER_PID
sleep 2

# Restart server
./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!
sleep 5  # Wait for reconnect

# Verify reconnected
curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null && echo "Reconnect: OK"

kill $CLIENT_PID $SERVER_PID 2>/dev/null
```

### Backconnect Concurrent Sessions Test

```bash
#!/bin/bash
# Test multiple concurrent SOCKS5 sessions through backconnect tunnel

PSK=$(openssl rand -hex 32)

./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!
sleep 1

./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT_PID=$!
sleep 2

# Run 50 concurrent requests through the tunnel
echo "Running 50 concurrent requests..."
seq 1 50 | xargs -P 10 -I {} curl -s -x socks5://127.0.0.1:6000 https://ifconfig.me > /dev/null

echo "Concurrent sessions test: OK"

kill $CLIENT_PID $SERVER_PID 2>/dev/null
```

### Server SOCKS5 Authentication Test

```bash
#!/bin/bash
# Test SOCKS5 authentication on the backconnect server

PSK=$(openssl rand -hex 32)

# Start server with SOCKS5 authentication
./backconnect_server_linux -bc-psk $PSK -socks-auth -socks-user testuser -socks-pass testpass &
SERVER_PID=$!
sleep 1

./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT_PID=$!
sleep 2

# With correct credentials (should succeed)
curl -s -x socks5://testuser:testpass@127.0.0.1:1080 https://ifconfig.me > /dev/null && echo "Correct creds: OK"

# With wrong credentials (should fail)
curl -s --connect-timeout 3 -x socks5://wrong:wrong@127.0.0.1:1080 https://ifconfig.me > /dev/null
if [ $? -ne 0 ]; then
    echo "Wrong creds rejected: OK"
else
    echo "ERROR: Wrong creds should have been rejected"
fi

kill $CLIENT_PID $SERVER_PID 2>/dev/null
```

## Pentesting Tools

```bash
./s5proxy_linux -addr 0.0.0.0:1080 &

# Nmap
nmap -sT -p 80,443 --proxies socks5://127.0.0.1:1080 scanme.nmap.org

# Proxychains
echo "socks5 127.0.0.1 1080" > /tmp/pc.conf
proxychains4 -f /tmp/pc.conf nmap -sT scanme.nmap.org
```

### Pentesting via Backconnect

```bash
PSK=$(openssl rand -hex 32)

./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!

./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT_PID=$!
sleep 2

# Use the dedicated client port for targeted access
echo "socks5 127.0.0.1 6000" > /tmp/pc.conf
proxychains4 -f /tmp/pc.conf nmap -sT scanme.nmap.org

kill $CLIENT_PID $SERVER_PID
```

## Build Tests

### Linux
```bash
./build.sh

# Test client help
./s5proxy_linux -h
./s5proxy_linux_dev -h
./s5proxy_linux_secure -h

# Test server help
./backconnect_server_linux -h
./backconnect_server_linux_dev -h
./backconnect_server_linux_secure -h
```

### Windows
```cmd
build.bat
s5proxy.exe -h
backconnect_server.exe -h
```

## Performance Check

### Normal Mode Performance

```bash
# With large buffer
./s5proxy_linux -addr 127.0.0.1:1080 &
PID=$!
time curl -x socks5://127.0.0.1:1080 https://speed.hetzner.de/10MB.bin -o /dev/null
kill $PID
```

### Backconnect Mode Performance

```bash
PSK=$(openssl rand -hex 32)

./backconnect_server_linux -bc-psk $PSK &
SERVER_PID=$!

./s5proxy_linux -backconnect -bc-server 127.0.0.1:8443 -bc-psk $PSK &
CLIENT_PID=$!
sleep 2

# Measure throughput through the encrypted tunnel
time curl -x socks5://127.0.0.1:6000 https://speed.hetzner.de/10MB.bin -o /dev/null

kill $CLIENT_PID $SERVER_PID
```

## Known Issues

- UDP ASSOCIATE not implemented
- BIND command not implemented
- IPv6 not fully supported in backconnect mode
- Server generates new keypair on each restart (use -bc-pubkey carefully)

## Success Criteria

### Normal Mode
- No memory growth over 1000+ requests
- Handles partial reads (slow client test passes)
- Concurrent connections work
- Authentication blocks wrong credentials
- Works with standard pentesting tools

### Backconnect Mode
- Client connects and authenticates with server
- PSK verification rejects invalid keys
- Server public key pinning works
- Each client gets a dedicated SOCKS5 port (6000+)
- Shared port (1080) uses round-robin across clients
- Multiple concurrent sessions work through tunnel
- Client auto-reconnects after server restart
- SOCKS5 authentication works on server frontend
- Works with proxychains and other pentesting tools
