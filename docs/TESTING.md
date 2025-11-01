# Testing

## Quick Validation

```bash
# Build
./build.sh

# Start proxy
./s5proxy -addr 127.0.0.1:1080 &
PID=$!

# Test basic connectivity
curl -x socks5://127.0.0.1:1080 https://ifconfig.me

# Kill
kill $PID
```

## Critical Tests

### Memory Leak Test

```bash
./s5proxy -addr 127.0.0.1:1080 &
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
print("✅ Partial read handled correctly")

s.close()
```

**Expected:** Connection succeeds despite slow sends

### Concurrent Load Test

```bash
./s5proxy -addr 127.0.0.1:1080 &
PID=$!

# 100 concurrent requests
seq 1 100 | xargs -P 20 -I {} curl -s -x socks5://127.0.0.1:1080 https://ifconfig.me > /dev/null

echo "✅ All 100 succeeded"

kill $PID
```

### Authentication Test

```bash
./s5proxy -addr 127.0.0.1:1080 -auth -user test -pass secret &
PID=$!

# With correct creds
curl -x socks5://test:secret@127.0.0.1:1080 https://ifconfig.me

# With wrong creds (should fail)
curl -x socks5://wrong:wrong@127.0.0.1:1080 https://ifconfig.me && echo "❌ Should have failed"

kill $PID
```

## Pentesting Tools

```bash
./s5proxy -addr 0.0.0.0:1080 &

# Nmap
nmap -sT -p 80,443 --proxies socks5://127.0.0.1:1080 scanme.nmap.org

# Proxychains
echo "socks5 127.0.0.1 1080" > /tmp/pc.conf
proxychains4 -f /tmp/pc.conf nmap -sT scanme.nmap.org
```

## Build Tests

### Linux
```bash
./build.sh
./s5proxy -h
```

### Windows
```cmd
build.bat
s5proxy.exe -h
```

## Performance Check

```bash
# With large buffer
time ./s5proxy -addr 127.0.0.1:1080 -buffer 65536 &
curl -x socks5://127.0.0.1:1080 https://speed.hetzner.de/10MB.bin -o /dev/null

# Default buffer
time ./s5proxy -addr 127.0.0.1:1080 &
curl -x socks5://127.0.0.1:1080 https://speed.hetzner.de/10MB.bin -o /dev/null
```

## Known Issues

- Authentication string comparison may have edge cases
- UDP ASSOCIATE not implemented
- BIND command not implemented
- No socket timeouts (vulnerable to Slowloris)

## Success Criteria

- ✅ No memory growth over 1000+ requests
- ✅ Handles partial reads (slow client test passes)
- ✅ Concurrent connections work
- ✅ Authentication blocks wrong credentials
- ✅ Works with standard pentesting tools
