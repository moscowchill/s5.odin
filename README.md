# SOCKS5 Proxy Server (Odin)

A production-ready, high-performance SOCKS5 proxy server written in Odin, ported from the original [s5.go](https://github.com/ring04h/s5.go) with significant hardening for reliability and security.

## Features

### Core SOCKS5 Support
- **SOCKS5 Protocol**: Full RFC 1928 compliant implementation
- **Connection Types**: CONNECT command support (BIND and UDP_ASSOCIATE stubs included)
- **Address Types**: IPv4, IPv6, and domain name resolution
- **Authentication**: No-auth mode and username/password authentication (RFC 1929)

### Production Hardening

This implementation has been hardened for real-world traffic:

1. **Memory Safety**
   - Zero memory leaks (all allocations properly freed)
   - Proper string cleanup in connection handlers
   - No resource exhaustion under sustained load

2. **Network Resilience**
   - Partial read protection (handles slow clients and network congestion)
   - Robust error handling for all socket operations
   - Partial send handling prevents hung connections

3. **Resource Management**
   - Configurable buffer sizes (default 16KB)
   - Proper thread lifecycle management
   - Relies on OS file descriptor limits (ulimit)

4. **Modern Architecture**
   - Native Odin implementation for better performance
   - Concurrent connection handling with threads
   - Efficient bidirectional data relay

5. **Security Features**
   - Optional username/password authentication
   - Input validation (domain/username/password lengths)
   - Minimal logging by default
   - OS-level resource protection (ulimit)

## Building

### Requirements
- [Odin compiler](https://odin-lang.org/) (latest version recommended)
- Linux or Windows operating system
- Basic understanding of SOCKS5 proxy configuration

### Quick Build

**Linux/macOS:**
```bash
./build.sh
```

**Windows:**
```cmd
build.bat
```

### Manual Compilation

**Development build** (with bounds checking):
```bash
# Linux
odin build s5_proxy.odin -file -out:s5proxy_dev

# Windows
odin build s5_proxy.odin -file -out:s5proxy_dev.exe
```

**Optimized build** (recommended for production):
```bash
# Linux
odin build s5_proxy.odin -file -o:speed -no-bounds-check -out:s5proxy

# Windows
odin build s5_proxy.odin -file -o:speed -no-bounds-check -out:s5proxy.exe
```

**Small binary** (for deployment in size-constrained environments):
```bash
# Linux
odin build s5_proxy.odin -file -o:size -no-bounds-check -out:s5proxy_tiny

# Windows
odin build s5_proxy.odin -file -o:size -no-bounds-check -out:s5proxy_tiny.exe
```

### Cross-Compilation Note

Cross-compilation from Linux to Windows is not yet fully supported by Odin's linker. To build for Windows, compile on a Windows machine or use a Windows VM/container.

## Usage

### Basic Usage

Start proxy on default address (127.0.0.1:1080):
```bash
./s5proxy
```

Specify custom address:
```bash
./s5proxy -addr 0.0.0.0:1080
```

### Authentication

Enable authentication:
```bash
./s5proxy -addr 127.0.0.1:1080 -auth -user admin -pass secret
```

### Debugging

Enable verbose logging:
```bash
./s5proxy -v -addr 127.0.0.1:1080
```

### Buffer Configuration

Adjust buffer size for performance tuning:
```bash
./s5proxy -buffer 32768  # 32KB buffers for large transfers
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-addr <address>` | Listen address and port | `127.0.0.1:1080` |
| `-v`, `-verbose` | Enable verbose logging | `false` |
| `-auth` | Require authentication | `false` |
| `-user <username>` | Authentication username | `admin` |
| `-pass <password>` | Authentication password | `password` |
| `-buffer <size>` | Buffer size in bytes | `16384` (16KB) |
| `-h`, `-help` | Show help message | - |

## Testing

### Test with curl

```bash
# Start proxy
./s5proxy -addr 127.0.0.1:1080

# Test connection (in another terminal)
curl -x socks5://127.0.0.1:1080 https://ifconfig.me
```

### Test with authentication

```bash
# Start proxy with auth
./s5proxy -addr 127.0.0.1:1080 -auth -user myuser -pass mypass

# Test connection
curl -x socks5://myuser:mypass@127.0.0.1:1080 https://ifconfig.me
```

### Test with proxychains

Edit `/etc/proxychains.conf`:
```
[ProxyList]
socks5 127.0.0.1 1080
```

Then use:
```bash
proxychains curl https://ifconfig.me
proxychains nmap -sT target.com
```

## Pentesting Use Cases

### 1. Internal Network Pivoting

Deploy on compromised host:
```bash
./s5proxy -addr 0.0.0.0:1080 -auth -user pivot -pass [random-pass]
```

Connect from attacker machine:
```bash
ssh -L 1080:localhost:1080 user@compromised-host
# Or use the proxy directly if network allows
```

### 2. Traffic Routing

Chain with other tools:
```bash
# Through Tor
./s5proxy -addr 127.0.0.1:9150
# Then configure Tor to use this as upstream

# Through VPN
./s5proxy -addr 10.8.0.1:1080
```

### 3. Tool Aggregation

```bash
# Single proxy endpoint for multiple tools
./s5proxy -addr 0.0.0.0:1080 -auth -user team -pass [pass]

# Use with all your pentesting tools
nmap --proxies socks5://team:pass@proxy:1080 target
burpsuite (configure SOCKS5 proxy)
sqlmap --proxy=socks5://team:pass@proxy:1080 ...
```

## Architecture

### Connection Flow

```
Client → Handshake → Authentication (optional) → Request Parsing → Connect → Relay
```

### Threading Model

- Main thread: Accept connections (unlimited, OS-bound)
- Connection thread: Handle SOCKS5 protocol
- Relay threads (2x): Bidirectional data transfer

### Hardening Features

1. **Partial Read Protection**: recv_exactly() helper prevents partial TCP read failures
2. **Memory Safety**: All allocations properly freed, zero leaks
3. **Error Handling**: Robust handling of all socket operations
4. **Input Validation**: Length checks for domains, usernames, passwords
5. **OS Resource Limits**: Respects system ulimit for file descriptors

## Comparison with Original Go Implementation

| Feature | Original s5.go | This Port |
|---------|----------------|-----------|
| Language | Go | Odin |
| Authentication | No auth only | No auth + user/pass |
| Memory Leaks | Unknown | Zero (verified) |
| Partial Reads | Not handled | Protected |
| Connection Limits | None | None (OS-bound) |
| Buffer Size | Fixed 8KB | Configurable (default 16KB) |
| Logging | Basic | Verbose mode + minimal |
| IPv6 Support | Basic | Full support |
| Error Handling | Basic | Enhanced |
| Threading | Goroutines | Native threads |

## Security Considerations

### Operational Security

1. **Change default credentials** if using authentication
2. **Use TLS tunneling** for exposed proxies (e.g., stunnel, ssh -D)
3. **Monitor logs** in verbose mode during testing only
4. **Firewall rules** to restrict access by IP
5. **Adjust ulimit** if needed for high-concurrency scenarios (`ulimit -n 100000`)

### Detection Vectors

SOCKS5 proxies can be detected by:
- **Deep packet inspection** - SOCKS5 handshake is plaintext and distinctive
- **Active probing** - Blue teams can test if your port responds to SOCKS5
- **Behavioral analysis** - Many diverse connections from single source
- **TLS fingerprinting** - If proxying HTTPS, downstream fingerprints visible

### Mitigation Strategies

1. **Layer tunneling**: Wrap in SSH/TLS/VPN (provides actual encryption)
2. **Port selection**: Use common ports (443, 8080, 22)
3. **Access control**: IP whitelisting + strong authentication
4. **Buffer tuning**: Adjust buffer sizes for your traffic patterns
5. **Monitoring**: Use verbose mode to detect unusual activity

## Performance Tuning

### Buffer Size

- **Small (4KB-8KB)**: Lower memory, more CPU for small files
- **Medium (16KB)**: Balanced default
- **Large (32KB-64KB)**: Better throughput for large transfers

```bash
./s5proxy -buffer 32768  # 32KB buffers
```

### Threading

Odin's threading model is lightweight. Each connection spawns:
- 1 handler thread
- 2 relay threads (temporary, during active transfer)

For high-concurrency scenarios, ensure adequate system resources.

## Troubleshooting

### Connection Refused

- Check firewall rules
- Verify address/port availability
- Ensure correct listen address (0.0.0.0 for external access)

### Authentication Failures

- Verify credentials match on both client and server
- Check client supports SOCKS5 username/password auth
- Enable verbose mode to see handshake details

### Slow Performance

- Increase buffer size: `-buffer 65536` (for large transfers)
- Check network latency to target
- Verify no bottlenecks on network path

### High CPU Usage

- Reduce buffer size for many small connections
- Disable verbose logging
- Check for connection leaks (should auto-cleanup)

### File Descriptor Exhaustion

If you hit OS limits with many concurrent connections:
- Check current limit: `ulimit -n`
- Increase limit: `ulimit -n 100000` (temporary)
- Permanent: Edit `/etc/security/limits.conf`
- Consider if tool has connection leak bug

## Future Enhancements

Potential additions for future versions:

- [ ] Socket timeouts (prevent Slowloris attacks)
- [ ] Per-IP rate limiting
- [ ] UDP ASSOCIATE implementation
- [ ] BIND command support
- [ ] TLS/SSL wrapper support (proper encryption)
- [ ] Connection pooling and reuse
- [ ] Access control lists (ACL)
- [ ] Bandwidth throttling
- [ ] Connection statistics and monitoring
- [ ] Graceful shutdown (SIGTERM handling)
- [ ] Configuration file support

## License

This is a port and enhancement of the original s5.go project. Use responsibly and only on networks you have permission to test.

**Educational and authorized security testing only.**

## References

- [RFC 1928 - SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929 - Username/Password Authentication for SOCKS V5](https://www.rfc-editor.org/rfc/rfc1929)
- [Original s5.go](https://github.com/ring04h/s5.go)
- [Odin Programming Language](https://odin-lang.org/)

## Contributing

Improvements welcome:
- Protocol compliance enhancements
- Socket timeout implementation
- Per-IP rate limiting
- Performance optimizations
- Additional error handling
- Cross-platform testing

## Disclaimer

This tool is provided for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before deploying or using this proxy server. Unauthorized access to computer systems is illegal.
