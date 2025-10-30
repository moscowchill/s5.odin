# Stealth SOCKS5 Proxy Server (Odin)

A modern, high-performance SOCKS5 proxy server written in Odin, ported from the original [s5.go](https://github.com/ring04h/s5.go) with significant enhancements for red teaming operations.

## Features

### Core SOCKS5 Support
- **SOCKS5 Protocol**: Full RFC 1928 compliant implementation
- **Connection Types**: CONNECT command support (BIND and UDP_ASSOCIATE stubs included)
- **Address Types**: IPv4, IPv6, and domain name resolution
- **Authentication**: No-auth mode and username/password authentication (RFC 1929)

### Stealth Enhancements for Red Teaming

This implementation includes several features designed to evade detection and blend in with normal network traffic:

1. **Traffic Timing Obfuscation**
   - Random micro-delays (0-5ms) between packet transmissions
   - Connection establishment delays (10-100ms) to avoid burst patterns
   - Accept delays (0-50ms) to randomize connection acceptance patterns

2. **Configurable Behavior**
   - Adjustable buffer sizes to match different network profiles
   - Minimal logging by default (stealth operation)
   - Optional verbose mode for debugging

3. **Modern Architecture**
   - Native Odin implementation for better performance
   - Concurrent connection handling with threads
   - Efficient bidirectional data relay

4. **Security Features**
   - Optional username/password authentication
   - No persistent connection tracking (minimal memory footprint)
   - Clean shutdown and resource management

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

### Stealth Mode

Stealth mode is **enabled by default**. To disable timing obfuscation:
```bash
./s5proxy -no-stealth
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-addr <address>` | Listen address and port | `127.0.0.1:1080` |
| `-v`, `-verbose` | Enable verbose logging | `false` |
| `-auth` | Require authentication | `false` |
| `-user <username>` | Authentication username | `admin` |
| `-pass <password>` | Authentication password | `password` |
| `-no-stealth` | Disable timing obfuscation | Stealth enabled |
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

## Red Teaming Use Cases

### 1. Internal Network Pivoting

Deploy on compromised host:
```bash
./s5proxy -addr 0.0.0.0:1080 -auth -user pivot -pass [random-pass] -no-stealth
```

Connect from attacker machine:
```bash
ssh -D 1080 -N -f user@compromised-host
# Or use the proxy directly if exposed
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

### 3. Egress Point Obfuscation

```bash
# Listen on non-standard port with stealth timing
./s5proxy -addr 0.0.0.0:8443 -auth -user web -pass [pass]
```

The stealth timing features help avoid detection by:
- Breaking up consistent timing patterns
- Mimicking human interaction delays
- Reducing network burst signatures

## Architecture

### Connection Flow

```
Client → Handshake → Authentication (optional) → Request Parsing → Connect → Relay
```

### Threading Model

- Main thread: Accept connections
- Connection thread: Handle SOCKS5 protocol
- Relay threads (2x): Bidirectional data transfer

### Stealth Features Implementation

1. **Accept Loop**: Random 0-50ms delay between accepts
2. **Connect Delay**: Random 10-100ms delay before target connection
3. **Relay Micro-delays**: Random 0-5ms delays during data transfer

These delays are small enough to not significantly impact performance but large enough to break statistical timing analysis.

## Comparison with Original Go Implementation

| Feature | Original s5.go | This Port |
|---------|----------------|-----------|
| Language | Go | Odin |
| Authentication | No auth only | No auth + user/pass |
| Stealth Features | None | Timing obfuscation |
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
5. **Disable stealth** for maximum performance if detection isn't a concern

### Detection Vectors

Even with stealth features, proxies can be detected by:
- Deep packet inspection (use encrypted tunnels)
- Active probing (use authentication + firewall rules)
- Behavioral analysis over long periods
- TLS fingerprinting (if using HTTPS through proxy)

### Mitigation Strategies

1. **Layer tunneling**: Wrap in SSH/TLS/VPN
2. **Port selection**: Use common ports (443, 8080)
3. **Access control**: IP whitelisting + authentication
4. **Traffic shaping**: Adjust buffer sizes and timing
5. **Rotation**: Change proxy instances regularly

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

- Disable stealth mode: `-no-stealth`
- Increase buffer size: `-buffer 65536`
- Check network latency to target

### High CPU Usage

- Reduce buffer size for many small connections
- Disable verbose logging
- Check for connection leaks (should auto-cleanup)

## Future Enhancements

Potential additions for future versions:

- [ ] UDP ASSOCIATE implementation
- [ ] BIND command support
- [ ] TLS/SSL wrapper support
- [ ] Traffic encryption between client and proxy
- [ ] Connection pooling and reuse
- [ ] Access control lists (ACL)
- [ ] Bandwidth throttling
- [ ] Connection statistics and monitoring
- [ ] Multi-hop proxy chaining
- [ ] Protocol obfuscation (looks like HTTPS, DNS, etc.)

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
- Additional stealth features
- Performance optimizations
- Better error handling
- Cross-platform testing

## Disclaimer

This tool is provided for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before deploying or using this proxy server. Unauthorized access to computer systems is illegal.
