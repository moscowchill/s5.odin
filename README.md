# SOCKS5 Proxy Server (Odin)

Production-ready SOCKS5 proxy written in Odin. Hardened for real traffic with zero memory leaks, partial read protection, and robust error handling.

## Features

- RFC 1928 compliant SOCKS5
- IPv4/IPv6/domain name support
- Optional username/password auth (RFC 1929)
- Zero memory leaks
- Handles partial TCP reads (slow clients/congestion)
- Configurable buffer sizes (default 16KB)
- OS-bound connection limits (no artificial restrictions)

## Build

```bash
./build.sh                                                    # Quick build
odin build s5_proxy.odin -file -o:speed -no-bounds-check    # Optimized
```

## Usage

```bash
# Basic
./s5proxy

# Custom address
./s5proxy -addr 0.0.0.0:1080

# With authentication
./s5proxy -addr 0.0.0.0:1080 -auth -user admin -pass secret

# Verbose logging
./s5proxy -v

# Custom buffer size
./s5proxy -buffer 32768
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-addr` | Listen address:port | `127.0.0.1:1080` |
| `-v` | Verbose logging | `false` |
| `-auth` | Require authentication | `false` |
| `-user` | Username | `admin` |
| `-pass` | Password | `password` |
| `-buffer` | Buffer size (bytes) | `16384` |

## Testing

```bash
# Basic test
curl -x socks5://127.0.0.1:1080 https://ifconfig.me

# With auth
curl -x socks5://user:pass@127.0.0.1:1080 https://ifconfig.me

# Proxychains
echo "socks5 127.0.0.1 1080" > /tmp/proxychains.conf
proxychains4 -f /tmp/proxychains.conf curl https://ifconfig.me
```

## Pentesting

```bash
# Internal pivoting
./s5proxy -addr 0.0.0.0:1080 -auth -user pivot -pass [random]

# Use with tools
nmap --proxies socks5://pivot:pass@proxy:1080 target
burpsuite  # Configure SOCKS5 in settings
sqlmap --proxy=socks5://pivot:pass@proxy:1080 ...
```

## Security Notes

**Detection:** SOCKS5 handshake is plaintext and easily detected by DPI. For actual stealth:
- Use SSH tunnel: `ssh -D 1080 user@host`
- Use TLS wrapper: `stunnel`
- Use VPN: Wireguard/OpenVPN

**Defense:**
- Change default credentials
- Use firewall rules to restrict access
- Wrap in encrypted tunnel if exposed
- Adjust `ulimit -n` for high concurrency

## Troubleshooting

**Connection refused:** Check firewall, verify port availability

**Auth failures:** Match credentials on client/server, enable `-v` to debug

**FD exhaustion:** Increase ulimit: `ulimit -n 100000` or edit `/etc/security/limits.conf`

## References

- [RFC 1928 - SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929 - SOCKS5 Auth](https://www.rfc-editor.org/rfc/rfc1929)
- [Original s5.go](https://github.com/ring04h/s5.go)
- [Odin Language](https://odin-lang.org/)

## License

Port of s5.go. Educational and authorized security testing only.
