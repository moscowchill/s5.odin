# SOCKS5 Proxy Server (Odin)

Production-ready SOCKS5 proxy written in Odin. Hardened for real traffic with zero memory leaks, partial read protection, and robust error handling.

## Features

- RFC 1928 compliant SOCKS5
- IPv4/domain name support (IPv6 in normal mode only)
- Optional username/password auth (RFC 1929)
- Zero memory leaks
- Handles partial TCP reads (slow clients/congestion)
- Configurable buffer sizes (default 16KB)
- OS-bound connection limits (no artificial restrictions)
- **Backconnect mode**: Reverse proxy tunneling for clients behind NAT/firewall

## Build

```bash
./build.sh                                                    # Quick build
odin build s5_proxy.odin -file -o:speed -no-bounds-check    # Optimized
```

## Usage

### Normal Mode (Local SOCKS5 Server)

```bash
./s5proxy                                          # Listen on 127.0.0.1:1080
./s5proxy -addr 0.0.0.0:1080                       # Listen on all interfaces
./s5proxy -addr 0.0.0.0:1080 -auth -user a -pass b # With authentication
```

### Backconnect Mode (Reverse Tunnel)

```bash
# Server (on your VPS)
./backconnect_server -bc-psk $(openssl rand -hex 32)

# Client (on target network) - use OTP displayed by server
./s5proxy -backconnect -bc-server your-vps:8443 -bc-otp <otp>

# Route traffic through client's network
curl --socks5 your-vps:6000 http://internal-target/
```

## Options

### Client (s5proxy)

| Flag | Description | Default |
|------|-------------|---------|
| `-addr` | Listen address (normal mode) | `127.0.0.1:1080` |
| `-auth` | Require SOCKS5 authentication | `false` |
| `-user` | Username | `admin` |
| `-pass` | Password | `password` |
| `-v` | Verbose logging | `false` |
| `-backconnect` | Enable backconnect client mode | `false` |
| `-bc-server` | Backconnect server address | - |
| `-bc-otp` | One-time password (8 hex chars) | - |
| `-bc-psk` | Raw PSK for `-no-otp` servers | - |
| `-bc-pubkey` | Pin server public key | - |
| `-no-reconnect` | Disable auto-reconnect | `false` |

### Server (backconnect_server)

| Flag | Description | Default |
|------|-------------|---------|
| `-bc-addr` | Listen address for clients | `0.0.0.0:8443` |
| `-bc-psk` | Master PSK (64 hex chars) | required |
| `-no-otp` | Use raw PSK instead of OTP | `false` |
| `-socks-auth` | Require auth on SOCKS5 ports | `false` |
| `-socks-user` | SOCKS5 username | `admin` |
| `-socks-pass` | SOCKS5 password | `password` |
| `-v` | Verbose logging | `false` |

## Security Notes

**Detection:**
- *Normal mode:* SOCKS5 handshake is plaintext and easily detected by DPI
- *Backconnect mode:* Fully encrypted tunnel with encrypted handshake - only random bytes visible on the wire, resistant to protocol fingerprinting

For stealth on the SOCKS5 frontend (normal mode), wrap it in an encrypted tunnel:
- SSH tunnel: `ssh -D 1080 user@host`
- TLS wrapper: `stunnel`
- VPN: Wireguard/OpenVPN

**Defense:**
- Change default credentials
- Use firewall rules to restrict access
- Bind SOCKS5 frontend to localhost in backconnect mode
- Adjust `ulimit -n` for high concurrency

## Troubleshooting

**Connection refused:** Check firewall, verify port availability

**Auth failures:** Match credentials on client/server, enable `-v` to debug

**FD exhaustion:** Increase ulimit: `ulimit -n 100000` or edit `/etc/security/limits.conf`

## Backconnect Mode

Run a SOCKS5 proxy on machines behind NAT/firewall without opening inbound ports. The client connects **out** to your server, then you can tunnel traffic through the client's network.

### Architecture

```
┌─────────────────┐      ┌─────────────────────┐      ┌──────────────────┐
│   SOCKS5 User   │─────▶│  Backconnect Server │◀─────│ Backconnect Client│
│  (curl, browser)│      │   (Your VPS)        │      │  (Target network) │
└─────────────────┘      └─────────────────────┘      └──────────────────┘
     Connect to              :8443 BC listener           Connects OUT to
     :6000 (Client A)        :6000-8000 per-client       server:8443
     :6001 (Client B)
```

Each client gets a **dedicated SOCKS5 port** (6000-8000), so you can target specific client networks.

### Quick Start

```bash
# 1. Generate a master PSK (keep this secret on server)
PSK=$(openssl rand -hex 32)

# 2. Start the server (on your VPS) - displays OTP
./backconnect_server -bc-psk $PSK
# Server displays:
# ========================================
#   OTP (valid for 3h 59m):
#   abc123def456...  <- copy this
# ========================================

# 3. Start a client using the OTP (on target network)
./s5proxy -backconnect -bc-server your-server.com:8443 -bc-otp <otp-from-server>

# Client will display:
# ========================================
#   SOCKS5 Proxy Port Assigned: 6000
# ========================================

# 4. Route traffic through that specific client
curl --socks5 your-server.com:6000 http://internal-site.local
```

**OTP Mode (default):** Server generates time-based OTP that rotates every 4 hours. The master PSK never needs to be shared with clients.

### Multiple Clients

Each client gets its own dedicated port:

```
Client A (Office network)    → Port 6000
Client B (Home network)      → Port 6001
Client C (Cloud instance)    → Port 6002
```

Target a specific network by connecting to its port:
```bash
# Access Office network resources
curl --socks5 server:6000 http://office-intranet/

# Access Home network resources
curl --socks5 server:6001 http://192.168.1.1/

# Access Cloud network resources
curl --socks5 server:6002 http://10.0.0.5/
```

### Security

- **Encryption**: X25519 key exchange + ChaCha20-Poly1305
- **Authentication**: Time-based OTP derived from master PSK (rotates every 4h)
- **Key pinning**: Optional server public key verification
- **Opsec**: Master PSK stays on server, only OTP is shared with clients

See [BACKCONNECT.md](BACKCONNECT.md) for full protocol details.

## References

- [RFC 1928 - SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929 - SOCKS5 Auth](https://www.rfc-editor.org/rfc/rfc1929)
- [Original s5.go](https://github.com/ring04h/s5.go)
- [Odin Language](https://odin-lang.org/)

## License

Port of s5.go. Educational and authorized security testing only.
