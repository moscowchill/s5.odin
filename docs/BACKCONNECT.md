# Backconnect SOCKS5 Proxy

A reverse-tunnel SOCKS5 proxy where the client connects OUT to a server, then receives and executes SOCKS5 requests through an encrypted, multiplexed tunnel.

## Architecture

```
┌─────────────────┐      ┌─────────────────────┐      ┌──────────────────┐
│   SOCKS5 User   │─────▶│  Backconnect Server │◀─────│ Backconnect Client│
│  (curl, browser)│      │   (SOCKS5 frontend) │      │  (behind NAT/FW) │
└─────────────────┘      └─────────────────────┘      └──────────────────┘
                              :1080 SOCKS5              connects to :8443
                              :8443 BC listener         executes requests
```

**Use case:** Run a SOCKS5 proxy on a machine behind NAT/firewall without opening inbound ports.

## Quick Start

### 1. Generate a PSK (Pre-Shared Key)

```bash
# Generate a random 32-byte (64 hex char) PSK
openssl rand -hex 32
# Example output: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### 2. Start the Server

```bash
# On your public-facing server
./backconnect_server -bc-psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Output:
# Server public key: <64-hex-chars>
# SOCKS5 listener on 127.0.0.1:1080
# Backconnect listener on 0.0.0.0:8443
```

### 3. Start the Client

```bash
# On the machine behind NAT (copy the server's public key from step 2)
./s5proxy -backconnect \
  -bc-server your-server.com:8443 \
  -bc-psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -bc-pubkey <server-public-key>
```

### 4. Use the Proxy

```bash
# Connect through the server's SOCKS5 frontend
curl --socks5 your-server.com:1080 http://ifconfig.me
```

## Building

```bash
# Build the client (extends existing s5proxy)
odin build . -out:s5proxy

# Build the server
cd cmd/server
odin build . -out:backconnect_server
```

## Server Options

```
backconnect_server [options]

SOCKS5 Frontend:
  -socks-addr <addr>   Listen address for SOCKS5 clients (default: 127.0.0.1:1080)
  -socks-auth          Require SOCKS5 username/password authentication
  -socks-user <user>   SOCKS5 username (default: admin)
  -socks-pass <pass>   SOCKS5 password (default: password)

Backconnect Backend:
  -bc-addr <addr>      Listen address for backconnect clients (default: 0.0.0.0:8443)
  -bc-psk <hex>        Allowed client PSK, 64 hex chars (can specify multiple)

General:
  -v, -verbose         Enable verbose logging
  -print-pubkey        Print server public key and exit
  -h, -help            Show help
```

### Multiple PSKs

You can allow multiple clients with different PSKs:

```bash
./backconnect_server \
  -bc-psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -bc-psk abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567
```

### SOCKS5 Authentication

```bash
./backconnect_server \
  -bc-psk <psk> \
  -socks-auth \
  -socks-user myuser \
  -socks-pass mypass
```

## Client Options

```
s5proxy -backconnect [options]

Required:
  -backconnect         Enable backconnect client mode
  -bc-server <addr>    Server address (host:port)
  -bc-psk <hex>        Pre-shared key (64 hex characters)

Optional:
  -bc-pubkey <hex>     Server public key for pinning (recommended)
  -no-reconnect        Disable automatic reconnection
  -v, -verbose         Enable verbose logging
```

### Server Key Pinning

For security, pin the server's public key to prevent MITM attacks:

```bash
# Get server's public key
./backconnect_server -print-pubkey
# Output: a1b2c3d4...

# Use it when connecting
./s5proxy -backconnect \
  -bc-server example.com:8443 \
  -bc-psk <psk> \
  -bc-pubkey a1b2c3d4...
```

## Protocol

### Encryption

- **Key Exchange:** X25519 (Curve25519 ECDH)
- **Symmetric Cipher:** ChaCha20-Poly1305 AEAD
- **Key Derivation:** SHA256(shared_secret || nonce || direction || psk)
- **Forward Secrecy:** Client generates ephemeral keypair per connection

### Handshake

```
Client                              Server
   |                                   |
   |◀──────── TCP Connect ─────────────|
   |                                   |
   |◀─────── HANDSHAKE_INIT ───────────|  server_pubkey (32) + nonce (24)
   |                                   |
   |──────── HANDSHAKE_RESP ──────────▶|  client_pubkey (32) + encrypted_psk (48)
   |                                   |
   |◀─────── HANDSHAKE_ACK ────────────|  status (encrypted)
   |                                   |
   |═══════ Encrypted Channel ═════════|
```

### Wire Format

After handshake, all messages are encrypted:

```
┌────────────────┬──────────────────────────────────────────┐
│ Length (2 BE)  │ Encrypted(counter + type + session + payload + tag) │
└────────────────┴──────────────────────────────────────────┘
```

### Message Types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| HANDSHAKE_INIT | 0x01 | S→C | Server sends pubkey + nonce |
| HANDSHAKE_RESP | 0x02 | C→S | Client sends pubkey + encrypted PSK |
| HANDSHAKE_ACK | 0x03 | S→C | Authentication result |
| PING | 0x04 | Both | Keepalive request |
| PONG | 0x05 | Both | Keepalive response |
| SESSION_NEW | 0x10 | S→C | New connection request |
| SESSION_READY | 0x11 | C→S | Connection established |
| SESSION_DATA | 0x12 | Both | Tunnel data |
| SESSION_CLOSE | 0x13 | Both | Close session |

### Session Multiplexing

Multiple SOCKS5 connections are multiplexed over a single encrypted tunnel using 32-bit session IDs.

## Security Considerations

1. **Use strong PSKs:** Generate with `openssl rand -hex 32`
2. **Pin server keys:** Always use `-bc-pubkey` in production
3. **Restrict SOCKS5 access:** Bind to localhost or use `-socks-auth`
4. **Firewall the BC port:** Only allow expected client IPs on port 8443

## Multiple Clients

The server supports multiple simultaneous backconnect clients. SOCKS5 requests are distributed round-robin across connected clients.

```bash
# Server accepts multiple clients
./backconnect_server -bc-psk <shared-psk> -v

# Multiple clients can connect with the same PSK
# Client 1:
./s5proxy -backconnect -bc-server server:8443 -bc-psk <shared-psk>

# Client 2:
./s5proxy -backconnect -bc-server server:8443 -bc-psk <shared-psk>
```

## Troubleshooting

### Connection refused
- Check firewall allows port 8443 (or your -bc-addr port)
- Verify server is running: `ss -tlnp | grep 8443`

### PSK verification failed
- Ensure PSK is exactly 64 hex characters
- Verify same PSK on both client and server

### Server public key mismatch
- Server generates new keypair each restart
- Update `-bc-pubkey` or omit it during testing

### No backconnect clients available
- Client hasn't connected yet
- Check client logs for connection errors

### Verbose logging
Use `-v` on both client and server to see detailed handshake and session info.
