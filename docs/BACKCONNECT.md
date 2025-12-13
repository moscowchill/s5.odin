# Backconnect SOCKS5 Proxy

A reverse-tunnel SOCKS5 proxy where the client connects OUT to a server, then receives and executes SOCKS5 requests through an encrypted, multiplexed tunnel.

## Architecture

```
┌─────────────────┐      ┌─────────────────────┐      ┌──────────────────┐
│   SOCKS5 User   │─────▶│  Backconnect Server │◀─────│ Backconnect Client│
│  (curl, browser)│      │                     │      │  (behind NAT/FW) │
└─────────────────┘      └─────────────────────┘      └──────────────────┘
     :6000 (Client A)         :8443 BC listener         connects to :8443
     :6001 (Client B)         :6000-8000 per-client     executes requests
```

**Use case:** Run a SOCKS5 proxy on a machine behind NAT/firewall without opening inbound ports.

## Quick Start

### 1. Generate a Master PSK

```bash
# Generate a random 32-byte (64 hex char) PSK - keep this secret on server
openssl rand -hex 32
# Example output: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### 2. Start the Server

```bash
# On your public-facing server
./backconnect_server -bc-psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Output:
# Server public key: <64-hex-chars>
#
# ========================================
#   OTP (valid for 3h 59m): a1b2c3d4
# ========================================
#
# Backconnect listener on 0.0.0.0:8443
```

### 3. Start the Client

```bash
# On the machine behind NAT - use the OTP displayed by server
./s5proxy -backconnect \
  -bc-server your-server.com:8443 \
  -bc-otp <otp-from-server>
```

### 4. Use the Proxy

```bash
# Connect through the client's dedicated port (displayed on connect)
curl --socks5 your-server.com:6000 http://ifconfig.me
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
backconnect_server -bc-psk <hex> [options]

Backconnect:
  -bc-addr <addr>      Listen address for clients (default: 0.0.0.0:8443)
  -bc-psk <hex>        Master PSK, 64 hex chars (enables OTP mode)
  -no-otp              Disable OTP mode, use raw PSK for authentication

SOCKS5 Auth (for per-client ports):
  -socks-auth          Require authentication on SOCKS5 ports
  -socks-user <user>   Username (default: admin)
  -socks-pass <pass>   Password (default: password)

General:
  -v, -verbose         Enable verbose logging
  -print-pubkey        Print server public key and exit
  -h, -help            Show help
```

Each connected client gets a dedicated SOCKS5 port (6000-8000 range).

## OTP Authentication

By default, the server operates in **OTP mode** for improved operational security:

- Server generates a time-based OTP from the master PSK
- OTP rotates every **4 hours**
- OTP is displayed on server startup and when it rotates
- Clients authenticate using `-bc-otp` with the displayed OTP
- **The master PSK never needs to be shared with clients**

### Why OTP Mode?

| Scenario | Raw PSK Mode | OTP Mode |
|----------|--------------|----------|
| Client binary captured | Attacker gets master secret | Attacker gets expired OTP |
| PSK leaked | All clients compromised | Only current window affected |
| Key rotation | Must update all clients | Just wait 4 hours |

### Disabling OTP Mode

For backwards compatibility or testing, you can disable OTP mode:

```bash
# Server: use raw PSK directly
./backconnect_server -bc-psk <psk> -no-otp

# Client: use -bc-psk instead of -bc-otp
./s5proxy -backconnect -bc-server server:8443 -bc-psk <same-psk>
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
  -bc-otp <hex>        One-time password from server (64 hex chars) - recommended
  -bc-psk <hex>        Pre-shared key (only for -no-otp servers)

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

### Encrypted Handshake

The entire handshake is encrypted to prevent protocol fingerprinting. Only the random nonce is visible to observers - all other data (including public keys) is hidden.

**Handshake encryption key derivation:**
```
handshake_key = SHA256(expanded_otp || nonce || "handshake")

Where expanded_otp = SHA256(short_otp) in OTP mode, or master_psk in raw PSK mode
```

**Wire format:**
```
HANDSHAKE_INIT (server → client):
┌────────────────┬────────────┬───────────────────────────────────────────┐
│ Length (2 BE)  │ Nonce (24) │ Encrypted(type + session_id + server_pubkey) + Tag (16) │
└────────────────┴────────────┴───────────────────────────────────────────┘
Total: 2 + 24 + 37 + 16 = 79 bytes

HANDSHAKE_RESP (client → server):
┌────────────────┬───────────────────────────────────────────────────────────────┐
│ Length (2 BE)  │ Encrypted(type + session_id + client_pubkey + encrypted_psk) + Tag (16) │
└────────────────┴───────────────────────────────────────────────────────────────┘
Total: 2 + 85 + 16 = 103 bytes (uses nonce XOR 0xFF for different nonce)

HANDSHAKE_ACK (server → client):
  Standard encrypted message format (uses session keys)
```

**Sequence diagram:**
```
Client                              Server
   |                                   |
   |◀──────── TCP Connect ─────────────|
   |                                   |
   |◀─────── HANDSHAKE_INIT ───────────|  [nonce] + encrypted(server_pubkey)
   |                                   |
   |──────── HANDSHAKE_RESP ──────────▶|  encrypted(client_pubkey + encrypted_psk)
   |                                   |
   |◀─────── HANDSHAKE_ACK ────────────|  status (encrypted with session keys)
   |                                   |
   |═══════ Encrypted Channel ═════════|
```

**Security benefit:** Without the PSK, an observer cannot:
- Identify this as a backconnect proxy (no recognizable magic bytes)
- See the public keys being exchanged
- Determine message types or structure
- Distinguish this from random data

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
| PORT_ASSIGNED | 0x08 | S→C | Server assigns dedicated SOCKS5 port |
| SESSION_NEW | 0x10 | S→C | New connection request |
| SESSION_READY | 0x11 | C→S | Connection established |
| SESSION_DATA | 0x12 | Both | Tunnel data |
| SESSION_CLOSE | 0x13 | Both | Close session |

### Session Multiplexing

Multiple SOCKS5 connections are multiplexed over a single encrypted tunnel using 32-bit session IDs.

## Security Considerations

1. **Use OTP mode:** Keep master PSK secret on server, share only OTPs with clients
2. **Use strong PSKs:** Generate with `openssl rand -hex 32`
3. **Pin server keys:** Always use `-bc-pubkey` in production
4. **Restrict SOCKS5 access:** Bind to localhost or use `-socks-auth`
5. **Firewall the BC port:** Only allow expected client IPs on port 8443

### Protocol Fingerprinting Resistance

The encrypted handshake prevents passive observers from identifying this as a backconnect proxy:

| Before (Plaintext Handshake) | After (Encrypted Handshake) |
|------------------------------|----------------------------|
| Public keys visible (32+32 bytes) | All encrypted, only random nonce visible |
| Message types identifiable | Encrypted, indistinguishable |
| Fixed message sizes reveal protocol | Sizes include auth tag, less predictable |
| Easy to fingerprint and block | Looks like random encrypted data |

## Multiple Clients

The server supports multiple simultaneous backconnect clients. **Each client gets a dedicated SOCKS5 port** (range 6000-8000), allowing you to target specific client networks.

```bash
# Server accepts multiple clients
./backconnect_server -bc-psk <shared-psk> -v

# Client 1 connects and gets port 6000
./s5proxy -backconnect -bc-server server:8443 -bc-psk <shared-psk>
# Output: SOCKS5 Proxy Port Assigned: 6000

# Client 2 connects and gets port 6001
./s5proxy -backconnect -bc-server server:8443 -bc-psk <shared-psk>
# Output: SOCKS5 Proxy Port Assigned: 6001

# Route through specific client networks:
curl --socks5 server:6000 http://target  # Through Client 1's network
curl --socks5 server:6001 http://target  # Through Client 2's network
```

### Port Assignment

- Port range: **6000-8000** (2000 concurrent clients max)
- Ports are allocated sequentially from the lowest available
- When a client disconnects, its port is freed for reuse
- Each client gets a dedicated SOCKS5 port for targeted routing

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
