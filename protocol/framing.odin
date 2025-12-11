/*
   Wire protocol framing for backconnect SOCKS5 proxy

   Message format (after encryption):
   +----------------+----------------+-------------------+-------------------+
   | Length (2 BE)  | Type (1)       | Session ID (4 BE) | Payload (N)       |
   +----------------+----------------+-------------------+-------------------+

   On the wire (encrypted):
   +----------------+------------------------------------------+
   | Length (2 BE)  | Encrypted(counter + msg + tag)           |
   +----------------+------------------------------------------+
*/

package protocol

import "core:net"
import "core:mem"

// Message header size (type + session_id)
HEADER_SIZE :: 5  // 1 byte type + 4 bytes session_id

// Maximum message size
MAX_MSG_SIZE :: 65535

// Message types
Message_Type :: enum u8 {
    // Control plane (session_id = 0)
    HANDSHAKE_INIT = 0x01,
    HANDSHAKE_RESP = 0x02,
    HANDSHAKE_ACK  = 0x03,
    PING           = 0x04,
    PONG           = 0x05,
    DISCONNECT     = 0x06,
    ERROR          = 0x07,

    // Data plane (session_id > 0)
    SESSION_NEW    = 0x10,
    SESSION_READY  = 0x11,
    SESSION_DATA   = 0x12,
    SESSION_CLOSE  = 0x13,
}

// Session ID for control plane messages
SESSION_ID_CONTROL :: 0

// Encode a message into wire format (unencrypted, for use before encryption)
// Returns: type (1) || session_id (4 BE) || payload
frame_encode :: proc(msg_type: Message_Type, session_id: u32, payload: []u8, allocator := context.allocator) -> []u8 {
    msg_len := HEADER_SIZE + len(payload)
    msg := make([]u8, msg_len, allocator)

    // Type
    msg[0] = u8(msg_type)

    // Session ID (big-endian)
    msg[1] = u8(session_id >> 24)
    msg[2] = u8(session_id >> 16)
    msg[3] = u8(session_id >> 8)
    msg[4] = u8(session_id)

    // Payload
    if len(payload) > 0 {
        copy(msg[HEADER_SIZE:], payload)
    }

    return msg
}

// Decode a message from wire format
// Returns message type, session_id, payload slice (points into input data)
frame_decode :: proc(data: []u8) -> (msg_type: Message_Type, session_id: u32, payload: []u8, ok: bool) {
    if len(data) < HEADER_SIZE {
        return .HANDSHAKE_INIT, 0, nil, false
    }

    msg_type = Message_Type(data[0])

    session_id = u32(data[1]) << 24 |
                 u32(data[2]) << 16 |
                 u32(data[3]) << 8 |
                 u32(data[4])

    payload = data[HEADER_SIZE:]

    return msg_type, session_id, payload, true
}

// Read exactly n bytes from socket
read_exact :: proc(socket: net.TCP_Socket, buf: []u8) -> bool {
    total_read := 0
    for total_read < len(buf) {
        n, err := net.recv_tcp(socket, buf[total_read:])
        if err != nil || n == 0 {
            return false
        }
        total_read += n
    }
    return true
}

// Write all bytes to socket
write_all :: proc(socket: net.TCP_Socket, data: []u8) -> bool {
    total_written := 0
    for total_written < len(data) {
        n, err := net.send_tcp(socket, data[total_written:])
        if err != nil {
            return false
        }
        total_written += n
    }
    return true
}

// Read a length-prefixed message from socket (plaintext, for handshake)
// Returns the message data (caller must free)
frame_read_raw :: proc(socket: net.TCP_Socket, allocator := context.allocator) -> ([]u8, bool) {
    // Read 2-byte length prefix (big-endian)
    len_buf: [2]u8
    if !read_exact(socket, len_buf[:]) {
        return nil, false
    }

    msg_len := int(len_buf[0]) << 8 | int(len_buf[1])

    if msg_len == 0 || msg_len > MAX_MSG_SIZE {
        return nil, false
    }

    // Read message body
    msg := make([]u8, msg_len, allocator)
    if !read_exact(socket, msg) {
        delete(msg)
        return nil, false
    }

    return msg, true
}

// Write a length-prefixed message to socket (plaintext, for handshake)
frame_write_raw :: proc(socket: net.TCP_Socket, data: []u8) -> bool {
    if len(data) > MAX_MSG_SIZE {
        return false
    }

    // Write 2-byte length prefix (big-endian)
    len_buf: [2]u8
    len_buf[0] = u8(len(data) >> 8)
    len_buf[1] = u8(len(data))

    if !write_all(socket, len_buf[:]) {
        return false
    }

    return write_all(socket, data)
}

// Read an encrypted message from socket
// Returns decrypted message data (caller must free)
frame_read_encrypted :: proc(socket: net.TCP_Socket, crypto_ctx: ^Crypto_Context, allocator := context.allocator) -> ([]u8, bool) {
    // Read 2-byte length prefix
    len_buf: [2]u8
    if !read_exact(socket, len_buf[:]) {
        return nil, false
    }

    msg_len := int(len_buf[0]) << 8 | int(len_buf[1])

    if msg_len == 0 || msg_len > MAX_MSG_SIZE {
        return nil, false
    }

    // Read encrypted data
    encrypted := make([]u8, msg_len)
    defer delete(encrypted)

    if !read_exact(socket, encrypted) {
        return nil, false
    }

    // Decrypt
    return crypto_decrypt(crypto_ctx, encrypted, allocator)
}

// Write an encrypted message to socket
frame_write_encrypted :: proc(socket: net.TCP_Socket, crypto_ctx: ^Crypto_Context, data: []u8) -> bool {
    // Encrypt
    encrypted, ok := crypto_encrypt(crypto_ctx, data)
    if !ok {
        return false
    }
    defer delete(encrypted)

    if len(encrypted) > MAX_MSG_SIZE {
        return false
    }

    // Write 2-byte length prefix
    len_buf: [2]u8
    len_buf[0] = u8(len(encrypted) >> 8)
    len_buf[1] = u8(len(encrypted))

    if !write_all(socket, len_buf[:]) {
        return false
    }

    return write_all(socket, encrypted)
}

// Send a framed message (encrypts, length-prefixes, and sends)
send_message :: proc(socket: net.TCP_Socket, crypto_ctx: ^Crypto_Context,
                     msg_type: Message_Type, session_id: u32, payload: []u8) -> bool {
    // Encode message
    msg := frame_encode(msg_type, session_id, payload)
    defer delete(msg)

    // Encrypt and send
    return frame_write_encrypted(socket, crypto_ctx, msg)
}

// Receive a framed message (receives, decrypts, and decodes)
recv_message :: proc(socket: net.TCP_Socket, crypto_ctx: ^Crypto_Context,
                     allocator := context.allocator) -> (msg_type: Message_Type, session_id: u32, payload: []u8, ok: bool) {
    // Read and decrypt
    data, read_ok := frame_read_encrypted(socket, crypto_ctx, allocator)
    if !read_ok {
        return .HANDSHAKE_INIT, 0, nil, false
    }

    // Decode
    decoded_type, decoded_session_id, _, decode_ok := frame_decode(data)
    if !decode_ok {
        delete(data)
        return .HANDSHAKE_INIT, 0, nil, false
    }

    // Return full data - caller uses get_payload() to extract payload
    return decoded_type, decoded_session_id, data, true
}

// Helper: get payload from received message data
// (The data returned by recv_message contains header + payload)
get_payload :: proc(msg_data: []u8) -> []u8 {
    if len(msg_data) <= HEADER_SIZE {
        return nil
    }
    return msg_data[HEADER_SIZE:]
}

// Handshake message builders

// HANDSHAKE_INIT: server_pubkey (32) || nonce (24)
build_handshake_init :: proc(server_pubkey: [PUBKEY_SIZE]u8, nonce: [NONCE_SIZE]u8, allocator := context.allocator) -> []u8 {
    data := make([]u8, PUBKEY_SIZE + NONCE_SIZE, allocator)
    for i in 0..<PUBKEY_SIZE {
        data[i] = server_pubkey[i]
    }
    for i in 0..<NONCE_SIZE {
        data[PUBKEY_SIZE + i] = nonce[i]
    }
    return data
}

// Parse HANDSHAKE_INIT
parse_handshake_init :: proc(data: []u8) -> (server_pubkey: [PUBKEY_SIZE]u8, nonce: [NONCE_SIZE]u8, ok: bool) {
    if len(data) != PUBKEY_SIZE + NONCE_SIZE {
        return {}, {}, false
    }
    for i in 0..<PUBKEY_SIZE {
        server_pubkey[i] = data[i]
    }
    for i in 0..<NONCE_SIZE {
        nonce[i] = data[PUBKEY_SIZE + i]
    }
    return server_pubkey, nonce, true
}

// HANDSHAKE_RESP: client_pubkey (32) || encrypted_psk (48)
build_handshake_resp :: proc(client_pubkey: [PUBKEY_SIZE]u8, encrypted_psk: []u8, allocator := context.allocator) -> []u8 {
    data := make([]u8, PUBKEY_SIZE + len(encrypted_psk), allocator)
    for i in 0..<PUBKEY_SIZE {
        data[i] = client_pubkey[i]
    }
    copy(data[PUBKEY_SIZE:], encrypted_psk)
    return data
}

// Parse HANDSHAKE_RESP
parse_handshake_resp :: proc(data: []u8) -> (client_pubkey: [PUBKEY_SIZE]u8, encrypted_psk: []u8, ok: bool) {
    expected_len := PUBKEY_SIZE + PSK_SIZE + TAG_SIZE  // 32 + 32 + 16 = 80
    if len(data) != expected_len {
        return {}, nil, false
    }
    for i in 0..<PUBKEY_SIZE {
        client_pubkey[i] = data[i]
    }
    encrypted_psk = data[PUBKEY_SIZE:]
    return client_pubkey, encrypted_psk, true
}

// HANDSHAKE_ACK: status (1)
Handshake_Status :: enum u8 {
    SUCCESS   = 0x00,
    AUTH_FAIL = 0x01,
    ERROR     = 0x02,
}

build_handshake_ack :: proc(status: Handshake_Status, allocator := context.allocator) -> []u8 {
    data := make([]u8, 1, allocator)
    data[0] = u8(status)
    return data
}

parse_handshake_ack :: proc(data: []u8) -> (status: Handshake_Status, ok: bool) {
    if len(data) != 1 {
        return .ERROR, false
    }
    return Handshake_Status(data[0]), true
}

// SESSION_NEW: atyp (1) || addr_len (1) || addr (N) || port (2 BE)
Address_Type :: enum u8 {
    IPV4   = 0x01,
    DOMAIN = 0x03,
    IPV6   = 0x04,
}

build_session_new :: proc(atyp: Address_Type, addr: []u8, port: u16, allocator := context.allocator) -> []u8 {
    data := make([]u8, 1 + 1 + len(addr) + 2, allocator)
    data[0] = u8(atyp)
    data[1] = u8(len(addr))
    copy(data[2:2+len(addr)], addr)
    data[2+len(addr)] = u8(port >> 8)
    data[2+len(addr)+1] = u8(port)
    return data
}

parse_session_new :: proc(data: []u8) -> (atyp: Address_Type, addr: []u8, port: u16, ok: bool) {
    if len(data) < 4 {  // min: atyp + len + 0-byte addr + port
        return .IPV4, nil, 0, false
    }
    atyp = Address_Type(data[0])
    addr_len := int(data[1])
    if len(data) != 2 + addr_len + 2 {
        return .IPV4, nil, 0, false
    }
    addr = data[2:2+addr_len]
    port = u16(data[2+addr_len]) << 8 | u16(data[2+addr_len+1])
    return atyp, addr, port, true
}

// SESSION_READY: status (1)
Session_Ready_Status :: enum u8 {
    CONNECTED           = 0x00,
    CONNECTION_REFUSED  = 0x01,
    HOST_UNREACHABLE    = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    TIMEOUT             = 0x04,
}

build_session_ready :: proc(status: Session_Ready_Status, allocator := context.allocator) -> []u8 {
    data := make([]u8, 1, allocator)
    data[0] = u8(status)
    return data
}

parse_session_ready :: proc(data: []u8) -> (status: Session_Ready_Status, ok: bool) {
    if len(data) != 1 {
        return .CONNECTION_REFUSED, false
    }
    return Session_Ready_Status(data[0]), true
}

// SESSION_CLOSE: reason (1)
Session_Close_Reason :: enum u8 {
    NORMAL  = 0x00,
    ERROR   = 0x01,
    TIMEOUT = 0x02,
}

build_session_close :: proc(reason: Session_Close_Reason, allocator := context.allocator) -> []u8 {
    data := make([]u8, 1, allocator)
    data[0] = u8(reason)
    return data
}

parse_session_close :: proc(data: []u8) -> (reason: Session_Close_Reason, ok: bool) {
    if len(data) != 1 {
        return .ERROR, false
    }
    return Session_Close_Reason(data[0]), true
}

// PING/PONG: timestamp (8 BE)
build_ping_pong :: proc(timestamp: u64, allocator := context.allocator) -> []u8 {
    data := make([]u8, 8, allocator)
    data[0] = u8(timestamp >> 56)
    data[1] = u8(timestamp >> 48)
    data[2] = u8(timestamp >> 40)
    data[3] = u8(timestamp >> 32)
    data[4] = u8(timestamp >> 24)
    data[5] = u8(timestamp >> 16)
    data[6] = u8(timestamp >> 8)
    data[7] = u8(timestamp)
    return data
}

parse_ping_pong :: proc(data: []u8) -> (timestamp: u64, ok: bool) {
    if len(data) != 8 {
        return 0, false
    }
    timestamp = u64(data[0]) << 56 |
                u64(data[1]) << 48 |
                u64(data[2]) << 40 |
                u64(data[3]) << 32 |
                u64(data[4]) << 24 |
                u64(data[5]) << 16 |
                u64(data[6]) << 8 |
                u64(data[7])
    return timestamp, true
}
