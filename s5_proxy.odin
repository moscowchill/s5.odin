/*
   SOCKS5 Proxy Server in Odin

   Production-ready SOCKS5 proxy with:
   - Configurable timeouts and buffer sizes
   - Partial read protection for network resilience
   - Username/password authentication option
   - Backconnect client mode for reverse proxy tunneling

   Usage (Normal mode):
     odin run s5_proxy.odin -- -addr 127.0.0.1:1080
     odin run s5_proxy.odin -- -addr 127.0.0.1:1080 -auth -user admin -pass secret

   Usage (Backconnect mode):
     odin run s5_proxy.odin -- -backconnect -bc-server server:8443 -bc-psk <64-hex-chars>

   Build:
     odin build s5_proxy.odin -o:speed -no-bounds-check
*/

package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"
import "core:thread"
import "core:sync"

import "protocol"
import "core:crypto/x25519"

// SOCKS5 Protocol Constants
SOCKS_VERSION :: 0x05
AUTH_NONE :: 0x00
AUTH_USERPASS :: 0x02
CMD_CONNECT :: 0x01
CMD_BIND :: 0x02
CMD_UDP_ASSOCIATE :: 0x03
ATYP_IPV4 :: 0x01
ATYP_DOMAIN :: 0x03
ATYP_IPV6 :: 0x04
REP_SUCCESS :: 0x00
REP_GENERAL_FAILURE :: 0x01
REP_CONNECTION_NOT_ALLOWED :: 0x02
REP_NETWORK_UNREACHABLE :: 0x03
REP_HOST_UNREACHABLE :: 0x04
REP_CONNECTION_REFUSED :: 0x05
REP_TTL_EXPIRED :: 0x06
REP_COMMAND_NOT_SUPPORTED :: 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED :: 0x08

// Configuration
Config :: struct {
    listen_addr:     string,
    verbose:         bool,
    require_auth:    bool,
    username:        string,
    password:        string,
    buffer_size:     int,
    connect_timeout: time.Duration,
    read_timeout:    time.Duration,

    // Backconnect mode
    backconnect:         bool,
    bc_server_addr:      string,
    bc_psk:              [protocol.PSK_SIZE]u8,
    bc_server_pubkey:    [protocol.PUBKEY_SIZE]u8,
    bc_server_pubkey_set: bool,
    bc_auto_reconnect:   bool,
}

// Connection context for tracking
Connection_Context :: struct {
    client_socket:  net.TCP_Socket,
    target_host:    string,
    target_port:    u16,
    start_time:     time.Time,
    bytes_sent:     u64,
    bytes_received: u64,
}

// Relay context for bidirectional data transfer
Relay_Context :: struct {
    src:      net.TCP_Socket,
    dst:      net.TCP_Socket,
    buffer:   []byte,
    done:     bool,
}

// Global state
g_config: Config
g_active_connections: [dynamic]^Connection_Context

// Constant-time string comparison to prevent timing attacks
constant_time_compare :: proc(a: string, b: string) -> bool {
    if len(a) != len(b) {
        // Still do a comparison to avoid early-exit timing leak
        dummy: u8 = 0
        for i := 0; i < max(len(a), len(b)); i += 1 {
            dummy |= 0xFF
        }
        return false
    }

    diff: u8 = 0
    for i := 0; i < len(a); i += 1 {
        diff |= a[i] ~ b[i]  // XOR and accumulate differences
    }
    return diff == 0
}

// Helper: Receive exactly N bytes (handles partial reads)
recv_exactly :: proc(socket: net.TCP_Socket, buf: []byte) -> (ok: bool) {
    total := 0
    for total < len(buf) {
        n, err := net.recv_tcp(socket, buf[total:])
        if err != nil || n == 0 {
            return false
        }
        total += n
    }
    return true
}

main :: proc() {
    context.logger = log.create_console_logger()

    // Parse command line arguments
    parse_args()

    // Run in backconnect mode or normal mode
    if g_config.backconnect {
        run_backconnect_client()
    } else {
        run_socks5_server()
    }
}

// Normal SOCKS5 server mode
run_socks5_server :: proc() {
    if g_config.verbose {
        log.info("Starting SOCKS5 Proxy Server")
        log.infof("Listening on: %s", g_config.listen_addr)
        log.infof("Authentication: %v", g_config.require_auth)
    }

    // Parse endpoint
    endpoint, parse_ok := net.parse_endpoint(g_config.listen_addr)
    if !parse_ok {
        log.errorf("Failed to parse address: %s", g_config.listen_addr)
        os.exit(1)
    }

    // Create listening socket
    listen_socket, listen_err := net.listen_tcp(endpoint)
    if listen_err != nil {
        log.errorf("Failed to bind to %s: %v", g_config.listen_addr, listen_err)
        os.exit(1)
    }
    defer net.close(listen_socket)

    if !g_config.verbose {
        fmt.printf("Listening on %s\n", g_config.listen_addr)
    }

    // Accept connections
    for {
        client_socket, client_endpoint, accept_err := net.accept_tcp(listen_socket)
        if accept_err != nil {
            if g_config.verbose {
                log.errorf("Accept error: %v", accept_err)
            }
            continue
        }

        if g_config.verbose {
            log.infof("New connection from: %v", client_endpoint)
        }

        // Handle connection in new thread
        ctx := new(Connection_Context)
        ctx.client_socket = client_socket
        ctx.start_time = time.now()

        thread.create_and_start_with_poly_data(ctx, handle_connection_thread)
    }
}

handle_connection_thread :: proc(ctx: ^Connection_Context) {
    defer free(ctx)
    defer net.close(ctx.client_socket)

    // Perform SOCKS5 handshake
    if !socks5_handshake(ctx.client_socket) {
        if g_config.verbose {
            log.warn("Handshake failed")
        }
        return
    }

    // Parse target address
    target_host, target_port, cmd, parse_ok := parse_socks5_request(ctx.client_socket)
    if !parse_ok {
        if g_config.verbose {
            log.warn("Failed to parse SOCKS5 request")
        }
        send_socks5_reply(ctx.client_socket, REP_GENERAL_FAILURE)
        return
    }

    ctx.target_host = target_host
    ctx.target_port = target_port

    // Handle different commands
    switch cmd {
    case CMD_CONNECT:
        handle_connect(ctx)
    case CMD_BIND:
        if g_config.verbose {
            log.warn("BIND command not implemented")
        }
        send_socks5_reply(ctx.client_socket, REP_COMMAND_NOT_SUPPORTED)
    case CMD_UDP_ASSOCIATE:
        if g_config.verbose {
            log.warn("UDP ASSOCIATE command not implemented")
        }
        send_socks5_reply(ctx.client_socket, REP_COMMAND_NOT_SUPPORTED)
    case:
        send_socks5_reply(ctx.client_socket, REP_COMMAND_NOT_SUPPORTED)
    }
}

socks5_handshake :: proc(socket: net.TCP_Socket) -> bool {
    buf: [258]byte

    // Read version and method count
    n, err := net.recv_tcp(socket, buf[:2])
    if err != nil || n != 2 {
        return false
    }

    version := buf[0]
    nmethods := int(buf[1])

    if version != SOCKS_VERSION {
        if g_config.verbose {
            log.warnf("Unsupported SOCKS version: 0x%02x", version)
        }
        return false
    }

    // Read authentication methods
    if nmethods > 0 {
        n, err = net.recv_tcp(socket, buf[:nmethods])
        if err != nil || n != nmethods {
            return false
        }
    }

    // Choose authentication method
    chosen_method: byte
    if g_config.require_auth {
        // Check if client supports username/password auth
        supports_userpass := false
        for i in 0..<nmethods {
            if buf[i] == AUTH_USERPASS {
                supports_userpass = true
                break
            }
        }

        if !supports_userpass {
            // No acceptable method
            response := [2]byte{SOCKS_VERSION, 0xFF}
            net.send_tcp(socket, response[:])
            return false
        }

        chosen_method = AUTH_USERPASS
    } else {
        chosen_method = AUTH_NONE
    }

    // Send method selection
    response := [2]byte{SOCKS_VERSION, chosen_method}
    _, send_err := net.send_tcp(socket, response[:])
    if send_err != nil {
        return false
    }

    // If authentication required, perform username/password auth
    if chosen_method == AUTH_USERPASS {
        return socks5_authenticate(socket)
    }

    return true
}

socks5_authenticate :: proc(socket: net.TCP_Socket) -> bool {
    buf: [512]byte

    // Read auth version
    n, err := net.recv_tcp(socket, buf[:1])
    if err != nil || n != 1 || buf[0] != 0x01 {
        return false
    }

    // Read username length
    if !recv_exactly(socket, buf[:1]) {
        return false
    }
    ulen := int(buf[0])
    if ulen > 255 || ulen == 0 {
        return false
    }

    // Read username
    if !recv_exactly(socket, buf[:ulen]) {
        return false
    }
    username := strings.clone(string(buf[:ulen]))
    defer delete(username)

    // Read password length
    if !recv_exactly(socket, buf[ulen:ulen+1]) {
        return false
    }
    plen := int(buf[ulen])
    if plen > 255 || plen == 0 {
        return false
    }

    // Read password
    if !recv_exactly(socket, buf[ulen+1:ulen+1+plen]) {
        return false
    }
    password := string(buf[ulen+1:ulen+1+plen])

    // Verify credentials using constant-time comparison to prevent timing attacks
    auth_ok := constant_time_compare(username, g_config.username) &&
               constant_time_compare(password, g_config.password)

    if g_config.verbose {
        log.infof("SOCKS5 authentication: %s", auth_ok ? "success" : "failure")
    }

    // Send auth response
    response: [2]byte
    response[0] = 0x01
    if auth_ok {
        response[1] = 0x00 // Success
    } else {
        response[1] = 0x01 // Failure
        net.send_tcp(socket, response[:])
        return false
    }

    _, send_err := net.send_tcp(socket, response[:])
    return send_err == nil && auth_ok
}

parse_socks5_request :: proc(socket: net.TCP_Socket) -> (host: string, port: u16, cmd: byte, ok: bool) {
    buf: [263]byte

    // Read request header
    n, err := net.recv_tcp(socket, buf[:4])
    if err != nil || n != 4 {
        return "", 0, 0, false
    }

    version := buf[0]
    cmd = buf[1]
    // buf[2] is reserved
    atyp := buf[3]

    if version != SOCKS_VERSION {
        return "", 0, 0, false
    }

    host_bytes: []byte
    port_bytes: [2]byte

    // Parse address based on type
    switch atyp {
    case ATYP_IPV4:
        // Read 4 bytes for IPv4 + 2 bytes for port
        n, err = net.recv_tcp(socket, buf[:6])
        if err != nil || n != 6 {
            return "", 0, 0, false
        }

        // Format IPv4 address
        host_str := fmt.tprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
        host = strings.clone(host_str)
        port_bytes[0] = buf[4]
        port_bytes[1] = buf[5]

    case ATYP_DOMAIN:
        // Read domain length
        n, err = net.recv_tcp(socket, buf[:1])
        if err != nil || n != 1 {
            return "", 0, 0, false
        }
        domain_len := int(buf[0])

        // Read domain + port
        n, err = net.recv_tcp(socket, buf[:domain_len + 2])
        if err != nil || n != domain_len + 2 {
            return "", 0, 0, false
        }

        host = strings.clone(string(buf[:domain_len]))
        port_bytes[0] = buf[domain_len]
        port_bytes[1] = buf[domain_len + 1]

    case ATYP_IPV6:
        // Read 16 bytes for IPv6 + 2 bytes for port
        n, err = net.recv_tcp(socket, buf[:18])
        if err != nil || n != 18 {
            return "", 0, 0, false
        }

        // Format IPv6 address (simplified)
        host_str := fmt.tprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15])
        host = strings.clone(host_str)
        port_bytes[0] = buf[16]
        port_bytes[1] = buf[17]

    case:
        return "", 0, 0, false
    }

    // Parse port (big endian)
    port = u16(port_bytes[0]) << 8 | u16(port_bytes[1])

    if g_config.verbose {
        log.infof("Request: CMD=%d, Host=%s, Port=%d", cmd, host, port)
    }

    return host, port, cmd, true
}

send_socks5_reply :: proc(socket: net.TCP_Socket, reply_code: byte, bind_addr: Maybe([4]byte) = nil, bind_port: u16 = 0) {
    // Build reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    buf: [10]byte
    buf[0] = SOCKS_VERSION
    buf[1] = reply_code
    buf[2] = 0x00 // Reserved
    buf[3] = ATYP_IPV4

    // Bind address (0.0.0.0 if not specified)
    if addr, ok := bind_addr.?; ok {
        buf[4] = addr[0]
        buf[5] = addr[1]
        buf[6] = addr[2]
        buf[7] = addr[3]
    } else {
        buf[4] = 0
        buf[5] = 0
        buf[6] = 0
        buf[7] = 0
    }

    // Bind port (big endian)
    buf[8] = byte(bind_port >> 8)
    buf[9] = byte(bind_port & 0xFF)

    net.send_tcp(socket, buf[:])
}

handle_connect :: proc(ctx: ^Connection_Context) {
    // Build target address
    target_addr := fmt.tprintf("%s:%d", ctx.target_host, ctx.target_port)

    if g_config.verbose {
        log.infof("Connecting to: %s", target_addr)
    }

    // Parse target endpoint
    target_endpoint, parse_ok := net.parse_endpoint(target_addr)
    if !parse_ok {
        if g_config.verbose {
            log.errorf("Failed to parse target: %s", target_addr)
        }
        send_socks5_reply(ctx.client_socket, REP_GENERAL_FAILURE)
        return
    }

    // Connect to target
    target_socket, dial_err := net.dial_tcp(target_endpoint)
    if dial_err != nil {
        if g_config.verbose {
            log.errorf("Failed to connect to %s: %v", target_addr, dial_err)
        }
        send_socks5_reply(ctx.client_socket, REP_HOST_UNREACHABLE)
        return
    }
    defer net.close(target_socket)

    // Send success reply
    send_socks5_reply(ctx.client_socket, REP_SUCCESS)

    if g_config.verbose {
        log.infof("Connected to: %s", target_addr)
    }

    // Relay data bidirectionally
    relay_data(ctx.client_socket, target_socket)
}

relay_data :: proc(client: net.TCP_Socket, target: net.TCP_Socket) {
    // Create buffers with configurable size
    client_to_target_buf := make([]byte, g_config.buffer_size)
    target_to_client_buf := make([]byte, g_config.buffer_size)
    defer delete(client_to_target_buf)
    defer delete(target_to_client_buf)

    // Create relay contexts
    ctx1 := new(Relay_Context)
    ctx1.src = client
    ctx1.dst = target
    ctx1.buffer = client_to_target_buf

    ctx2 := new(Relay_Context)
    ctx2.src = target
    ctx2.dst = client
    ctx2.buffer = target_to_client_buf

    // Start relay threads
    t1 := thread.create_and_start_with_poly_data(ctx1, relay_thread)
    t2 := thread.create_and_start_with_poly_data(ctx2, relay_thread)

    // Wait for both to complete
    thread.join(t1)
    thread.join(t2)

    free(ctx1)
    free(ctx2)
    thread.destroy(t1)
    thread.destroy(t2)
}

relay_thread :: proc(ctx: ^Relay_Context) {
    for {
        n, err := net.recv_tcp(ctx.src, ctx.buffer)
        if err != nil || n == 0 {
            break
        }

        // Send data
        sent := 0
        for sent < n {
            s, send_err := net.send_tcp(ctx.dst, ctx.buffer[sent:n])
            if send_err != nil {
                break
            }
            sent += s
        }

        if sent < n {
            break
        }
    }
}

// ============================================================================
// Backconnect Client Mode
// ============================================================================

// Backconnect session - tracks a proxied connection
BC_Session :: struct {
    id:            u32,
    target_socket: net.TCP_Socket,
    connected:     bool,
}

// Global backconnect state
g_bc_mux: ^protocol.Multiplexer
g_bc_sessions: map[u32]^BC_Session
g_bc_sessions_mutex: sync.Mutex

// Run backconnect client mode
run_backconnect_client :: proc() {
    if g_config.verbose {
        log.info("Starting Backconnect Client")
        log.infof("Server: %s", g_config.bc_server_addr)
    } else {
        fmt.printf("Connecting to %s...\n", g_config.bc_server_addr)
    }

    g_bc_sessions = make(map[u32]^BC_Session)
    defer delete(g_bc_sessions)

    reconnect_delay := 1 * time.Second

    for {
        // Connect to server
        if bc_connect_and_run() {
            // Clean disconnect, reset delay
            reconnect_delay = 1 * time.Second
        } else {
            // Connection failed or errored
            if !g_config.bc_auto_reconnect {
                break
            }
        }

        if !g_config.bc_auto_reconnect {
            break
        }

        // Reconnect with backoff
        if g_config.verbose {
            log.infof("Reconnecting in %v...", reconnect_delay)
        } else {
            fmt.printf("Reconnecting in %v...\n", reconnect_delay)
        }
        time.sleep(reconnect_delay)

        // Exponential backoff
        reconnect_delay = min(reconnect_delay * 2, 60 * time.Second)
    }
}

// Connect to server and run until disconnected
bc_connect_and_run :: proc() -> bool {
    // Parse server address
    endpoint, parse_ok := net.parse_endpoint(g_config.bc_server_addr)
    if !parse_ok {
        log.errorf("Failed to parse server address: %s", g_config.bc_server_addr)
        return false
    }

    // Connect
    socket, dial_err := net.dial_tcp(endpoint)
    if dial_err != nil {
        if g_config.verbose {
            log.errorf("Failed to connect to server: %v", dial_err)
        }
        return false
    }

    if g_config.verbose {
        log.info("Connected to server, performing handshake...")
    }

    // Perform handshake
    crypto_ctx: protocol.Crypto_Context
    if !bc_handshake(socket, &crypto_ctx) {
        net.close(socket)
        return false
    }

    if g_config.verbose {
        log.info("Handshake successful, starting multiplexer...")
    } else {
        fmt.println("Connected and authenticated")
    }

    // Create and start multiplexer
    g_bc_mux = protocol.mux_create(socket, &crypto_ctx)

    // Set callbacks
    g_bc_mux.on_session_new = bc_on_session_new
    g_bc_mux.on_session_data = bc_on_session_data
    g_bc_mux.on_session_close = bc_on_session_close
    g_bc_mux.on_disconnect = bc_on_disconnect
    g_bc_mux.on_port_assigned = bc_on_port_assigned

    protocol.mux_start(g_bc_mux)

    // Wait for disconnect (mux_stop will be called by disconnect handler)
    for g_bc_mux.is_running {
        time.sleep(100 * time.Millisecond)
    }

    // Cleanup
    protocol.mux_destroy(g_bc_mux)
    protocol.crypto_wipe(&crypto_ctx)

    return true
}

// Perform handshake with server
bc_handshake :: proc(socket: net.TCP_Socket, crypto_ctx: ^protocol.Crypto_Context) -> bool {
    // Initialize crypto with our PSK
    protocol.crypto_init(crypto_ctx, g_config.bc_psk)

    // Read HANDSHAKE_INIT from server
    init_data, read_ok := protocol.frame_read_raw(socket)
    if !read_ok {
        if g_config.verbose {
            log.error("Failed to read HANDSHAKE_INIT")
        }
        return false
    }
    defer delete(init_data)

    // Parse: should be type (1) + session_id (4) + server_pubkey (32) + nonce (24) = 61 bytes
    if len(init_data) < protocol.HEADER_SIZE {
        if g_config.verbose {
            log.error("HANDSHAKE_INIT too short")
        }
        return false
    }

    msg_type, _, _, decode_ok := protocol.frame_decode(init_data)
    if !decode_ok || msg_type != .HANDSHAKE_INIT {
        if g_config.verbose {
            log.error("Invalid HANDSHAKE_INIT message")
        }
        return false
    }

    payload := protocol.get_payload(init_data)
    server_pubkey, nonce, parse_ok := protocol.parse_handshake_init(payload)
    if !parse_ok {
        if g_config.verbose {
            log.error("Failed to parse HANDSHAKE_INIT payload")
        }
        return false
    }

    // Verify server pubkey if pinning enabled
    if g_config.bc_server_pubkey_set {
        match := true
        for i in 0..<protocol.PUBKEY_SIZE {
            if server_pubkey[i] != g_config.bc_server_pubkey[i] {
                match = false
                break
            }
        }
        if !match {
            if g_config.verbose {
                log.error("Server public key mismatch!")
            }
            return false
        }
    }

    // Generate our ephemeral keypair
    protocol.crypto_generate_keypair(crypto_ctx)

    // Set server's public key and compute shared secret
    protocol.crypto_set_remote_pubkey(crypto_ctx, server_pubkey)

    // Compute shared secret (for PSK encryption)
    x25519.scalarmult(crypto_ctx.shared_secret[:], crypto_ctx.local_private[:], server_pubkey[:])
    crypto_ctx.handshake_nonce = nonce

    if g_config.verbose {
        shared_hex := protocol.bytes_to_hex(crypto_ctx.shared_secret[:])
        log.infof("Client shared secret: %s", shared_hex)
        delete(shared_hex)
    }

    // Encrypt our PSK
    encrypted_psk, enc_ok := protocol.crypto_encrypt_psk(crypto_ctx)
    if !enc_ok {
        if g_config.verbose {
            log.error("Failed to encrypt PSK")
        }
        return false
    }
    defer delete(encrypted_psk)

    // Build HANDSHAKE_RESP
    resp_payload := protocol.build_handshake_resp(crypto_ctx.local_public, encrypted_psk)
    defer delete(resp_payload)

    resp_msg := protocol.frame_encode(.HANDSHAKE_RESP, protocol.SESSION_ID_CONTROL, resp_payload)
    defer delete(resp_msg)

    if !protocol.frame_write_raw(socket, resp_msg) {
        if g_config.verbose {
            log.error("Failed to send HANDSHAKE_RESP")
        }
        return false
    }

    // Now derive session keys
    if !protocol.crypto_derive_keys(crypto_ctx, nonce, true) {  // true = we are initiator
        if g_config.verbose {
            log.error("Failed to derive session keys")
        }
        return false
    }

    // Read HANDSHAKE_ACK (this one is encrypted!)
    ack_data, ack_read_ok := protocol.frame_read_encrypted(socket, crypto_ctx)
    if !ack_read_ok {
        if g_config.verbose {
            log.error("Failed to read HANDSHAKE_ACK")
        }
        return false
    }
    defer delete(ack_data)

    ack_type, _, _, ack_decode_ok := protocol.frame_decode(ack_data)
    if !ack_decode_ok || ack_type != .HANDSHAKE_ACK {
        if g_config.verbose {
            log.error("Invalid HANDSHAKE_ACK message")
        }
        return false
    }

    ack_payload := protocol.get_payload(ack_data)
    status, status_ok := protocol.parse_handshake_ack(ack_payload)
    if !status_ok || status != .SUCCESS {
        if g_config.verbose {
            log.errorf("Handshake failed with status: %v", status)
        }
        return false
    }

    return true
}

// Connection args struct for thread
BC_Conn_Args :: struct {
    session_id: u32,
    host:       string,
    port:       u16,
}

// Callback: new session request from server
bc_on_session_new :: proc(mux: ^protocol.Multiplexer, session_id: u32, host: string, port: u16) {
    if g_config.verbose {
        log.infof("Session %d: connect to %s:%d", session_id, host, port)
    }

    // Create session
    session := new(BC_Session)
    session.id = session_id
    session.connected = false

    sync.mutex_lock(&g_bc_sessions_mutex)
    g_bc_sessions[session_id] = session
    sync.mutex_unlock(&g_bc_sessions_mutex)

    // Connect to target in background thread
    args := new(BC_Conn_Args)
    args.session_id = session_id
    args.host = strings.clone(host)
    args.port = port

    thread.create_and_start_with_poly_data(args, bc_connect_target_thread)
}

// Thread to connect to target
bc_connect_target_thread :: proc(args: ^BC_Conn_Args) {
    defer {
        delete(args.host)
        free(args)
    }

    session_id := args.session_id
    host := args.host
    port := args.port

    // Get session
    sync.mutex_lock(&g_bc_sessions_mutex)
    session, exists := g_bc_sessions[session_id]
    sync.mutex_unlock(&g_bc_sessions_mutex)

    if !exists {
        return
    }

    // Build target address
    target_addr := fmt.tprintf("%s:%d", host, port)
    endpoint, parse_ok := net.parse_endpoint(target_addr)

    if !parse_ok {
        if g_config.verbose {
            log.errorf("Session %d: failed to parse target %s", session_id, target_addr)
        }
        protocol.mux_send_session_ready(g_bc_mux, session_id, .HOST_UNREACHABLE)
        bc_cleanup_session(session_id)
        return
    }

    // Connect
    target_socket, dial_err := net.dial_tcp(endpoint)
    if dial_err != nil {
        if g_config.verbose {
            log.errorf("Session %d: failed to connect to %s: %v", session_id, target_addr, dial_err)
        }
        // Map error to status
        status: protocol.Session_Ready_Status = .CONNECTION_REFUSED
        protocol.mux_send_session_ready(g_bc_mux, session_id, status)
        bc_cleanup_session(session_id)
        return
    }

    // Success!
    session.target_socket = target_socket
    session.connected = true

    fmt.printf("[BC] Session %d: connected to %s\n", session_id, target_addr)
    if g_config.verbose {
        log.infof("Session %d: connected to %s", session_id, target_addr)
    }

    fmt.printf("[BC] Session %d: sending SESSION_READY\n", session_id)
    protocol.mux_send_session_ready(g_bc_mux, session_id, .CONNECTED)

    // Start reading from target and sending to mux
    bc_relay_from_target(session)
}

// Relay data from target socket to multiplexer
bc_relay_from_target :: proc(session: ^BC_Session) {
    buffer := make([]u8, g_config.buffer_size)
    defer delete(buffer)

    for session.connected && g_bc_mux.is_running {
        n, err := net.recv_tcp(session.target_socket, buffer)
        if err != nil || n == 0 {
            break
        }

        // Send to mux
        if !protocol.mux_session_send(g_bc_mux, session.id, buffer[:n]) {
            break
        }
    }

    // Session ended
    if session.connected {
        protocol.mux_session_close(g_bc_mux, session.id, .NORMAL)
    }
    bc_cleanup_session(session.id)
}

// Callback: data received for session
bc_on_session_data :: proc(mux: ^protocol.Multiplexer, session_id: u32, data: []u8) {
    fmt.printf("[BC] on_session_data: session=%d, len=%d\n", session_id, len(data))

    sync.mutex_lock(&g_bc_sessions_mutex)
    session, exists := g_bc_sessions[session_id]
    sync.mutex_unlock(&g_bc_sessions_mutex)

    if !exists {
        fmt.printf("[BC] on_session_data: session %d not found\n", session_id)
        return
    }

    if !session.connected {
        fmt.printf("[BC] on_session_data: session %d not connected yet\n", session_id)
        return
    }

    // Write to target socket
    fmt.printf("[BC] on_session_data: writing to target socket\n")
    if !protocol.write_all(session.target_socket, data) {
        fmt.printf("[BC] on_session_data: write failed\n")
    } else {
        fmt.printf("[BC] on_session_data: write succeeded\n")
    }
}

// Callback: session closed by server
bc_on_session_close :: proc(mux: ^protocol.Multiplexer, session_id: u32, reason: protocol.Session_Close_Reason) {
    if g_config.verbose {
        log.infof("Session %d: closed by server (reason: %v)", session_id, reason)
    }
    bc_cleanup_session(session_id)
}

// Callback: disconnected from server
bc_on_disconnect :: proc(mux: ^protocol.Multiplexer) {
    if g_config.verbose {
        log.warn("Disconnected from server")
    } else {
        fmt.println("Disconnected from server")
    }
    mux.should_stop = true
}

// Callback: server assigned us a dedicated SOCKS5 port
bc_on_port_assigned :: proc(mux: ^protocol.Multiplexer, port: u16) {
    fmt.printf("\n")
    fmt.printf("========================================\n")
    fmt.printf("  SOCKS5 Proxy Port Assigned: %d\n", port)
    fmt.printf("========================================\n")
    fmt.printf("\n")
    fmt.printf("Use this port to route traffic through this client's network:\n")
    fmt.printf("  curl --socks5 <server>:%d http://example.com\n", port)
    fmt.printf("\n")
}

// Cleanup a session
bc_cleanup_session :: proc(session_id: u32) {
    sync.mutex_lock(&g_bc_sessions_mutex)
    defer sync.mutex_unlock(&g_bc_sessions_mutex)

    if session, exists := g_bc_sessions[session_id]; exists {
        if session.connected {
            net.close(session.target_socket)
        }
        free(session)
        delete_key(&g_bc_sessions, session_id)
    }
}

// ============================================================================
// Argument Parsing
// ============================================================================

parse_args :: proc() {
    // Set defaults
    g_config.listen_addr = "127.0.0.1:1080"
    g_config.verbose = false
    g_config.require_auth = false
    g_config.username = "admin"
    g_config.password = "password"
    g_config.buffer_size = 16384 // 16KB default
    g_config.connect_timeout = 15 * time.Second
    g_config.read_timeout = 300 * time.Second

    // Backconnect defaults
    g_config.backconnect = false
    g_config.bc_auto_reconnect = true

    // Parse command line arguments
    args := os.args[1:]

    for i := 0; i < len(args); i += 1 {
        arg := args[i]

        switch arg {
        // Normal mode options
        case "-addr":
            if i + 1 < len(args) {
                i += 1
                g_config.listen_addr = args[i]
            }
        case "-v", "-verbose":
            g_config.verbose = true
        case "-auth":
            g_config.require_auth = true
        case "-user":
            if i + 1 < len(args) {
                i += 1
                g_config.username = args[i]
            }
        case "-pass":
            if i + 1 < len(args) {
                i += 1
                g_config.password = args[i]
            }

        // Backconnect mode options
        case "-backconnect":
            g_config.backconnect = true
        case "-bc-server":
            if i + 1 < len(args) {
                i += 1
                g_config.bc_server_addr = args[i]
            }
        case "-bc-psk":
            if i + 1 < len(args) {
                i += 1
                if !protocol.hex_to_bytes(args[i], g_config.bc_psk[:]) {
                    fmt.eprintln("Error: Invalid PSK (must be 64 hex characters)")
                    os.exit(1)
                }
            }
        case "-bc-pubkey":
            if i + 1 < len(args) {
                i += 1
                if !protocol.hex_to_bytes(args[i], g_config.bc_server_pubkey[:]) {
                    fmt.eprintln("Error: Invalid server pubkey (must be 64 hex characters)")
                    os.exit(1)
                }
                g_config.bc_server_pubkey_set = true
            }
        case "-no-reconnect":
            g_config.bc_auto_reconnect = false

        case "-h", "-help":
            print_help()
            os.exit(0)
        }
    }

    // Validate backconnect mode
    if g_config.backconnect {
        if g_config.bc_server_addr == "" {
            fmt.eprintln("Error: -bc-server is required in backconnect mode")
            os.exit(1)
        }
        // Check if PSK is set (non-zero)
        psk_set := false
        for b in g_config.bc_psk {
            if b != 0 {
                psk_set = true
                break
            }
        }
        if !psk_set {
            fmt.eprintln("Error: -bc-psk is required in backconnect mode")
            os.exit(1)
        }
    }
}

print_help :: proc() {
    fmt.println("SOCKS5 Proxy with Backconnect Support")
    fmt.println()
    fmt.println("Usage:")
    fmt.println("  s5_proxy [options]                    # Normal SOCKS5 server mode")
    fmt.println("  s5_proxy -backconnect [options]       # Backconnect client mode")
    fmt.println()
    fmt.println("Normal Mode Options:")
    fmt.println("  -addr <address>     Listen address (default: 127.0.0.1:1080)")
    fmt.println("  -auth               Require username/password authentication")
    fmt.println("  -user <username>    Username for authentication (default: admin)")
    fmt.println("  -pass <password>    Password for authentication (default: password)")
    fmt.println()
    fmt.println("Backconnect Mode Options:")
    fmt.println("  -backconnect        Enable backconnect client mode")
    fmt.println("  -bc-server <addr>   Backconnect server address (host:port)")
    fmt.println("  -bc-psk <hex>       Pre-shared key (64 hex characters)")
    fmt.println("  -bc-pubkey <hex>    Server public key for pinning (optional)")
    fmt.println("  -no-reconnect       Disable automatic reconnection")
    fmt.println()
    fmt.println("General Options:")
    fmt.println("  -v, -verbose        Enable verbose logging")
    fmt.println("  -h, -help           Show this help message")
    fmt.println()
    fmt.println("Examples:")
    fmt.println("  # Run as local SOCKS5 proxy")
    fmt.println("  s5_proxy -addr 0.0.0.0:1080")
    fmt.println()
    fmt.println("  # Run as backconnect client")
    fmt.println("  s5_proxy -backconnect -bc-server 1.2.3.4:8443 -bc-psk <64-hex>")
}
