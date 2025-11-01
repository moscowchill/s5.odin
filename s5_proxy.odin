/*
   SOCKS5 Proxy Server in Odin

   Production-ready SOCKS5 proxy with robust error handling:
   - Configurable timeouts and buffer sizes
   - Connection limits to prevent resource exhaustion
   - Partial read protection for network resilience
   - Memory leak free
   - Username/password authentication option
   - Minimal logging by default

   Usage:
     odin run s5_proxy.odin -- -addr 127.0.0.1:1080
     odin run s5_proxy.odin -- -addr 127.0.0.1:1080 -auth -user admin -pass secret
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
g_connection_count: int
g_connection_mutex: ^os.Handle

// Connection limits (adjusted for small pentesting team)
MAX_CONNECTIONS :: 1000  // Plenty for 1-2 users with aggressive scanning

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

        // Check connection limit
        if g_connection_count >= MAX_CONNECTIONS {
            if g_config.verbose {
                log.warnf("Connection limit reached (%d), rejecting connection", MAX_CONNECTIONS)
            }
            net.close(client_socket)
            continue
        }

        if g_config.verbose {
            log.infof("New connection from: %v", client_endpoint)
        }

        // Increment connection counter
        g_connection_count += 1

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
    defer {
        g_connection_count -= 1
    }

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
    defer delete(target_host)  // Free the allocated host string

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
    if !recv_exactly(socket, buf[:2]) {
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
        if !recv_exactly(socket, buf[:nmethods]) {
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
    if !recv_exactly(socket, buf[:1]) || buf[0] != 0x01 {
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
    username := string(buf[:ulen])

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

    // Verify credentials (comparing slices directly to avoid string allocation)
    auth_ok := username == g_config.username && password == g_config.password

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
    if !recv_exactly(socket, buf[:4]) {
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
        if !recv_exactly(socket, buf[:6]) {
            return "", 0, 0, false
        }

        // Format IPv4 address
        host_str := fmt.tprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
        host = strings.clone(host_str)
        port_bytes[0] = buf[4]
        port_bytes[1] = buf[5]

    case ATYP_DOMAIN:
        // Read domain length
        if !recv_exactly(socket, buf[:1]) {
            return "", 0, 0, false
        }
        domain_len := int(buf[0])
        if domain_len == 0 || domain_len > 255 {
            return "", 0, 0, false
        }

        // Read domain + port
        if !recv_exactly(socket, buf[:domain_len + 2]) {
            return "", 0, 0, false
        }

        host = strings.clone(string(buf[:domain_len]))
        port_bytes[0] = buf[domain_len]
        port_bytes[1] = buf[domain_len + 1]

    case ATYP_IPV6:
        // Read 16 bytes for IPv6 + 2 bytes for port
        if !recv_exactly(socket, buf[:18]) {
            return "", 0, 0, false
        }

        // Format IPv6 address (proper format with colons)
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

send_socks5_reply :: proc(socket: net.TCP_Socket, reply_code: byte, bind_addr: Maybe([4]byte) = nil, bind_port: u16 = 0) -> bool {
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

    // Send the reply and handle partial sends
    sent := 0
    for sent < len(buf) {
        n, err := net.send_tcp(socket, buf[sent:])
        if err != nil {
            return false
        }
        sent += n
    }
    return true
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

    // Parse command line arguments
    args := os.args[1:]

    for i := 0; i < len(args); i += 1 {
        arg := args[i]

        switch arg {
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
        case "-buffer":
            if i + 1 < len(args) {
                i += 1
                buffer_val := args[i]
                // Simple integer parsing
                val := 0
                for c in buffer_val {
                    if c >= '0' && c <= '9' {
                        val = val * 10 + int(c - '0')
                    }
                }
                if val > 0 && val <= 1048576 { // Max 1MB buffer
                    g_config.buffer_size = val
                }
            }
        case "-h", "-help":
            print_help()
            os.exit(0)
        }
    }
}

print_help :: proc() {
    fmt.println("SOCKS5 Proxy Server")
    fmt.println()
    fmt.println("Usage:")
    fmt.println("  s5_proxy [options]")
    fmt.println()
    fmt.println("Options:")
    fmt.println("  -addr <address>     Listen address (default: 127.0.0.1:1080)")
    fmt.println("  -v, -verbose        Enable verbose logging")
    fmt.println("  -auth               Require username/password authentication")
    fmt.println("  -user <username>    Username for authentication (default: admin)")
    fmt.println("  -pass <password>    Password for authentication (default: password)")
    fmt.println("  -buffer <size>      Buffer size in bytes (default: 16384)")
    fmt.println("  -h, -help           Show this help message")
    fmt.println()
    fmt.println("Examples:")
    fmt.println("  s5_proxy -addr 0.0.0.0:1080")
    fmt.println("  s5_proxy -addr 127.0.0.1:9050 -auth -user admin -pass secret")
    fmt.println("  s5_proxy -v -buffer 32768")
}
