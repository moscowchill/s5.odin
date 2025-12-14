/*
   Backconnect SOCKS5 Server

   This server:
   1. Listens for backconnect clients (encrypted tunnel)
   2. Exposes a SOCKS5 interface for end users
   3. Routes SOCKS5 requests through connected backconnect clients

   Usage:
     odin run backconnect_server.odin -- -bc-psk <64-hex>
     odin run backconnect_server.odin -- -socks-addr :1080 -bc-addr :8443 -bc-psk <64-hex>
*/

package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"
import "core:thread"
import "core:mem"
import "core:sync"
import "core:crypto"
import "core:crypto/x25519"

import "../../protocol"

// ============================================================================
// ANSI Colors & Styling
// ============================================================================

// Colors
C_RESET    :: "\x1b[0m"
C_BOLD     :: "\x1b[1m"
C_DIM      :: "\x1b[2m"
C_RED      :: "\x1b[31m"
C_GREEN    :: "\x1b[32m"
C_YELLOW   :: "\x1b[33m"
C_BLUE     :: "\x1b[34m"
C_MAGENTA  :: "\x1b[35m"
C_CYAN     :: "\x1b[36m"
C_WHITE    :: "\x1b[37m"
C_B_GREEN  :: "\x1b[1;32m"
C_B_RED    :: "\x1b[1;31m"
C_B_YELLOW :: "\x1b[1;33m"
C_B_CYAN   :: "\x1b[1;36m"
C_B_MAGENTA:: "\x1b[1;35m"

// Symbols
SYM_CONNECTED    :: "●"
SYM_DISCONNECTED :: "○"
SYM_ARROW        :: "→"
SYM_KEY          :: "🔑"
SYM_LOCK         :: "🔒"

// Box drawing (rounded)
BOX_TL :: "╭"
BOX_TR :: "╮"
BOX_BL :: "╰"
BOX_BR :: "╯"
BOX_H  :: "─"
BOX_V  :: "│"

// Get current timestamp string
get_timestamp :: proc() -> string {
    now := time.now()
    h, m, s := time.clock_from_time(now)
    return fmt.tprintf("%02d:%02d:%02d", h, m, s)
}

// Print the banner
print_banner :: proc() {
    fmt.printf("%s", C_B_CYAN)
    fmt.println("  ____  ____     ___      _ _       ")
    fmt.println(" / ___|| ___|   / _ \\  __| (_)_ __  ")
    fmt.println(" \\___ \\|___ \\  | | | |/ _` | | '_ \\ ")
    fmt.println("  ___) |___) | | |_| | (_| | | | | |")
    fmt.println(" |____/|____/ (_)___/ \\__,_|_|_| |_|")
    fmt.printf("%s", C_RESET)
    fmt.printf("  %s%sBackconnect Proxy Server%s\n", C_DIM, C_WHITE, C_RESET)
    fmt.println()
}

// SOCKS5 Protocol Constants
SOCKS_VERSION :: 0x05
AUTH_NONE :: 0x00
AUTH_USERPASS :: 0x02
CMD_CONNECT :: 0x01
ATYP_IPV4 :: 0x01
ATYP_DOMAIN :: 0x03
ATYP_IPV6 :: 0x04
REP_SUCCESS :: 0x00
REP_GENERAL_FAILURE :: 0x01
REP_HOST_UNREACHABLE :: 0x04
REP_COMMAND_NOT_SUPPORTED :: 0x07

// Server configuration
Server_Config :: struct {
    // SOCKS5 authentication (for per-client dedicated ports)
    socks_auth:       bool,
    socks_user:       string,
    socks_pass:       string,

    // Backconnect backend
    bc_addr:          string,
    server_privkey:   [protocol.PRIVKEY_SIZE]u8,
    server_pubkey:    [protocol.PUBKEY_SIZE]u8,
    allowed_psks:     [dynamic][protocol.PSK_SIZE]u8,
    master_psk:       [protocol.PSK_SIZE]u8,  // Master PSK for OTP generation
    otp_enabled:      bool,                    // Whether OTP mode is active
    current_otp_window: i64,                   // Current OTP window for refresh detection

    // General
    verbose:          bool,
}

// Connected backconnect client
BC_Client :: struct {
    id:               u32,
    socket:           net.TCP_Socket,
    mux:              ^protocol.Multiplexer,
    crypto_ctx:       protocol.Crypto_Context,
    connected_at:     time.Time,
    last_activity:    time.Time,
    active_sessions:  int,
    is_authenticated: bool,
    // Per-client SOCKS5 port
    socks_port:       u16,
    socks_listener:   net.TCP_Socket,
    socks_running:    bool,
}

// Pending SOCKS5 request waiting for backconnect session
Pending_Request :: struct {
    socks_socket:     net.TCP_Socket,
    session_id:       u32,
    bc_client_id:     u32,
    target_host:      string,
    target_port:      u16,
    created_at:       time.Time,
}

// Active session (after SESSION_READY)
Active_Session :: struct {
    session_id:       u32,
    socks_socket:     net.TCP_Socket,
    bc_client_id:     u32,
}

// Arguments for relay thread (SOCKS -> BC direction)
Relay_Args :: struct {
    socks_socket: net.TCP_Socket,
    bc_client:    ^BC_Client,
    session_id:   u32,
}

// Global server state
g_config: Server_Config
g_clients: map[u32]^BC_Client
g_clients_mutex: sync.Mutex
g_next_client_id: u32 = 1
g_pending: map[u32]^Pending_Request  // session_id -> pending request
g_pending_mutex: sync.Mutex
g_active: map[u32]^Active_Session    // session_id -> active session
g_active_mutex: sync.Mutex

// Port allocation for per-client SOCKS5 listeners
PORT_RANGE_START :: 6000
PORT_RANGE_END   :: 8000

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
g_allocated_ports: map[u16]bool  // port -> in_use
g_ports_mutex: sync.Mutex

main :: proc() {
    context.logger = log.create_console_logger()

    parse_args()

    // Print banner
    print_banner()

    // Print server public key
    pubkey_hex := protocol.bytes_to_hex(g_config.server_pubkey[:])
    fmt.printf("%s%s pubkey:%s %s%s%s\n", C_DIM, SYM_KEY, C_RESET, C_CYAN, pubkey_hex, C_RESET)
    delete(pubkey_hex)

    if g_config.verbose {
        log.infof("Backconnect listener: %s", g_config.bc_addr)
    }

    // Display OTP if enabled
    if g_config.otp_enabled {
        display_current_otp()
    }

    g_clients = make(map[u32]^BC_Client)
    g_pending = make(map[u32]^Pending_Request)
    g_active = make(map[u32]^Active_Session)
    g_allocated_ports = make(map[u16]bool)

    // Start OTP refresh thread if OTP mode is enabled
    if g_config.otp_enabled {
        thread.create_and_start(otp_refresh_thread)
    }

    // Start backconnect listener (runs in main thread)
    // Each client gets a dedicated SOCKS5 port when they connect
    run_bc_listener()
}

// Display current OTP (short 8-char version)
display_current_otp :: proc() {
    unix_time := time.time_to_unix(time.now())
    full_otp := protocol.generate_current_otp(g_config.master_psk, unix_time)
    short_otp := protocol.get_short_otp(full_otp)
    otp_hex := protocol.bytes_to_hex(short_otp[:])
    defer delete(otp_hex)

    remaining := protocol.otp_seconds_remaining(unix_time)
    hours := remaining / 3600
    mins := (remaining % 3600) / 60

    // Fixed width box (36 chars inner)
    BOX_WIDTH :: 36

    fmt.println()
    fmt.printf("%s%s", C_YELLOW, BOX_TL)
    for _ in 0..<BOX_WIDTH { fmt.printf("%s", BOX_H) }
    fmt.printf("%s%s\n", BOX_TR, C_RESET)

    fmt.printf("%s%s%s  %s OTP: %s%s%s  %s(valid %dh %dm)%s  %s%s%s\n",
        C_YELLOW, BOX_V, C_RESET,
        SYM_LOCK, C_B_YELLOW, otp_hex, C_RESET,
        C_DIM, hours, mins, C_RESET,
        C_YELLOW, BOX_V, C_RESET)

    fmt.printf("%s%s", C_YELLOW, BOX_BL)
    for _ in 0..<BOX_WIDTH { fmt.printf("%s", BOX_H) }
    fmt.printf("%s%s\n", BOX_BR, C_RESET)
    fmt.println()

    // Update current window
    g_config.current_otp_window = protocol.get_current_otp_window(unix_time)

    // Update allowed_psks with current valid OTPs (full versions for crypto)
    refresh_otp_psks()
}

// Refresh the OTP-derived PSKs in allowed_psks
// Server generates full OTP -> extracts short OTP -> expands via SHA256
// This matches what the client does with the 8-char OTP
refresh_otp_psks :: proc() {
    unix_time := time.time_to_unix(time.now())
    window := protocol.get_current_otp_window(unix_time)

    // Clear existing and add new expanded OTPs
    clear(&g_config.allowed_psks)

    // Add current and previous window (for clock drift)
    windows := [2]i64{window, window - 1}
    for w in windows {
        full_otp := protocol.generate_otp(g_config.master_psk, w)
        short_otp := protocol.get_short_otp(full_otp)
        expanded := protocol.expand_short_otp(short_otp)
        append(&g_config.allowed_psks, expanded)
    }
}

// Thread to refresh OTP display when window changes
otp_refresh_thread :: proc() {
    context.logger = log.create_console_logger()

    for {
        time.sleep(60 * time.Second)  // Check every minute

        unix_time := time.time_to_unix(time.now())
        current_window := protocol.get_current_otp_window(unix_time)

        if current_window != g_config.current_otp_window {
            // Window changed, display new OTP
            ts := get_timestamp()
            fmt.printf("\n%s[%s]%s %s%s OTP rotated%s\n", C_DIM, ts, C_RESET, C_B_MAGENTA, SYM_LOCK, C_RESET)
            display_current_otp()
        }
    }
}

// ============================================================================
// Port Allocation
// ============================================================================

// Allocate next available port starting from PORT_RANGE_START
allocate_port :: proc() -> (port: u16, ok: bool) {
    sync.mutex_lock(&g_ports_mutex)
    defer sync.mutex_unlock(&g_ports_mutex)

    for p := u16(PORT_RANGE_START); p <= PORT_RANGE_END; p += 1 {
        if !(p in g_allocated_ports) {
            g_allocated_ports[p] = true
            return p, true
        }
    }
    return 0, false
}

// Free an allocated port
free_port :: proc(port: u16) {
    sync.mutex_lock(&g_ports_mutex)
    defer sync.mutex_unlock(&g_ports_mutex)

    delete_key(&g_allocated_ports, port)
}

// Start a dedicated SOCKS5 listener for a specific client
start_client_socks_listener :: proc(client: ^BC_Client) -> bool {
    // Try to find a port that we can actually bind to
    // (some ports may be in TIME_WAIT from recently closed connections)
    MAX_ATTEMPTS :: 100

    for attempt in 0..<MAX_ATTEMPTS {
        // Allocate port
        port, ok := allocate_port()
        if !ok {
            log.error("Failed to allocate port for client - port range exhausted")
            return false
        }

        // Create listener
        addr_str := fmt.tprintf("0.0.0.0:%d", port)
        endpoint, parse_ok := net.parse_endpoint(addr_str)
        if !parse_ok {
            free_port(port)
            continue
        }

        listen_socket, listen_err := net.listen_tcp(endpoint)
        if listen_err != nil {
            if g_config.verbose {
                log.warnf("Port %d unavailable (likely TIME_WAIT), trying next...", port)
            }
            // Don't free the port - mark it as unavailable for now
            // It will be cleaned up eventually or on restart
            continue
        }

        // Success!
        client.socks_port = port
        client.socks_listener = listen_socket
        client.socks_running = true

        // Start listener thread
        thread.create_and_start_with_poly_data(client, run_client_socks_listener_thread)
        return true
    }

    log.error("Failed to find available port after multiple attempts")
    return false
}

// Stop the dedicated SOCKS5 listener for a client
stop_client_socks_listener :: proc(client: ^BC_Client) {
    if client.socks_running {
        client.socks_running = false
        net.close(client.socks_listener)
        free_port(client.socks_port)
    }
}

// Per-client SOCKS5 listener thread
run_client_socks_listener_thread :: proc(client: ^BC_Client) {
    context.logger = log.create_console_logger()

    if g_config.verbose {
        log.infof("Client %d SOCKS5 listener started on port %d", client.id, client.socks_port)
    }

    for client.socks_running && client.mux.is_running {
        client_socket, _, accept_err := net.accept_tcp(client.socks_listener)
        if accept_err != nil {
            if client.socks_running {
                continue
            }
            break
        }

        // Create args for the handler
        args := new(Client_Socks_Args)
        args.socks_socket = client_socket
        args.bc_client = client

        thread.create_and_start_with_poly_data(args, handle_client_socks_thread)
    }

    if g_config.verbose {
        log.infof("Client %d SOCKS5 listener stopped", client.id)
    }
}

// Args for per-client SOCKS5 handler
Client_Socks_Args :: struct {
    socks_socket: net.TCP_Socket,
    bc_client:    ^BC_Client,
}

// Handle SOCKS5 connection for a specific client
handle_client_socks_thread :: proc(args: ^Client_Socks_Args) {
    context.logger = log.create_console_logger()
    defer free(args)

    socket := args.socks_socket
    bc_client := args.bc_client

    // SOCKS5 handshake
    if !socks_handshake(socket) {
        net.close(socket)
        return
    }

    // Parse request
    host, port, cmd, ok := parse_socks_request(socket)
    if !ok {
        send_socks_reply(socket, REP_GENERAL_FAILURE)
        net.close(socket)
        return
    }
    defer delete(host)

    if cmd != CMD_CONNECT {
        send_socks_reply(socket, REP_COMMAND_NOT_SUPPORTED)
        net.close(socket)
        return
    }

    if g_config.verbose {
        log.infof("Client %d SOCKS5: %s:%d", bc_client.id, host, port)
    }

    // Check if client is still connected
    if !bc_client.mux.is_running {
        send_socks_reply(socket, REP_GENERAL_FAILURE)
        net.close(socket)
        return
    }

    // Create session on this specific client
    session_id := protocol.mux_session_create(bc_client.mux, host, port)

    if g_config.verbose {
        log.infof("Routing %s:%d through BC client %d (session %d)", host, port, bc_client.id, session_id)
    }

    // Create pending request
    pending := new(Pending_Request)
    pending.socks_socket = socket
    pending.session_id = session_id
    pending.bc_client_id = bc_client.id
    pending.target_host = strings.clone(host)
    pending.target_port = port
    pending.created_at = time.now()

    sync.mutex_lock(&g_pending_mutex)
    g_pending[session_id] = pending
    sync.mutex_unlock(&g_pending_mutex)

    // Send SESSION_NEW to backconnect client
    atyp: protocol.Address_Type
    addr_bytes: []u8

    if ep, ep_ok := net.parse_endpoint(fmt.tprintf("%s:0", host)); ep_ok {
        #partial switch v in ep.address {
        case net.IP4_Address:
            atyp = .IPV4
            addr_bytes = make([]u8, 4)
            addr_bytes[0] = v[0]
            addr_bytes[1] = v[1]
            addr_bytes[2] = v[2]
            addr_bytes[3] = v[3]
        case:
            atyp = .DOMAIN
            addr_bytes = transmute([]u8)host
        }
    } else {
        atyp = .DOMAIN
        addr_bytes = transmute([]u8)host
    }

    protocol.mux_send_session_new(bc_client.mux, session_id, atyp, addr_bytes, port)

    if atyp != .DOMAIN {
        delete(addr_bytes)
    }

    // Wait for response (with timeout)
    start := time.now()
    timeout := 30 * time.Second

    for {
        time.sleep(50 * time.Millisecond)

        sync.mutex_lock(&g_pending_mutex)
        still_pending := session_id in g_pending
        sync.mutex_unlock(&g_pending_mutex)

        if !still_pending {
            return
        }

        if time.diff(start, time.now()) > timeout {
            sync.mutex_lock(&g_pending_mutex)
            if p, exists := g_pending[session_id]; exists {
                delete(p.target_host)
                free(p)
                delete_key(&g_pending, session_id)
            }
            sync.mutex_unlock(&g_pending_mutex)

            send_socks_reply(socket, REP_GENERAL_FAILURE)
            net.close(socket)
            return
        }

        if !bc_client.mux.is_running {
            sync.mutex_lock(&g_pending_mutex)
            if p, exists := g_pending[session_id]; exists {
                delete(p.target_host)
                free(p)
                delete_key(&g_pending, session_id)
            }
            sync.mutex_unlock(&g_pending_mutex)

            send_socks_reply(socket, REP_GENERAL_FAILURE)
            net.close(socket)
            return
        }
    }
}

// ============================================================================
// Backconnect Listener
// ============================================================================

run_bc_listener :: proc() {
    endpoint, parse_ok := net.parse_endpoint(g_config.bc_addr)
    if !parse_ok {
        log.errorf("Failed to parse backconnect address: %s", g_config.bc_addr)
        os.exit(1)
    }

    listen_socket, listen_err := net.listen_tcp(endpoint)
    if listen_err != nil {
        log.errorf("Failed to bind backconnect listener: %v", listen_err)
        os.exit(1)
    }
    defer net.close(listen_socket)

    // Print listener info
    ts := get_timestamp()
    fmt.printf("%s[%s]%s %s%s%s Listening on %s%s%s\n",
        C_DIM, ts, C_RESET,
        C_B_CYAN, SYM_ARROW, C_RESET,
        C_WHITE, g_config.bc_addr, C_RESET)

    for {
        client_socket, client_endpoint, accept_err := net.accept_tcp(listen_socket)
        if accept_err != nil {
            if g_config.verbose {
                log.errorf("BC accept error: %v", accept_err)
            }
            continue
        }

        if g_config.verbose {
            log.infof("New backconnect client from: %v", client_endpoint)
        }

        // Handle in new thread
        thread.create_and_start_with_poly_data(client_socket, handle_bc_client_thread)
    }
}

handle_bc_client_thread :: proc(socket: net.TCP_Socket) {
    // Set up logger for this thread
    context.logger = log.create_console_logger()

    if g_config.verbose {
        log.info("handle_bc_client_thread: started")
    }
    // Perform handshake
    client := bc_handshake(socket)
    if client == nil {
        net.close(socket)
        return
    }

    if g_config.verbose {
        log.infof("BC client %d authenticated", client.id)
    }

    // Register client
    sync.mutex_lock(&g_clients_mutex)
    g_clients[client.id] = client
    sync.mutex_unlock(&g_clients_mutex)

    // Start multiplexer
    client.mux.on_session_ready = bc_on_session_ready
    client.mux.on_session_data = bc_on_session_data
    client.mux.on_session_close = bc_on_session_close
    client.mux.on_disconnect = bc_on_disconnect
    client.mux.user_data = client

    protocol.mux_start(client.mux)

    // Start per-client SOCKS5 listener
    if !start_client_socks_listener(client) {
        log.errorf("Failed to start SOCKS5 listener for client %d", client.id)
        protocol.mux_stop(client.mux)
        sync.mutex_lock(&g_clients_mutex)
        delete_key(&g_clients, client.id)
        sync.mutex_unlock(&g_clients_mutex)
        protocol.mux_destroy(client.mux)
        protocol.crypto_wipe(&client.crypto_ctx)
        free(client)
        return
    }

    // Send PORT_ASSIGNED message to client
    port_payload := protocol.build_port_assigned(client.socks_port)
    defer delete(port_payload)
    protocol.send_message(client.socket, &client.crypto_ctx, .PORT_ASSIGNED, protocol.SESSION_ID_CONTROL, port_payload)

    ts := get_timestamp()
    fmt.printf("%s[%s]%s %s%s%s Client %s#%d%s connected %s→%s port %s%d%s\n",
        C_DIM, ts, C_RESET,
        C_B_GREEN, SYM_CONNECTED, C_RESET,
        C_WHITE, client.id, C_RESET,
        C_DIM, C_RESET,
        C_B_GREEN, client.socks_port, C_RESET)

    // Wait for disconnect
    for client.mux.is_running {
        time.sleep(100 * time.Millisecond)
    }

    // Stop per-client SOCKS5 listener
    stop_client_socks_listener(client)

    // Cleanup
    ts = get_timestamp()
    if g_config.verbose {
        log.infof("BC client %d disconnected", client.id)
    }
    fmt.printf("%s[%s]%s %s%s%s Client %s#%d%s disconnected %s←%s port %s%d%s\n",
        C_DIM, ts, C_RESET,
        C_DIM, SYM_DISCONNECTED, C_RESET,
        C_DIM, client.id, C_RESET,
        C_DIM, C_RESET,
        C_DIM, client.socks_port, C_RESET)

    sync.mutex_lock(&g_clients_mutex)
    delete_key(&g_clients, client.id)
    sync.mutex_unlock(&g_clients_mutex)

    // Cancel any pending requests for this client
    sync.mutex_lock(&g_pending_mutex)
    to_remove: [dynamic]u32
    for session_id, pending in g_pending {
        if pending.bc_client_id == client.id {
            net.close(pending.socks_socket)
            delete(pending.target_host)
            free(pending)
            append(&to_remove, session_id)
        }
    }
    for id in to_remove {
        delete_key(&g_pending, id)
    }
    delete(to_remove)
    sync.mutex_unlock(&g_pending_mutex)

    protocol.mux_destroy(client.mux)
    protocol.crypto_wipe(&client.crypto_ctx)
    free(client)
}

bc_handshake :: proc(socket: net.TCP_Socket) -> ^BC_Client {
    if g_config.verbose {
        log.info("BC handshake: starting (encrypted mode)")
    }
    client := new(BC_Client)
    client.socket = socket
    client.connected_at = time.now()

    // Initialize crypto with server keys
    protocol.crypto_init(&client.crypto_ctx, {})  // PSK will be set after verification
    client.crypto_ctx.local_private = g_config.server_privkey
    client.crypto_ctx.local_public = g_config.server_pubkey

    // Get allowed PSKs for handshake encryption
    // In OTP mode: these are expanded short OTPs (SHA256 of short OTP)
    // In raw PSK mode: this is the master PSK
    psks_slice := g_config.allowed_psks[:]
    if len(psks_slice) == 0 {
        if g_config.verbose {
            log.error("No allowed PSKs configured")
        }
        free(client)
        return nil
    }

    // Send encrypted HANDSHAKE_INIT using first (current window) PSK
    nonce, write_ok := protocol.frame_write_handshake_init_encrypted(socket, psks_slice[0], g_config.server_pubkey)
    if !write_ok {
        if g_config.verbose {
            log.error("Failed to send encrypted HANDSHAKE_INIT")
        }
        free(client)
        return nil
    }

    if g_config.verbose {
        log.info("BC handshake: sent encrypted HANDSHAKE_INIT, waiting for HANDSHAKE_RESP")
    }

    // Read encrypted HANDSHAKE_RESP - try all allowed PSKs for clock drift tolerance
    client_pubkey, encrypted_psk, matched_psk, read_ok := protocol.frame_read_handshake_resp_encrypted_multi(socket, psks_slice, nonce)
    if !read_ok {
        if g_config.verbose {
            log.error("Failed to read/decrypt HANDSHAKE_RESP (wrong PSK or OTP expired?)")
        }
        free(client)
        return nil
    }
    defer delete(encrypted_psk)

    if g_config.verbose {
        log.info("BC handshake: received and decrypted HANDSHAKE_RESP")
    }

    // Use the matched PSK for further operations
    _ = matched_psk  // Will be verified again in crypto_verify_psk

    // Set client's public key and compute shared secret
    protocol.crypto_set_remote_pubkey(&client.crypto_ctx, client_pubkey)
    x25519.scalarmult(client.crypto_ctx.shared_secret[:], g_config.server_privkey[:], client_pubkey[:])
    client.crypto_ctx.handshake_nonce = nonce

    // Verify PSK (psks_slice already defined above)
    if g_config.verbose {
        log.infof("Verifying PSK, encrypted_psk len=%d, num_psks=%d", len(encrypted_psk), len(psks_slice))
        shared_hex := protocol.bytes_to_hex(client.crypto_ctx.shared_secret[:])
        log.infof("Shared secret: %s", shared_hex)
        delete(shared_hex)
    }
    if !protocol.crypto_verify_psk(&client.crypto_ctx, encrypted_psk, psks_slice) {
        if g_config.verbose {
            log.error("PSK verification failed")
        }

        // Send failure ACK (need to derive keys first for encrypted response)
        // Actually for failure, we should send unencrypted or just close
        free(client)
        return nil
    }
    if g_config.verbose {
        log.info("PSK verified successfully")
    }

    // Derive session keys (we are not the initiator)
    if !protocol.crypto_derive_keys(&client.crypto_ctx, nonce, false) {
        if g_config.verbose {
            log.error("Failed to derive session keys")
        }
        free(client)
        return nil
    }

    // Send encrypted HANDSHAKE_ACK
    ack_payload := protocol.build_handshake_ack(.SUCCESS)
    defer delete(ack_payload)

    ack_msg := protocol.frame_encode(.HANDSHAKE_ACK, protocol.SESSION_ID_CONTROL, ack_payload)
    defer delete(ack_msg)

    if !protocol.frame_write_encrypted(socket, &client.crypto_ctx, ack_msg) {
        if g_config.verbose {
            log.error("Failed to send HANDSHAKE_ACK")
        }
        free(client)
        return nil
    }

    // Assign ID and create multiplexer
    sync.mutex_lock(&g_clients_mutex)
    client.id = g_next_client_id
    g_next_client_id += 1
    sync.mutex_unlock(&g_clients_mutex)

    client.mux = protocol.mux_create(socket, &client.crypto_ctx)
    client.is_authenticated = true

    return client
}

// Callback: session ready response from backconnect client
bc_on_session_ready :: proc(mux: ^protocol.Multiplexer, session_id: u32, status: protocol.Session_Ready_Status) {
    sync.mutex_lock(&g_pending_mutex)
    pending, exists := g_pending[session_id]
    if !exists {
        sync.mutex_unlock(&g_pending_mutex)
        return
    }
    delete_key(&g_pending, session_id)
    sync.mutex_unlock(&g_pending_mutex)

    if status != .CONNECTED {
        // Connection failed
        if g_config.verbose {
            log.warnf("Session %d: connection failed with status %v", session_id, status)
        }
        send_socks_reply(pending.socks_socket, REP_HOST_UNREACHABLE)
        net.close(pending.socks_socket)
        delete(pending.target_host)
        free(pending)
        return
    }

    // Success! Send SOCKS5 success reply
    if g_config.verbose {
        log.infof("Session %d: connected to %s:%d", session_id, pending.target_host, pending.target_port)
    }
    send_socks_reply(pending.socks_socket, REP_SUCCESS)

    // Start relaying from SOCKS5 client to backconnect
    // Get the BC client
    sync.mutex_lock(&g_clients_mutex)
    bc_client, client_exists := g_clients[pending.bc_client_id]
    sync.mutex_unlock(&g_clients_mutex)

    if !client_exists {
        net.close(pending.socks_socket)
        delete(pending.target_host)
        free(pending)
        return
    }

    // Track as active session
    active := new(Active_Session)
    active.session_id = session_id
    active.socks_socket = pending.socks_socket
    active.bc_client_id = pending.bc_client_id

    sync.mutex_lock(&g_active_mutex)
    g_active[session_id] = active
    sync.mutex_unlock(&g_active_mutex)

    // Start relay thread (SOCKS -> BC direction)
    args := new(Relay_Args)
    args.socks_socket = pending.socks_socket
    args.bc_client = bc_client
    args.session_id = session_id

    thread.create_and_start_with_poly_data(args, relay_socks_to_bc_thread)

    delete(pending.target_host)
    free(pending)
}

// Relay from SOCKS5 client to backconnect session
relay_socks_to_bc_thread :: proc(args: ^Relay_Args) {
    context.logger = log.create_console_logger()
    defer free(args)

    buffer := make([]u8, 16384)
    defer delete(buffer)

    if g_config.verbose {
        log.infof("[RELAY] socks_to_bc thread started for session %d", args.session_id)
    }

    for args.bc_client.mux.is_running {
        n, err := net.recv_tcp(args.socks_socket, buffer)
        if err != nil || n == 0 {
            if g_config.verbose {
                log.infof("[RELAY] session %d: recv returned n=%d, err=%v", args.session_id, n, err)
            }
            break
        }

        if g_config.verbose {
            log.infof("[RELAY] session %d: forwarding %d bytes", args.session_id, n)
        }
        if !protocol.mux_session_send(args.bc_client.mux, args.session_id, buffer[:n]) {
            if g_config.verbose {
                log.warnf("[RELAY] session %d: mux_session_send failed", args.session_id)
            }
            break
        }
    }

    if g_config.verbose {
        log.infof("[RELAY] session %d: closing", args.session_id)
    }
    // Close session
    protocol.mux_session_close(args.bc_client.mux, args.session_id, .NORMAL)

    // Remove from active
    sync.mutex_lock(&g_active_mutex)
    if active, exists := g_active[args.session_id]; exists {
        free(active)
        delete_key(&g_active, args.session_id)
    }
    sync.mutex_unlock(&g_active_mutex)

    net.close(args.socks_socket)
}

// Callback: data from backconnect session to SOCKS5 client
bc_on_session_data :: proc(mux: ^protocol.Multiplexer, session_id: u32, data: []u8) {
    // Find the SOCKS5 socket for this session
    sync.mutex_lock(&g_active_mutex)
    active, exists := g_active[session_id]
    sync.mutex_unlock(&g_active_mutex)

    if !exists {
        return
    }

    // Write data to SOCKS5 client
    protocol.write_all(active.socks_socket, data)
}

// Callback: session closed
bc_on_session_close :: proc(mux: ^protocol.Multiplexer, session_id: u32, reason: protocol.Session_Close_Reason) {
    if g_config.verbose {
        log.infof("Session %d closed: %v", session_id, reason)
    }

    // Remove from pending if still there
    sync.mutex_lock(&g_pending_mutex)
    if pending, exists := g_pending[session_id]; exists {
        net.close(pending.socks_socket)
        delete(pending.target_host)
        free(pending)
        delete_key(&g_pending, session_id)
    }
    sync.mutex_unlock(&g_pending_mutex)

    // Remove from active if there
    sync.mutex_lock(&g_active_mutex)
    if active, exists := g_active[session_id]; exists {
        net.close(active.socks_socket)
        free(active)
        delete_key(&g_active, session_id)
    }
    sync.mutex_unlock(&g_active_mutex)
}

// Callback: backconnect client disconnected
bc_on_disconnect :: proc(mux: ^protocol.Multiplexer) {
    // Client will be cleaned up in handle_bc_client_thread
}

// ============================================================================
// SOCKS5 Protocol (for dedicated per-client listeners)
// ============================================================================

socks_handshake :: proc(socket: net.TCP_Socket) -> bool {
    buf: [258]byte

    n, err := net.recv_tcp(socket, buf[:2])
    if err != nil || n != 2 {
        return false
    }

    if buf[0] != SOCKS_VERSION {
        return false
    }

    nmethods := int(buf[1])
    if nmethods > 0 {
        n, err = net.recv_tcp(socket, buf[:nmethods])
        if err != nil || n != nmethods {
            return false
        }
    }

    // Choose auth method
    chosen: byte = AUTH_NONE
    if g_config.socks_auth {
        supports_auth := false
        for i in 0..<nmethods {
            if buf[i] == AUTH_USERPASS {
                supports_auth = true
                break
            }
        }
        if !supports_auth {
            response := [2]byte{SOCKS_VERSION, 0xFF}
            net.send_tcp(socket, response[:])
            return false
        }
        chosen = AUTH_USERPASS
    }

    response := [2]byte{SOCKS_VERSION, chosen}
    _, send_err := net.send_tcp(socket, response[:])
    if send_err != nil {
        return false
    }

    if chosen == AUTH_USERPASS {
        return socks_authenticate(socket)
    }

    return true
}

socks_authenticate :: proc(socket: net.TCP_Socket) -> bool {
    buf: [512]byte

    n, err := net.recv_tcp(socket, buf[:1])
    if err != nil || n != 1 || buf[0] != 0x01 {
        return false
    }

    n, err = net.recv_tcp(socket, buf[:1])
    if err != nil || n != 1 {
        return false
    }
    ulen := int(buf[0])

    n, err = net.recv_tcp(socket, buf[:ulen])
    if err != nil || n != ulen {
        return false
    }
    username := strings.clone_from_bytes(buf[:ulen])
    defer delete(username)

    n, err = net.recv_tcp(socket, buf[:1])
    if err != nil || n != 1 {
        return false
    }
    plen := int(buf[0])

    n, err = net.recv_tcp(socket, buf[:plen])
    if err != nil || n != plen {
        return false
    }
    password := strings.clone_from_bytes(buf[:plen])
    defer delete(password)

    // Use constant-time comparison to prevent timing attacks
    auth_ok := constant_time_compare(username, g_config.socks_user) &&
               constant_time_compare(password, g_config.socks_pass)

    if g_config.verbose {
        log.infof("SOCKS5 authentication attempt: %s", auth_ok ? "success" : "failure")
    }

    response: [2]byte = {0x01, auth_ok ? 0x00 : 0x01}
    net.send_tcp(socket, response[:])

    return auth_ok
}

parse_socks_request :: proc(socket: net.TCP_Socket) -> (host: string, port: u16, cmd: byte, ok: bool) {
    buf: [263]byte

    n, err := net.recv_tcp(socket, buf[:4])
    if err != nil || n != 4 || buf[0] != SOCKS_VERSION {
        return "", 0, 0, false
    }

    cmd = buf[1]
    atyp := buf[3]

    port_bytes: [2]byte

    switch atyp {
    case ATYP_IPV4:
        n, err = net.recv_tcp(socket, buf[:6])
        if err != nil || n != 6 {
            return "", 0, 0, false
        }
        host = fmt.aprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
        port_bytes[0] = buf[4]
        port_bytes[1] = buf[5]

    case ATYP_DOMAIN:
        n, err = net.recv_tcp(socket, buf[:1])
        if err != nil || n != 1 {
            return "", 0, 0, false
        }
        domain_len := int(buf[0])

        n, err = net.recv_tcp(socket, buf[:domain_len + 2])
        if err != nil || n != domain_len + 2 {
            return "", 0, 0, false
        }
        host = strings.clone(string(buf[:domain_len]))
        port_bytes[0] = buf[domain_len]
        port_bytes[1] = buf[domain_len + 1]

    case ATYP_IPV6:
        // IPv6 not supported
        return "", 0, 0, false

    case:
        return "", 0, 0, false
    }

    port = u16(port_bytes[0]) << 8 | u16(port_bytes[1])
    return host, port, cmd, true
}

send_socks_reply :: proc(socket: net.TCP_Socket, reply_code: byte) {
    buf: [10]byte = {SOCKS_VERSION, reply_code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0}
    net.send_tcp(socket, buf[:])
}

// ============================================================================
// Argument Parsing
// ============================================================================

parse_args :: proc() {
    // Defaults
    g_config.bc_addr = "0.0.0.0:8443"
    g_config.socks_auth = false
    g_config.socks_user = "admin"
    g_config.socks_pass = "password"
    g_config.verbose = false
    g_config.otp_enabled = false
    g_config.allowed_psks = make([dynamic][protocol.PSK_SIZE]u8)

    // Generate server keypair
    crypto.rand_bytes(g_config.server_privkey[:])
    x25519.scalarmult_basepoint(g_config.server_pubkey[:], g_config.server_privkey[:])

    args := os.args[1:]
    psk_provided := false

    for i := 0; i < len(args); i += 1 {
        arg := args[i]

        switch arg {
        case "-socks-auth":
            g_config.socks_auth = true
        case "-socks-user":
            if i + 1 < len(args) {
                i += 1
                g_config.socks_user = args[i]
            }
        case "-socks-pass":
            if i + 1 < len(args) {
                i += 1
                g_config.socks_pass = args[i]
            }
        case "-bc-addr":
            if i + 1 < len(args) {
                i += 1
                g_config.bc_addr = args[i]
            }
        case "-bc-psk":
            if i + 1 < len(args) {
                i += 1
                psk: [protocol.PSK_SIZE]u8
                if !protocol.hex_to_bytes(args[i], psk[:]) {
                    fmt.eprintln("Error: Invalid PSK (must be 64 hex characters)")
                    os.exit(1)
                }
                // Store as master PSK for OTP generation
                g_config.master_psk = psk
                g_config.otp_enabled = true
                psk_provided = true
            }
        case "-no-otp":
            // Disable OTP mode, use raw PSK directly
            g_config.otp_enabled = false
        case "-v", "-verbose":
            g_config.verbose = true
        case "-print-pubkey":
            pubkey_hex := protocol.bytes_to_hex(g_config.server_pubkey[:])
            fmt.println(pubkey_hex)
            delete(pubkey_hex)
            os.exit(0)
        case "-h", "-help":
            print_help()
            os.exit(0)
        }
    }

    // Validate
    if !psk_provided {
        fmt.eprintln("Error: -bc-psk is required")
        os.exit(1)
    }

    // If OTP disabled, add raw PSK to allowed list
    if !g_config.otp_enabled {
        append(&g_config.allowed_psks, g_config.master_psk)
    }
    // If OTP enabled, allowed_psks will be populated by display_current_otp()
}

print_help :: proc() {
    fmt.println("Backconnect Server")
    fmt.println()
    fmt.println("Each connected client gets a dedicated SOCKS5 port (6000-8000).")
    fmt.println()
    fmt.println("Usage:")
    fmt.println("  backconnect_server -bc-psk <hex> [options]")
    fmt.println()
    fmt.println("Backconnect:")
    fmt.println("  -bc-addr <addr>     Listen address (default: 0.0.0.0:8443)")
    fmt.println("  -bc-psk <hex>       Master PSK (64 hex chars) - enables OTP mode")
    fmt.println("  -no-otp             Disable OTP mode, use raw PSK for auth")
    fmt.println()
    fmt.println("SOCKS5 Auth (for per-client ports):")
    fmt.println("  -socks-auth         Require authentication on SOCKS5 ports")
    fmt.println("  -socks-user <user>  Username (default: admin)")
    fmt.println("  -socks-pass <pass>  Password (default: password)")
    fmt.println()
    fmt.println("General:")
    fmt.println("  -v, -verbose        Enable verbose logging")
    fmt.println("  -print-pubkey       Print server public key and exit")
    fmt.println("  -h, -help           Show this help")
    fmt.println()
    fmt.println("OTP Mode (default):")
    fmt.println("  Server displays 8-char OTP (rotates every 4 hours).")
    fmt.println("  Clients connect using: -bc-otp <otp>")
    fmt.println()
    fmt.println("Example:")
    fmt.println("  backconnect_server -bc-psk $(openssl rand -hex 32)")
}
