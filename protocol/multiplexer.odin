/*
   Session multiplexer for backconnect protocol

   Handles multiple concurrent SOCKS5 sessions over a single encrypted connection.
   Uses a thread-per-direction model with message queuing.
*/

package protocol

import "core:net"
import "core:sync"
import "core:thread"
import "core:time"
import "core:mem"
import "core:fmt"

// Session states
Session_State :: enum {
    PENDING,     // Waiting for target connection
    ACTIVE,      // Connected and relaying
    CLOSING,     // Shutdown in progress
    CLOSED,      // Session ended
}

// A multiplexed session
Mux_Session :: struct {
    id:            u32,
    state:         Session_State,
    target_host:   string,
    target_port:   u16,
    target_socket: Maybe(net.TCP_Socket),

    // For server: the SOCKS5 client socket
    client_socket: Maybe(net.TCP_Socket),

    // Data queues
    send_queue:    [dynamic][]u8,  // Data to send to remote
    send_mutex:    sync.Mutex,

    // Timestamps
    created_at:    time.Time,
    last_active:   time.Time,

    // Stats
    bytes_sent:    u64,
    bytes_recv:    u64,
}

// Multiplexer manages sessions over a single connection
Multiplexer :: struct {
    socket:         net.TCP_Socket,
    crypto:         ^Crypto_Context,

    // Session management
    sessions:       map[u32]^Mux_Session,
    next_session_id: u32,
    session_mutex:  sync.Mutex,

    // Outbound message queue
    send_queue:     [dynamic][]u8,
    send_mutex:     sync.Mutex,

    // State
    is_running:     bool,
    should_stop:    bool,
    last_ping:      time.Time,
    last_pong:      time.Time,

    // Threads
    reader_thread:  Maybe(^thread.Thread),
    writer_thread:  Maybe(^thread.Thread),
    keepalive_thread: Maybe(^thread.Thread),

    // Callbacks (set by client/server)
    on_session_new:   proc(mux: ^Multiplexer, session_id: u32, host: string, port: u16),
    on_session_ready: proc(mux: ^Multiplexer, session_id: u32, status: Session_Ready_Status),
    on_session_data:  proc(mux: ^Multiplexer, session_id: u32, data: []u8),
    on_session_close: proc(mux: ^Multiplexer, session_id: u32, reason: Session_Close_Reason),
    on_ping:          proc(mux: ^Multiplexer, timestamp: u64),
    on_pong:          proc(mux: ^Multiplexer, timestamp: u64),
    on_disconnect:    proc(mux: ^Multiplexer),
    on_error:         proc(mux: ^Multiplexer, msg: string),
    on_port_assigned: proc(mux: ^Multiplexer, port: u16),

    // User data pointer for callbacks
    user_data:      rawptr,

    // Debug output (disabled by default)
    verbose:        bool,
}

// Keepalive settings
PING_INTERVAL :: 30 * time.Second
PING_TIMEOUT  :: 10 * time.Second

// Create a new multiplexer
mux_create :: proc(socket: net.TCP_Socket, crypto: ^Crypto_Context) -> ^Multiplexer {
    mux := new(Multiplexer)
    mux.socket = socket
    mux.crypto = crypto
    mux.sessions = make(map[u32]^Mux_Session)
    mux.send_queue = make([dynamic][]u8)
    mux.next_session_id = 1  // 0 is reserved for control
    mux.is_running = false
    mux.should_stop = false
    mux.last_ping = time.now()
    mux.last_pong = time.now()
    return mux
}

// Start multiplexer threads
mux_start :: proc(mux: ^Multiplexer) {
    if mux.is_running {
        return
    }

    mux.is_running = true
    mux.should_stop = false

    // Start reader thread
    mux.reader_thread = thread.create_and_start_with_poly_data(mux, mux_reader_proc)

    // Start writer thread
    mux.writer_thread = thread.create_and_start_with_poly_data(mux, mux_writer_proc)

    // Start keepalive thread
    mux.keepalive_thread = thread.create_and_start_with_poly_data(mux, mux_keepalive_proc)
}

// Stop multiplexer and cleanup
mux_stop :: proc(mux: ^Multiplexer) {
    if !mux.is_running {
        return
    }

    mux.should_stop = true
    mux.is_running = false

    // Close socket to unblock reader
    net.close(mux.socket)

    // Wait for threads
    if t, ok := mux.reader_thread.?; ok {
        thread.join(t)
        thread.destroy(t)
    }
    if t, ok := mux.writer_thread.?; ok {
        thread.join(t)
        thread.destroy(t)
    }
    if t, ok := mux.keepalive_thread.?; ok {
        thread.join(t)
        thread.destroy(t)
    }

    // Cleanup sessions
    sync.mutex_lock(&mux.session_mutex)
    for _, session in mux.sessions {
        mux_session_cleanup(session)
    }
    delete(mux.sessions)
    sync.mutex_unlock(&mux.session_mutex)

    // Cleanup send queue
    sync.mutex_lock(&mux.send_mutex)
    for msg in mux.send_queue {
        delete(msg)
    }
    delete(mux.send_queue)
    sync.mutex_unlock(&mux.send_mutex)
}

// Destroy multiplexer
mux_destroy :: proc(mux: ^Multiplexer) {
    mux_stop(mux)
    free(mux)
}

// Create a new session (called by server to create outbound request)
mux_session_create :: proc(mux: ^Multiplexer, host: string, port: u16) -> u32 {
    sync.mutex_lock(&mux.session_mutex)
    defer sync.mutex_unlock(&mux.session_mutex)

    session := new(Mux_Session)
    session.id = mux.next_session_id
    mux.next_session_id += 1

    session.state = .PENDING
    session.target_host = host
    session.target_port = port
    session.created_at = time.now()
    session.last_active = time.now()
    session.send_queue = make([dynamic][]u8)

    mux.sessions[session.id] = session

    return session.id
}

// Get session by ID
mux_session_get :: proc(mux: ^Multiplexer, session_id: u32) -> Maybe(^Mux_Session) {
    sync.mutex_lock(&mux.session_mutex)
    defer sync.mutex_unlock(&mux.session_mutex)

    if session, ok := mux.sessions[session_id]; ok {
        return session
    }
    return nil
}

// Send data on a session
mux_session_send :: proc(mux: ^Multiplexer, session_id: u32, data: []u8) -> bool {
    // Build SESSION_DATA message
    payload := make([]u8, len(data))
    copy(payload, data)

    msg := frame_encode(.SESSION_DATA, session_id, payload)
    delete(payload)

    return mux_queue_send(mux, msg)
}

// Close a session
mux_session_close :: proc(mux: ^Multiplexer, session_id: u32, reason: Session_Close_Reason) {
    sync.mutex_lock(&mux.session_mutex)
    session, exists := mux.sessions[session_id]
    if !exists {
        sync.mutex_unlock(&mux.session_mutex)
        return
    }

    if session.state == .CLOSED {
        sync.mutex_unlock(&mux.session_mutex)
        return
    }

    session.state = .CLOSING
    sync.mutex_unlock(&mux.session_mutex)

    // Send close message
    payload := build_session_close(reason)
    msg := frame_encode(.SESSION_CLOSE, session_id, payload)
    delete(payload)
    mux_queue_send(mux, msg)

    // Cleanup session
    sync.mutex_lock(&mux.session_mutex)
    session.state = .CLOSED
    mux_session_cleanup(session)
    delete_key(&mux.sessions, session_id)
    sync.mutex_unlock(&mux.session_mutex)
}

// Internal: cleanup session resources
@(private)
mux_session_cleanup :: proc(session: ^Mux_Session) {
    if socket, ok := session.target_socket.?; ok {
        net.close(socket)
    }
    if socket, ok := session.client_socket.?; ok {
        net.close(socket)
    }

    sync.mutex_lock(&session.send_mutex)
    for msg in session.send_queue {
        delete(msg)
    }
    delete(session.send_queue)
    sync.mutex_unlock(&session.send_mutex)

    free(session)
}

// Queue a message for sending
mux_queue_send :: proc(mux: ^Multiplexer, msg: []u8) -> bool {
    if !mux.is_running {
        if mux.verbose {
            fmt.printf("[MUX] queue_send: mux not running, dropping message (len=%d)\n", len(msg))
        }
        delete(msg)
        return false
    }

    if mux.verbose && len(msg) >= 5 {
        msg_type := Message_Type(msg[0])
        session_id := u32(msg[1]) << 24 | u32(msg[2]) << 16 | u32(msg[3]) << 8 | u32(msg[4])
        fmt.printf("[MUX] queue_send: type=%v, session=%d, len=%d\n", msg_type, session_id, len(msg))
    }

    sync.mutex_lock(&mux.send_mutex)
    append(&mux.send_queue, msg)
    sync.mutex_unlock(&mux.send_mutex)
    return true
}

// Send SESSION_NEW message
mux_send_session_new :: proc(mux: ^Multiplexer, session_id: u32, atyp: Address_Type, addr: []u8, port: u16) -> bool {
    payload := build_session_new(atyp, addr, port)
    msg := frame_encode(.SESSION_NEW, session_id, payload)
    delete(payload)
    return mux_queue_send(mux, msg)
}

// Send SESSION_READY message
mux_send_session_ready :: proc(mux: ^Multiplexer, session_id: u32, status: Session_Ready_Status) -> bool {
    payload := build_session_ready(status)
    msg := frame_encode(.SESSION_READY, session_id, payload)
    delete(payload)
    return mux_queue_send(mux, msg)
}

// Send PING
mux_send_ping :: proc(mux: ^Multiplexer) -> bool {
    timestamp := u64(time.now()._nsec)
    payload := build_ping_pong(timestamp)
    msg := frame_encode(.PING, SESSION_ID_CONTROL, payload)
    delete(payload)

    mux.last_ping = time.now()
    return mux_queue_send(mux, msg)
}

// Send PONG
mux_send_pong :: proc(mux: ^Multiplexer, timestamp: u64) -> bool {
    payload := build_ping_pong(timestamp)
    msg := frame_encode(.PONG, SESSION_ID_CONTROL, payload)
    delete(payload)
    return mux_queue_send(mux, msg)
}

// Send DISCONNECT
mux_send_disconnect :: proc(mux: ^Multiplexer) -> bool {
    msg := frame_encode(.DISCONNECT, SESSION_ID_CONTROL, nil)
    return mux_queue_send(mux, msg)
}

// Reader thread - reads messages from socket and dispatches
@(private)
mux_reader_proc :: proc(mux: ^Multiplexer) {
    if mux.verbose {
        fmt.printf("[MUX] Reader thread started\n")
    }
    for !mux.should_stop {
        // Read encrypted message
        data, ok := frame_read_encrypted(mux.socket, mux.crypto)
        if !ok {
            if mux.verbose {
                fmt.printf("[MUX] Reader: frame_read_encrypted failed\n")
            }
            if !mux.should_stop {
                if mux.on_disconnect != nil {
                    mux.on_disconnect(mux)
                }
            }
            break
        }

        // Decode message
        msg_type, session_id, _, decode_ok := frame_decode(data)
        if !decode_ok {
            if mux.verbose {
                fmt.printf("[MUX] Reader: frame_decode failed\n")
            }
            delete(data)
            continue
        }

        if mux.verbose {
            fmt.printf("[MUX] Reader received: type=%v, session=%d, len=%d\n", msg_type, session_id, len(data))
        }

        payload := get_payload(data)

        // Dispatch based on message type
        switch msg_type {
        case .SESSION_NEW:
            if mux.on_session_new != nil {
                atyp, addr, port, parse_ok := parse_session_new(payload)
                if parse_ok {
                    // Convert addr to string based on atyp
                    host: string
                    switch atyp {
                    case .IPV4:
                        if len(addr) == 4 {
                            host = fmt_ipv4(addr)
                        }
                    case .DOMAIN:
                        host = string(addr)
                    case .IPV6:
                        if len(addr) == 16 {
                            host = fmt_ipv6(addr)
                        }
                    }
                    if len(host) > 0 {
                        mux.on_session_new(mux, session_id, host, port)
                    }
                }
            }

        case .SESSION_READY:
            if mux.on_session_ready != nil {
                status, parse_ok := parse_session_ready(payload)
                if parse_ok {
                    mux.on_session_ready(mux, session_id, status)
                }
            }

        case .SESSION_DATA:
            if mux.on_session_data != nil {
                mux.on_session_data(mux, session_id, payload)
            }

        case .SESSION_CLOSE:
            reason, _ := parse_session_close(payload)
            if mux.on_session_close != nil {
                mux.on_session_close(mux, session_id, reason)
            }
            // Remove session
            sync.mutex_lock(&mux.session_mutex)
            if session, exists := mux.sessions[session_id]; exists {
                session.state = .CLOSED
                mux_session_cleanup(session)
                delete_key(&mux.sessions, session_id)
            }
            sync.mutex_unlock(&mux.session_mutex)

        case .PING:
            timestamp, parse_ok := parse_ping_pong(payload)
            if parse_ok {
                mux_send_pong(mux, timestamp)
                if mux.on_ping != nil {
                    mux.on_ping(mux, timestamp)
                }
            }

        case .PONG:
            mux.last_pong = time.now()
            timestamp, parse_ok := parse_ping_pong(payload)
            if parse_ok && mux.on_pong != nil {
                mux.on_pong(mux, timestamp)
            }

        case .DISCONNECT:
            if mux.on_disconnect != nil {
                mux.on_disconnect(mux)
            }
            mux.should_stop = true

        case .ERROR:
            if mux.on_error != nil {
                mux.on_error(mux, string(payload))
            }

        case .PORT_ASSIGNED:
            if mux.on_port_assigned != nil {
                port, parse_ok := parse_port_assigned(payload)
                if parse_ok {
                    mux.on_port_assigned(mux, port)
                }
            }

        case .HANDSHAKE_INIT, .HANDSHAKE_RESP, .HANDSHAKE_ACK:
            // These shouldn't appear after handshake - ignore
        }

        delete(data)
    }
}

// Writer thread - sends queued messages
@(private)
mux_writer_proc :: proc(mux: ^Multiplexer) {
    if mux.verbose {
        fmt.printf("[MUX] Writer thread started\n")
    }
    for !mux.should_stop {
        // Check for messages to send
        msg: Maybe([]u8) = nil

        sync.mutex_lock(&mux.send_mutex)
        if len(mux.send_queue) > 0 {
            msg = pop_front(&mux.send_queue)
        }
        sync.mutex_unlock(&mux.send_mutex)

        if data, ok := msg.?; ok {
            // Log what we're sending
            if mux.verbose && len(data) >= 5 {
                msg_type := Message_Type(data[0])
                session_id := u32(data[1]) << 24 | u32(data[2]) << 16 | u32(data[3]) << 8 | u32(data[4])
                fmt.printf("[MUX] Writer sending: type=%v, session=%d, len=%d\n", msg_type, session_id, len(data))
            }
            // Send encrypted
            if !frame_write_encrypted(mux.socket, mux.crypto, data) {
                if mux.verbose {
                    fmt.printf("[MUX] Writer: frame_write_encrypted failed\n")
                }
                delete(data)
                if !mux.should_stop && mux.on_disconnect != nil {
                    mux.on_disconnect(mux)
                }
                break
            }
            if mux.verbose {
                fmt.printf("[MUX] Writer: sent successfully\n")
            }
            delete(data)
        } else {
            // No messages, sleep briefly
            time.sleep(1 * time.Millisecond)
        }
    }
    if mux.verbose {
        fmt.printf("[MUX] Writer thread exiting\n")
    }
}

// Keepalive thread - sends periodic pings
@(private)
mux_keepalive_proc :: proc(mux: ^Multiplexer) {
    for !mux.should_stop {
        time.sleep(1 * time.Second)

        if mux.should_stop {
            break
        }

        // Check if we need to send a ping
        since_ping := time.diff(mux.last_ping, time.now())
        if since_ping >= PING_INTERVAL {
            mux_send_ping(mux)
        }

        // Check for ping timeout
        since_pong := time.diff(mux.last_pong, time.now())
        if since_pong >= PING_INTERVAL + PING_TIMEOUT {
            // Connection timed out
            if mux.on_disconnect != nil {
                mux.on_disconnect(mux)
            }
            mux.should_stop = true
            break
        }
    }
}

// Helper: format IPv4 address
@(private)
fmt_ipv4 :: proc(addr: []u8) -> string {
    if len(addr) != 4 {
        return ""
    }
    buf := make([]u8, 16)
    n := 0

    write_byte :: proc(buf: []u8, n: ^int, b: u8) {
        if b >= 100 {
            buf[n^] = '0' + b / 100
            n^ += 1
        }
        if b >= 10 {
            buf[n^] = '0' + (b / 10) % 10
            n^ += 1
        }
        buf[n^] = '0' + b % 10
        n^ += 1
    }

    write_byte(buf, &n, addr[0])
    buf[n] = '.'
    n += 1
    write_byte(buf, &n, addr[1])
    buf[n] = '.'
    n += 1
    write_byte(buf, &n, addr[2])
    buf[n] = '.'
    n += 1
    write_byte(buf, &n, addr[3])

    result := make([]u8, n)
    copy(result, buf[:n])
    delete(buf)
    return string(result)
}

// Helper: format IPv6 address (simplified)
@(private)
fmt_ipv6 :: proc(addr: []u8) -> string {
    if len(addr) != 16 {
        return ""
    }
    hex := "0123456789abcdef"
    buf := make([]u8, 39)  // xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
    n := 0

    for i := 0; i < 16; i += 2 {
        if i > 0 {
            buf[n] = ':'
            n += 1
        }
        buf[n] = hex[addr[i] >> 4]
        n += 1
        buf[n] = hex[addr[i] & 0x0f]
        n += 1
        buf[n] = hex[addr[i+1] >> 4]
        n += 1
        buf[n] = hex[addr[i+1] & 0x0f]
        n += 1
    }

    result := make([]u8, n)
    copy(result, buf[:n])
    delete(buf)
    return string(result)
}

