/*
   Crypto wrapper for backconnect protocol
   - X25519 for key exchange
   - ChaCha20-Poly1305 for authenticated encryption
   - SHA256 for key derivation
*/

package protocol

import "core:crypto"
import "core:crypto/x25519"
import "core:crypto/chacha20poly1305"
import "core:crypto/hash"
import "core:mem"

// Constants
PUBKEY_SIZE        :: 32
PRIVKEY_SIZE       :: 32
SHARED_SECRET_SIZE :: 32
PSK_SIZE           :: 32
NONCE_SIZE         :: 24  // XChaCha20 nonce for handshake
KEY_SIZE           :: 32
TAG_SIZE           :: 16
COUNTER_SIZE       :: 8   // 8-byte counter, padded to 12 for ChaCha20-Poly1305

// Crypto context for an encrypted session
Crypto_Context :: struct {
    // Local keypair
    local_private:  [PRIVKEY_SIZE]u8,
    local_public:   [PUBKEY_SIZE]u8,

    // Remote public key
    remote_public:  [PUBKEY_SIZE]u8,

    // Shared secret from X25519
    shared_secret:  [SHARED_SECRET_SIZE]u8,

    // Derived session keys (one per direction)
    send_key:       [KEY_SIZE]u8,
    recv_key:       [KEY_SIZE]u8,

    // Nonce counters (incremented per message)
    send_counter:   u64,
    recv_counter:   u64,

    // ChaCha20-Poly1305 contexts
    send_ctx:       chacha20poly1305.Context,
    recv_ctx:       chacha20poly1305.Context,

    // PSK for authentication
    psk:            [PSK_SIZE]u8,

    // Handshake nonce (used in key derivation)
    handshake_nonce: [NONCE_SIZE]u8,

    // State
    is_initialized: bool,
    keys_derived:   bool,
}

// Initialize crypto context with PSK
crypto_init :: proc(ctx: ^Crypto_Context, psk: [PSK_SIZE]u8) {
    mem.zero(ctx, size_of(Crypto_Context))
    ctx.psk = psk
    ctx.is_initialized = true
}

// Generate ephemeral keypair
crypto_generate_keypair :: proc(ctx: ^Crypto_Context) {
    // Generate random private key
    crypto.rand_bytes(ctx.local_private[:])

    // Derive public key
    x25519.scalarmult_basepoint(ctx.local_public[:], ctx.local_private[:])
}

// Set remote public key
crypto_set_remote_pubkey :: proc(ctx: ^Crypto_Context, pubkey: [PUBKEY_SIZE]u8) {
    ctx.remote_public = pubkey
}

// Perform X25519 key exchange and derive session keys
// is_initiator: true for client (who sends HANDSHAKE_RESP), false for server
crypto_derive_keys :: proc(ctx: ^Crypto_Context, nonce: [NONCE_SIZE]u8, is_initiator: bool) -> bool {
    if !ctx.is_initialized {
        return false
    }

    ctx.handshake_nonce = nonce

    // Compute shared secret via X25519
    x25519.scalarmult(ctx.shared_secret[:], ctx.local_private[:], ctx.remote_public[:])

    // Check for all-zero result (invalid point)
    all_zero := true
    for b in ctx.shared_secret {
        if b != 0 {
            all_zero = false
            break
        }
    }
    if all_zero {
        return false
    }

    // Derive directional keys using SHA256
    // Key = SHA256(shared_secret || nonce || direction || psk)
    derive_buf: [SHARED_SECRET_SIZE + NONCE_SIZE + 3 + PSK_SIZE]u8

    // Copy shared secret and nonce (use local copy for nonce since value params aren't addressable)
    nonce_local := nonce
    mem.copy(&derive_buf[0], &ctx.shared_secret[0], SHARED_SECRET_SIZE)
    mem.copy(&derive_buf[SHARED_SECRET_SIZE], &nonce_local[0], NONCE_SIZE)

    // Derive send key
    if is_initiator {
        copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE:], "c2s")
    } else {
        copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE:], "s2c")
    }
    copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE + 3:], ctx.psk[:])

    send_hash := hash.hash_bytes_to_buffer(.SHA256, derive_buf[:], ctx.send_key[:])

    // Derive recv key (opposite direction)
    if is_initiator {
        copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE:], "s2c")
    } else {
        copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE:], "c2s")
    }

    recv_hash := hash.hash_bytes_to_buffer(.SHA256, derive_buf[:], ctx.recv_key[:])

    // Initialize ChaCha20-Poly1305 contexts
    chacha20poly1305.init(&ctx.send_ctx, ctx.send_key[:])
    chacha20poly1305.init(&ctx.recv_ctx, ctx.recv_key[:])

    // Reset counters
    ctx.send_counter = 0
    ctx.recv_counter = 0

    ctx.keys_derived = true

    // Zero sensitive intermediate data
    mem.zero_explicit(&derive_buf, size_of(derive_buf))

    return true
}

// Build 12-byte nonce from 8-byte counter (padded with zeros)
@(private)
counter_to_nonce :: proc(counter: u64) -> [12]u8 {
    nonce: [12]u8
    // Little-endian counter in first 8 bytes
    nonce[0] = u8(counter)
    nonce[1] = u8(counter >> 8)
    nonce[2] = u8(counter >> 16)
    nonce[3] = u8(counter >> 24)
    nonce[4] = u8(counter >> 32)
    nonce[5] = u8(counter >> 40)
    nonce[6] = u8(counter >> 48)
    nonce[7] = u8(counter >> 56)
    // Bytes 8-11 are zero
    return nonce
}

// Encrypt message with ChaCha20-Poly1305
// Returns: counter (8 bytes) || ciphertext || tag (16 bytes)
// Caller must free returned slice
crypto_encrypt :: proc(ctx: ^Crypto_Context, plaintext: []u8, allocator := context.allocator) -> ([]u8, bool) {
    if !ctx.keys_derived {
        return nil, false
    }

    // Output: 8 bytes counter + len(plaintext) ciphertext + 16 bytes tag
    out_len := COUNTER_SIZE + len(plaintext) + TAG_SIZE
    output := make([]u8, out_len, allocator)

    // Write counter (little-endian)
    counter := ctx.send_counter
    output[0] = u8(counter)
    output[1] = u8(counter >> 8)
    output[2] = u8(counter >> 16)
    output[3] = u8(counter >> 24)
    output[4] = u8(counter >> 32)
    output[5] = u8(counter >> 40)
    output[6] = u8(counter >> 48)
    output[7] = u8(counter >> 56)

    // Build nonce from counter
    nonce := counter_to_nonce(counter)

    // Encrypt
    ciphertext := output[COUNTER_SIZE:COUNTER_SIZE + len(plaintext)]
    tag := output[COUNTER_SIZE + len(plaintext):]

    chacha20poly1305.seal(&ctx.send_ctx, ciphertext, tag, nonce[:], nil, plaintext)

    // Increment counter
    ctx.send_counter += 1

    return output, true
}

// Decrypt message with ChaCha20-Poly1305
// Input: counter (8 bytes) || ciphertext || tag (16 bytes)
// Returns plaintext, caller must free
crypto_decrypt :: proc(ctx: ^Crypto_Context, data: []u8, allocator := context.allocator) -> ([]u8, bool) {
    if !ctx.keys_derived {
        return nil, false
    }

    // Minimum size: 8 (counter) + 0 (empty payload) + 16 (tag) = 24
    if len(data) < COUNTER_SIZE + TAG_SIZE {
        return nil, false
    }

    // Extract counter (little-endian)
    counter := u64(data[0]) |
               u64(data[1]) << 8 |
               u64(data[2]) << 16 |
               u64(data[3]) << 24 |
               u64(data[4]) << 32 |
               u64(data[5]) << 40 |
               u64(data[6]) << 48 |
               u64(data[7]) << 56

    // Verify counter is not replayed (must be >= expected)
    if counter < ctx.recv_counter {
        return nil, false
    }

    // Build nonce from counter
    nonce := counter_to_nonce(counter)

    // Extract ciphertext and tag
    ciphertext_len := len(data) - COUNTER_SIZE - TAG_SIZE
    ciphertext := data[COUNTER_SIZE:COUNTER_SIZE + ciphertext_len]
    tag := data[COUNTER_SIZE + ciphertext_len:]

    // Allocate plaintext buffer
    plaintext := make([]u8, ciphertext_len, allocator)

    // Decrypt and verify
    if !chacha20poly1305.open(&ctx.recv_ctx, plaintext, nonce[:], nil, ciphertext, tag) {
        delete(plaintext)
        return nil, false
    }

    // Update expected counter
    ctx.recv_counter = counter + 1

    return plaintext, true
}

// Encrypt PSK for handshake (using XChaCha20-Poly1305 with handshake nonce)
// Used by client to prove knowledge of PSK
crypto_encrypt_psk :: proc(ctx: ^Crypto_Context, allocator := context.allocator) -> ([]u8, bool) {
    if !ctx.is_initialized {
        return nil, false
    }

    // First derive a temporary key from shared secret for PSK encryption
    // Key = SHA256(shared_secret || nonce || "psk")
    derive_buf: [SHARED_SECRET_SIZE + NONCE_SIZE + 3]u8
    copy(derive_buf[:SHARED_SECRET_SIZE], ctx.shared_secret[:])
    copy(derive_buf[SHARED_SECRET_SIZE:], ctx.handshake_nonce[:])
    copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE:], "psk")

    temp_key: [KEY_SIZE]u8
    hash.hash_bytes_to_buffer(.SHA256, derive_buf[:], temp_key[:])

    // Encrypt PSK with XChaCha20-Poly1305
    temp_ctx: chacha20poly1305.Context
    chacha20poly1305.init_xchacha(&temp_ctx, temp_key[:])

    // Output: ciphertext (32) + tag (16) = 48 bytes
    output := make([]u8, PSK_SIZE + TAG_SIZE, allocator)
    ciphertext := output[:PSK_SIZE]
    tag := output[PSK_SIZE:]

    chacha20poly1305.seal(&temp_ctx, ciphertext, tag, ctx.handshake_nonce[:], nil, ctx.psk[:])

    // Cleanup
    chacha20poly1305.reset(&temp_ctx)
    mem.zero_explicit(&temp_key, size_of(temp_key))
    mem.zero_explicit(&derive_buf, size_of(derive_buf))

    return output, true
}

// Decrypt and verify PSK from handshake
// Returns true if PSK matches
crypto_verify_psk :: proc(ctx: ^Crypto_Context, encrypted_psk: []u8, expected_psks: [][PSK_SIZE]u8) -> bool {
    if len(encrypted_psk) != PSK_SIZE + TAG_SIZE {
        return false
    }

    // Derive temporary key (same as encrypt)
    derive_buf: [SHARED_SECRET_SIZE + NONCE_SIZE + 3]u8
    copy(derive_buf[:SHARED_SECRET_SIZE], ctx.shared_secret[:])
    copy(derive_buf[SHARED_SECRET_SIZE:], ctx.handshake_nonce[:])
    copy(derive_buf[SHARED_SECRET_SIZE + NONCE_SIZE:], "psk")

    temp_key: [KEY_SIZE]u8
    hash.hash_bytes_to_buffer(.SHA256, derive_buf[:], temp_key[:])

    temp_ctx: chacha20poly1305.Context
    chacha20poly1305.init_xchacha(&temp_ctx, temp_key[:])

    ciphertext := encrypted_psk[:PSK_SIZE]
    tag := encrypted_psk[PSK_SIZE:]

    decrypted_psk: [PSK_SIZE]u8
    ok := chacha20poly1305.open(&temp_ctx, decrypted_psk[:], ctx.handshake_nonce[:], nil, ciphertext, tag)

    chacha20poly1305.reset(&temp_ctx)
    mem.zero_explicit(&temp_key, size_of(temp_key))
    mem.zero_explicit(&derive_buf, size_of(derive_buf))

    if !ok {
        return false
    }

    // Check against allowed PSKs
    for &psk in expected_psks {
        // Manual constant-time comparison
        diff: u8 = 0
        for i in 0..<PSK_SIZE {
            diff |= decrypted_psk[i] ~ psk[i]
        }
        if diff == 0 {
            // Store the matched PSK in context for key derivation
            ctx.psk = psk
            mem.zero_explicit(&decrypted_psk, size_of(decrypted_psk))
            return true
        }
    }

    mem.zero_explicit(&decrypted_psk, size_of(decrypted_psk))
    return false
}

// Zero all sensitive data in context
crypto_wipe :: proc(ctx: ^Crypto_Context) {
    if ctx.keys_derived {
        chacha20poly1305.reset(&ctx.send_ctx)
        chacha20poly1305.reset(&ctx.recv_ctx)
    }
    mem.zero_explicit(ctx, size_of(Crypto_Context))
}

// Generate random nonce for handshake
crypto_generate_nonce :: proc() -> [NONCE_SIZE]u8 {
    nonce: [NONCE_SIZE]u8
    crypto.rand_bytes(nonce[:])
    return nonce
}

// Parse hex string to bytes (for PSK input)
// Returns false if invalid hex or wrong length
hex_to_bytes :: proc(hex_str: string, out: []u8) -> bool {
    if len(hex_str) != len(out) * 2 {
        return false
    }

    hex_char_to_val :: proc(c: u8) -> (u8, bool) {
        switch c {
        case '0'..='9': return c - '0', true
        case 'a'..='f': return c - 'a' + 10, true
        case 'A'..='F': return c - 'A' + 10, true
        }
        return 0, false
    }

    for i := 0; i < len(out); i += 1 {
        high, ok1 := hex_char_to_val(hex_str[i*2])
        low, ok2 := hex_char_to_val(hex_str[i*2 + 1])
        if !ok1 || !ok2 {
            return false
        }
        out[i] = (high << 4) | low
    }

    return true
}

// Convert bytes to hex string
bytes_to_hex :: proc(data: []u8, allocator := context.allocator) -> string {
    hex_chars := "0123456789abcdef"
    result := make([]u8, len(data) * 2, allocator)

    for i := 0; i < len(data); i += 1 {
        result[i*2] = hex_chars[data[i] >> 4]
        result[i*2 + 1] = hex_chars[data[i] & 0x0f]
    }

    return string(result)
}
