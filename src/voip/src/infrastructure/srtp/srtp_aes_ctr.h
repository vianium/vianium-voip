// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// AES-128 in Counter (CTR) Mode — used by SRTP (RFC 3711) for both the key
// derivation function (KDF) and per-packet payload encryption.
//
// Construction:
//   Treat the supplied 16-byte IV as a 128-bit big-endian integer counter.
//   For block index b in [0..ceil(length / 16)):
//       counter_b = IV + b   (mod 2^128, big-endian addition)
//       keystream_b = AES_Encrypt_K(counter_b)
//   Output[i] = Input[i] XOR keystream[i].
//
// SRTP uses two specific counter shapes:
//   - KDF: the bottom 16 bits of the IV start at zero and are used as the
//     block counter. Always at most a few blocks.
//   - Packet encryption: the bottom 16 bits start at zero (per RFC 3711 §4.1.1)
//     and roll up as more keystream blocks are produced; this is exactly the
//     same behaviour as the generic CTR addition above.
//
// Because the counter increments through the entire 128-bit value, this
// implementation works for any length up to 2^32 * 16 bytes (more than enough
// for a single SRTP packet).
//
// Built on top of vianium::crypto::AesKey (linked source-level via the .vcxproj
// alongside aes_core.cpp from VianiumBrowser).

#include <cstdint>
#include <cstddef>

namespace vianigram { namespace voip { namespace infrastructure { namespace srtp {

class SrtpAesCtr {
public:
    // Encrypt (or decrypt — CTR is symmetric) `length` bytes from `in` to `out`
    // using the 16-byte AES-128 key and 16-byte initial counter. `in` and `out`
    // may alias (we read each block before writing it). `length` may be any
    // non-negative value, including not a multiple of 16.
    static void Encrypt(const uint8_t key[16],
                        const uint8_t iv[16],
                        const uint8_t* in,
                        uint8_t* out,
                        size_t length);
};

}}}} // namespace vianigram::voip::infrastructure::srtp
