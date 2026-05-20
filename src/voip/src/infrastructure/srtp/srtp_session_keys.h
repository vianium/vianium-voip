// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// SRTP key derivation (RFC 3711 §4.3) for the
// SRTP_AES128_CM_HMAC_SHA1_80 profile (the WebRTC default and what we
// negotiate via DTLS-SRTP `use_srtp`).
//
// We implement the simple "KDR = 0" form: derive each session key once at
// session start by running AES-128-CTR over a label-tagged counter built from
// the master salt. RFC 3711 calls this `prf_n(k_master, key_id)` with
//
//   key_id = label_byte ^ salt[7]   (only label byte, since KDR = 0 contributes
//                                    zeroed bytes that are XORed with salt[8..])
//   x      = master_salt XOR key_id   (14 bytes wide, padded with two trailing
//                                      zero counter bytes to form the 16-byte
//                                      AES-CTR initial counter)
//
// The generated keystream is then truncated to the required key length:
//   - LABEL = 0x00 → session encryption key (16 bytes, AES-128)
//   - LABEL = 0x01 → session authentication key (20 bytes, HMAC-SHA1)
//   - LABEL = 0x02 → session salt (14 bytes, used in per-packet IV)
//
// We deliberately do NOT support label rotation / key derivation rate > 0:
// for a single call's lifetime one derivation suffices, which matches the
// libsrtp / WebRTC defaults and keeps this implementation small.

#include <cstdint>

namespace vianigram { namespace voip { namespace infrastructure { namespace srtp {

struct SrtpKeys {
    uint8_t MasterKey[16];   // 128-bit master key
    uint8_t MasterSalt[14];  // 112-bit master salt
};

class SrtpSessionKeys {
public:
    // out: 16-byte AES-128 session encryption key
    static void DeriveSessionEncrKey(const SrtpKeys& master, uint8_t out[16]);

    // out: 20-byte HMAC-SHA1 session authentication key
    static void DeriveSessionAuthKey(const SrtpKeys& master, uint8_t out[20]);

    // out: 14-byte session salt (used to build the per-packet IV)
    static void DeriveSessionSalt(const SrtpKeys& master, uint8_t out[14]);
};

}}}} // namespace vianigram::voip::infrastructure::srtp
