// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// SRTP key derivation function (KDF) — RFC 3711 §4.3.
//
// All three label-driven derivations share the same shape; only the label
// byte and output length differ. We build the 16-byte AES-CTR counter as:
//
//   counter[0..14)  = master_salt XOR salt_xor_pattern
//   counter[14..16) = 0x00 0x00         (block counter starts at zero)
//
// where salt_xor_pattern is 14 bytes wide and contains the LABEL byte at
// offset 7 with all other bytes zeroed. (Per RFC 3711 §4.3.1 the salt is
// XORed with `(label || index)` after a left-shift; with KDR = 0 the index
// term is zero and the label sits at offset 7.)

#include "srtp_session_keys.h"
#include "srtp_aes_ctr.h"

#include <cstring>

namespace vianigram { namespace voip { namespace infrastructure { namespace srtp {

namespace {

const uint8_t kLabelEncryption     = 0x00;
const uint8_t kLabelAuthentication = 0x01;
const uint8_t kLabelSalt           = 0x02;

// Build the 16-byte AES-CTR counter for KDF derivation.
// counter[0..14) = master_salt XOR (00...00 LABEL 00...00) where LABEL sits at index 7
// counter[14..16) = 0x00 0x00
void BuildKdfCounter(const SrtpKeys& master, uint8_t label, uint8_t counter[16]) {
    std::memcpy(counter, master.MasterSalt, 14);
    counter[7] = static_cast<uint8_t>(counter[7] ^ label);  // XOR label into byte 7
    counter[14] = 0;
    counter[15] = 0;
}

// Generate `len` bytes of keystream using the master key and a label-tagged counter.
void DeriveBytes(const SrtpKeys& master, uint8_t label, uint8_t* out, size_t len) {
    uint8_t counter[16];
    BuildKdfCounter(master, label, counter);

    // CTR keystream = AES-CTR(master_key, counter) XOR zeros == AES-CTR(master_key, counter)
    // We feed an all-zero plaintext so the output is the raw keystream.
    static const uint8_t zero[32] = {0};
    if (len <= sizeof(zero)) {
        SrtpAesCtr::Encrypt(master.MasterKey, counter, zero, out, len);
    } else {
        // No SRTP KDF output is larger than 20 bytes for our profile, but be defensive.
        size_t produced = 0;
        while (produced < len) {
            size_t take = len - produced;
            if (take > sizeof(zero)) take = sizeof(zero);
            SrtpAesCtr::Encrypt(master.MasterKey, counter, zero, out + produced, take);
            // Advance counter manually by `take/16` blocks; for our use we never hit this branch.
            // Round up to next block boundary.
            size_t blocks = (take + 15) / 16;
            for (size_t b = 0; b < blocks; ++b) {
                for (int i = 15; i >= 0; --i) {
                    if (++counter[i] != 0) break;
                }
            }
            produced += take;
        }
    }
}

} // namespace

void SrtpSessionKeys::DeriveSessionEncrKey(const SrtpKeys& master, uint8_t out[16]) {
    DeriveBytes(master, kLabelEncryption, out, 16);
}

void SrtpSessionKeys::DeriveSessionAuthKey(const SrtpKeys& master, uint8_t out[20]) {
    DeriveBytes(master, kLabelAuthentication, out, 20);
}

void SrtpSessionKeys::DeriveSessionSalt(const SrtpKeys& master, uint8_t out[14]) {
    DeriveBytes(master, kLabelSalt, out, 14);
}

}}}} // namespace vianigram::voip::infrastructure::srtp
