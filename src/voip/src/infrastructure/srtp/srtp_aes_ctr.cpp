// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "srtp_aes_ctr.h"

#include <vianium/crypto/aes_core.h>

#include <cstring>

namespace vianigram { namespace voip { namespace infrastructure { namespace srtp {

namespace {

// counter += 1, big-endian addition over the full 16 bytes.
inline void IncrementCounter(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i] != 0) return;  // no carry → done
    }
}

} // namespace

void SrtpAesCtr::Encrypt(const uint8_t key[16],
                         const uint8_t iv[16],
                         const uint8_t* in,
                         uint8_t* out,
                         size_t length)
{
    if (key == 0 || iv == 0 || (length != 0 && (in == 0 || out == 0))) return;

    vianium::crypto::AesKey aes;
    aes.Init(key, 16);  // AES-128

    uint8_t counter[16];
    std::memcpy(counter, iv, 16);

    uint8_t keystream[16];
    size_t produced = 0;
    while (produced < length) {
        aes.EncryptBlock(counter, keystream);

        size_t take = length - produced;
        if (take > 16) take = 16;
        for (size_t i = 0; i < take; ++i) {
            out[produced + i] = static_cast<uint8_t>(in[produced + i] ^ keystream[i]);
        }
        produced += take;

        IncrementCounter(counter);
    }
}

}}}} // namespace vianigram::voip::infrastructure::srtp
