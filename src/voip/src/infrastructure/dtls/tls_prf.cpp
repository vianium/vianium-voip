// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// Wrapper around vianium::tls::TlsPrf — keeps Vianium.VoIP self-contained
// while reusing the audited TLS 1.2 PRF implementation.
#include "tls_prf.h"
#include <tls/tls_prf.h>

namespace vianigram { namespace voip { namespace infrastructure { namespace dtls {

std::vector<uint8_t> TlsPrf::Compute(const std::vector<uint8_t>& secret,
                                     const std::string& label,
                                     const std::vector<uint8_t>& seed,
                                     size_t length)
{
    std::vector<uint8_t> output(length, 0);
    if (length == 0) return output;

    const uint8_t* secPtr  = secret.empty()  ? 0 : &secret[0];
    const uint8_t* seedPtr = seed.empty()    ? 0 : &seed[0];

    vianium::tls::TlsPrf::Compute(secPtr, (int)secret.size(),
                                   label.c_str(),
                                   seedPtr, (int)seed.size(),
                                   (int)length, &output[0],
                                   /*useSha384=*/false);
    return output;
}

}}}} // namespace vianigram::voip::infrastructure::dtls
