// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// Thin wrapper around vianium::tls::TlsPrf so DtlsClientSession code can
// stay self-contained inside Vianium.VoIP without re-importing the TLS
// project's full namespace surface.
//
// TLS 1.2 PRF (RFC 5246 §5):
//   PRF(secret, label, seed) = P_<hash>(secret, label || seed)
//
// where P_hash is the standard HMAC chain:
//   A(0) = label || seed
//   A(i) = HMAC(secret, A(i-1))
//   PRF  = HMAC(secret, A(1) || label || seed)
//        || HMAC(secret, A(2) || label || seed) || ...
//
// We only ever use HMAC-SHA-256 here — DTLS-SRTP cipher suites with the
// _SHA256 suffix are mandatory to support, and that's what tgcalls picks.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace dtls {

class TlsPrf {
public:
    // PRF(secret, label, seed) -> `length` bytes (HMAC-SHA-256).
    static std::vector<uint8_t> Compute(const std::vector<uint8_t>& secret,
                                        const std::string& label,
                                        const std::vector<uint8_t>& seed,
                                        size_t length);
};

}}}} // namespace vianigram::voip::infrastructure::dtls
