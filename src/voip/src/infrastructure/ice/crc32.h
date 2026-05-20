// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
//
// CRC-32 (IEEE 802.3, polynomial 0xEDB88320 reversed) used by STUN
// FINGERPRINT (RFC 5389 §15.5). Standard table-based bytewise update.
//

#include <cstdint>
#include <cstddef>

namespace vianigram { namespace voip { namespace infrastructure { namespace ice {

class Crc32 {
public:
    // One-shot CRC-32 over `data`/`length`.
    static uint32_t Compute(const uint8_t* data, size_t length);
};

}}}} // namespace vianigram::voip::infrastructure::ice
