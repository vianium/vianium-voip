// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "crc32.h"

namespace vianigram { namespace voip { namespace infrastructure { namespace ice {

namespace {

// Lazily-built reflected CRC-32 table for polynomial 0xEDB88320.
struct Crc32Table {
    uint32_t v[256];
    Crc32Table() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int j = 0; j < 8; ++j) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            v[i] = c;
        }
    }
};

const Crc32Table& Table() {
    static Crc32Table t;
    return t;
}

} // namespace

uint32_t Crc32::Compute(const uint8_t* data, size_t length) {
    const Crc32Table& tbl = Table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; ++i) {
        c = tbl.v[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

}}}} // namespace vianigram::voip::infrastructure::ice
