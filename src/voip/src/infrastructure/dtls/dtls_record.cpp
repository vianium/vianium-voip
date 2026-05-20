// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// DTLS 1.2 record framing implementation.
#include "dtls_record.h"
#include <cstring>

namespace vianigram { namespace voip { namespace infrastructure { namespace dtls {

DtlsRecord::DtlsRecord()
    : type(kDtlsContentHandshake),
      version(kDtlsVersion12),
      epoch(0),
      sequenceNumber(0)
{
}

static inline void StoreBE16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline uint16_t LoadBE16(const uint8_t* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

// 48-bit big-endian sequence number
static inline void StoreBE48(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 40);
    p[1] = (uint8_t)(v >> 32);
    p[2] = (uint8_t)(v >> 24);
    p[3] = (uint8_t)(v >> 16);
    p[4] = (uint8_t)(v >> 8);
    p[5] = (uint8_t)v;
}

static inline uint64_t LoadBE48(const uint8_t* p) {
    return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) |
           ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) |
           ((uint64_t)p[4] << 8)  | (uint64_t)p[5];
}

std::vector<uint8_t> DtlsRecordCodec::Encode(const DtlsRecord& r) {
    std::vector<uint8_t> out;
    out.resize(kDtlsRecordHeaderSize + r.payload.size());

    out[0] = r.type;
    StoreBE16(&out[1], r.version);
    StoreBE16(&out[3], r.epoch);
    StoreBE48(&out[5], r.sequenceNumber & 0x0000FFFFFFFFFFFFULL);
    StoreBE16(&out[11], (uint16_t)r.payload.size());

    if (!r.payload.empty()) {
        std::memcpy(&out[kDtlsRecordHeaderSize], &r.payload[0], r.payload.size());
    }
    return out;
}

bool DtlsRecordCodec::Decode(const uint8_t* data, size_t size, DtlsRecord& out, size_t& consumed) {
    consumed = 0;
    if (data == 0 || size < kDtlsRecordHeaderSize) {
        return false;
    }

    out.type           = data[0];
    out.version        = LoadBE16(&data[1]);
    out.epoch          = LoadBE16(&data[3]);
    out.sequenceNumber = LoadBE48(&data[5]);

    uint16_t length = LoadBE16(&data[11]);
    if (size < kDtlsRecordHeaderSize + (size_t)length) {
        return false;
    }

    out.payload.assign(&data[kDtlsRecordHeaderSize], &data[kDtlsRecordHeaderSize + length]);
    consumed = kDtlsRecordHeaderSize + (size_t)length;
    return true;
}

size_t DtlsRecordCodec::PeekRecordSize(const uint8_t* data, size_t size) {
    if (data == 0 || size < kDtlsRecordHeaderSize) return 0;
    uint16_t length = LoadBE16(&data[11]);
    size_t total = kDtlsRecordHeaderSize + (size_t)length;
    if (total > size) return 0;
    return total;
}

}}}} // namespace vianigram::voip::infrastructure::dtls
