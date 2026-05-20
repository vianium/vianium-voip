// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// DTLS 1.2 record framing (RFC 6347 §4.1).
//
// DTLS record on the wire (13-byte header + payload):
//
//   uint8  type
//   uint16 version    (0xFEFD for DTLS 1.2)
//   uint16 epoch
//   uint48 sequence_number
//   uint16 length
//   opaque fragment[length]
//
// Total header size: 13 bytes.
//
// Compared to TLS, DTLS adds the (epoch, sequence) pair so the receiver
// can detect lost / out-of-order datagrams without relying on TCP.

#include <cstdint>
#include <cstddef>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace dtls {

// DTLS record content types (same as TLS)
const uint8_t  kDtlsContentChangeCipherSpec = 20;
const uint8_t  kDtlsContentAlert            = 21;
const uint8_t  kDtlsContentHandshake        = 22;
const uint8_t  kDtlsContentApplicationData  = 23;

// Wire version for DTLS 1.2
const uint16_t kDtlsVersion12 = 0xFEFD;
const uint16_t kDtlsVersion10 = 0xFEFF;

// DTLS record header is 13 bytes
const size_t kDtlsRecordHeaderSize = 13;

struct DtlsRecord {
    uint8_t  type;            // see kDtlsContent* above
    uint16_t version;         // 0xFEFD for DTLS 1.2
    uint16_t epoch;           // increments on each ChangeCipherSpec
    uint64_t sequenceNumber;  // 48-bit value (top 16 bits MUST be zero on the wire)
    std::vector<uint8_t> payload; // length is implicit (payload.size())

    DtlsRecord();
};

class DtlsRecordCodec {
public:
    // Encode one record to a wire-format byte vector (13-byte header + payload).
    static std::vector<uint8_t> Encode(const DtlsRecord& r);

    // Decode one record starting at `data`.
    //   out:      filled with the parsed record on success.
    //   consumed: number of bytes read from `data` (always 13 + length on success).
    // Returns false if `size` is too small or the length field overruns the buffer.
    static bool Decode(const uint8_t* data, size_t size, DtlsRecord& out, size_t& consumed);

    // Helper: read the length field of a record without copying the payload.
    // Returns the total record size (header + payload), or 0 on parse error.
    static size_t PeekRecordSize(const uint8_t* data, size_t size);
};

}}}} // namespace vianigram::voip::infrastructure::dtls
