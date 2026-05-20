// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "srtp_packet_codec.h"
#include "srtp_aes_ctr.h"

#include <vianium/crypto/hmac.h>

#include <cstring>

namespace vianigram { namespace voip { namespace infrastructure { namespace srtp {

namespace {

const size_t kRtpFixedHeaderSize = 12;

// Parse the RTP header on `bytes` of length `len` and return the offset where
// the payload begins, or 0 if the header is malformed. RTP header layout:
//
//   byte[0]   V(2) | P(1) | X(1) | CC(4)
//   byte[1]   M(1) | PT(7)
//   bytes[2..4]   sequence_number (BE)
//   bytes[4..8]   timestamp (BE)
//   bytes[8..12]  SSRC (BE)
//   bytes[12..12+4*CC]  CSRC list
//   if X bit:  4-byte ext header + ext_length (in 32-bit words) * 4 bytes
size_t LocatePayloadStart(const uint8_t* bytes, size_t len) {
    if (len < kRtpFixedHeaderSize) return 0;
    uint8_t b0 = bytes[0];
    uint8_t version = static_cast<uint8_t>(b0 >> 6);
    if (version != 2) return 0;
    uint8_t cc = static_cast<uint8_t>(b0 & 0x0F);
    bool extensionPresent = (b0 & 0x10) != 0;

    size_t offset = kRtpFixedHeaderSize + (size_t)cc * 4;
    if (offset > len) return 0;

    if (extensionPresent) {
        if (offset + 4 > len) return 0;
        uint16_t extLengthWords = static_cast<uint16_t>((bytes[offset + 2] << 8) | bytes[offset + 3]);
        size_t extBytes = (size_t)extLengthWords * 4;
        offset += 4 + extBytes;
        if (offset > len) return 0;
    }

    return offset;
}

// Build the 16-byte AES-CTR IV per RFC 3711 §4.1.1:
//   iv = (salt || 00 00) XOR ((SSRC << 64) | (index << 16))
//
// Concretely, byte by byte (MSB first), the right-hand value when laid out as
// 16 bytes is:
//   [0..4)  : 0
//   [4..8)  : SSRC (big-endian)
//   [8..14) : 48-bit packet index (big-endian)
//   [14..16): 0
// XOR that pattern with `salt[0..14] || 00 00` to get the IV.
void BuildPacketIv(const uint8_t salt[14],
                   uint32_t ssrc,
                   uint64_t packetIndex48,
                   uint8_t outIv[16])
{
    std::memset(outIv, 0, 16);

    outIv[4] = static_cast<uint8_t>((ssrc >> 24) & 0xFF);
    outIv[5] = static_cast<uint8_t>((ssrc >> 16) & 0xFF);
    outIv[6] = static_cast<uint8_t>((ssrc >>  8) & 0xFF);
    outIv[7] = static_cast<uint8_t>( ssrc        & 0xFF);

    outIv[8]  = static_cast<uint8_t>((packetIndex48 >> 40) & 0xFF);
    outIv[9]  = static_cast<uint8_t>((packetIndex48 >> 32) & 0xFF);
    outIv[10] = static_cast<uint8_t>((packetIndex48 >> 24) & 0xFF);
    outIv[11] = static_cast<uint8_t>((packetIndex48 >> 16) & 0xFF);
    outIv[12] = static_cast<uint8_t>((packetIndex48 >>  8) & 0xFF);
    outIv[13] = static_cast<uint8_t>( packetIndex48        & 0xFF);

    // XOR with salt (14 bytes; bottom two bytes [14..16] stay zero).
    for (size_t i = 0; i < 14; ++i) outIv[i] = static_cast<uint8_t>(outIv[i] ^ salt[i]);
}

// Compute HMAC-SHA1 over (packet || ROC big-endian) and write the first
// `kAuthTagSize` bytes of the digest to `outTag`.
void ComputeAuthTag(const uint8_t authKey[20],
                    const uint8_t* packet,
                    size_t packetLen,
                    uint32_t roc,
                    uint8_t outTag[10])
{
    vianium::crypto::HmacSha1 hmac;
    hmac.Init(authKey, 20);
    hmac.Update(packet, packetLen);

    uint8_t rocBe[4];
    rocBe[0] = static_cast<uint8_t>((roc >> 24) & 0xFF);
    rocBe[1] = static_cast<uint8_t>((roc >> 16) & 0xFF);
    rocBe[2] = static_cast<uint8_t>((roc >>  8) & 0xFF);
    rocBe[3] = static_cast<uint8_t>( roc        & 0xFF);
    hmac.Update(rocBe, 4);

    uint8_t digest[vianium::crypto::HmacSha1::MAC_SIZE];
    hmac.Final(digest);

    std::memcpy(outTag, digest, SrtpPacketCodec::kAuthTagSize);
}

bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

} // namespace

std::vector<uint8_t> SrtpPacketCodec::Encrypt(SrtpEncryptParams& params,
                                              const std::vector<uint8_t>& rtp,
                                              uint16_t sequenceNumber)
{
    if (rtp.empty()) return std::vector<uint8_t>();

    size_t payloadStart = LocatePayloadStart(rtp.empty() ? 0 : &rtp[0], rtp.size());
    if (payloadStart == 0 || payloadStart >= rtp.size()) {
        return std::vector<uint8_t>();
    }

    // Maintain ROC. If the new seq_num is "less than" the previous one in the
    // sense of unsigned 16-bit wrap (i.e. previous was 0xFFFx, new is 0x000x),
    // we increment ROC. We treat the gap as a wrap when previous - new is
    // small (< 0x8000) — the standard heuristic from RFC 3711 §3.3.1.
    if (params.HasLastSequenceNumber) {
        uint16_t prev = params.LastSequenceNumber;
        // Rollover detected: prev close to 0xFFFF and new wrapped to small value.
        if (prev > sequenceNumber && (uint32_t)(prev - sequenceNumber) < 0x8000u) {
            params.RolloverCounter++;
        }
    }
    params.LastSequenceNumber = sequenceNumber;
    params.HasLastSequenceNumber = true;

    uint64_t packetIndex48 =
        ((uint64_t)params.RolloverCounter << 16) | (uint64_t)sequenceNumber;

    uint8_t iv[16];
    BuildPacketIv(params.SessionSalt, params.Ssrc, packetIndex48, iv);

    // Build the SRTP packet: copy header, encrypt payload, append auth tag.
    std::vector<uint8_t> srtp;
    srtp.reserve(rtp.size() + kAuthTagSize);
    srtp.insert(srtp.end(), rtp.begin(), rtp.end());

    size_t payloadLen = rtp.size() - payloadStart;
    if (payloadLen > 0) {
        SrtpAesCtr::Encrypt(params.SessionEncrKey,
                            iv,
                            &rtp[payloadStart],
                            &srtp[payloadStart],
                            payloadLen);
    }

    uint8_t tag[kAuthTagSize];
    ComputeAuthTag(params.SessionAuthKey, &srtp[0], srtp.size(), params.RolloverCounter, tag);
    srtp.insert(srtp.end(), tag, tag + kAuthTagSize);

    return srtp;
}

bool SrtpPacketCodec::Decrypt(const SrtpEncryptParams& params,
                              const std::vector<uint8_t>& srtp,
                              std::vector<uint8_t>& outRtp)
{
    outRtp.clear();
    if (srtp.size() < kRtpFixedHeaderSize + kAuthTagSize) return false;

    size_t bodyLen = srtp.size() - kAuthTagSize;
    const uint8_t* body = &srtp[0];

    size_t payloadStart = LocatePayloadStart(body, bodyLen);
    if (payloadStart == 0 || payloadStart > bodyLen) return false;

    // Verify auth tag first.
    uint8_t expectedTag[kAuthTagSize];
    ComputeAuthTag(params.SessionAuthKey, body, bodyLen, params.RolloverCounter, expectedTag);
    if (!ConstantTimeEqual(expectedTag, &srtp[bodyLen], kAuthTagSize)) {
        return false;
    }

    // Reconstruct the 48-bit packet index from current ROC and the seq_num
    // carried in the header (bytes [2..4]).
    uint16_t seqNum = static_cast<uint16_t>((body[2] << 8) | body[3]);
    uint64_t packetIndex48 =
        ((uint64_t)params.RolloverCounter << 16) | (uint64_t)seqNum;

    uint8_t iv[16];
    BuildPacketIv(params.SessionSalt, params.Ssrc, packetIndex48, iv);

    outRtp.assign(body, body + bodyLen);  // copy header + ciphertext
    size_t payloadLen = bodyLen - payloadStart;
    if (payloadLen > 0) {
        SrtpAesCtr::Encrypt(params.SessionEncrKey,
                            iv,
                            &outRtp[payloadStart],
                            &outRtp[payloadStart],
                            payloadLen);
    }
    return true;
}

}}}} // namespace vianigram::voip::infrastructure::srtp
