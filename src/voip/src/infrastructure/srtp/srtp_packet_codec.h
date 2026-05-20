// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// SRTP packet encryption / decryption for the SRTP_AES128_CM_HMAC_SHA1_80
// profile (RFC 3711 + RFC 5764).
//
// Packet shape on the wire:
//
//   +-----------------------+
//   | RTP header (cleartext)|
//   +-----------------------+
//   | encrypted payload     |  ← AES-128-CTR (session_encr_key, IV)
//   +-----------------------+
//   | auth tag (10 bytes)   |  ← HMAC-SHA1-80(session_auth_key, header||cipher||ROC)
//   +-----------------------+
//
// IV construction (RFC 3711 §4.1.1):
//   iv = (session_salt || 00 00) XOR ((SSRC << 64) | (i << 16))
//   where i = 48-bit packet index = (rollover_counter << 16) | seq_num.
//
// The codec is stateless apart from the rollover counter, which is supplied
// by the caller via `SrtpEncryptParams`. On the encrypt path we update the
// caller's counter when the 16-bit RTP sequence number wraps from 0xFFFF
// back to 0x0000.

#include <cstdint>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace srtp {

struct SrtpEncryptParams {
    uint8_t  SessionEncrKey[16];
    uint8_t  SessionAuthKey[20];
    uint8_t  SessionSalt[14];
    uint32_t Ssrc;             // RTP SSRC (host order; we serialise as big-endian)
    uint32_t RolloverCounter;  // ROC, increments when seq_num wraps 0xFFFF→0
    uint16_t LastSequenceNumber; // last seq_num observed (for ROC bookkeeping)
    bool     HasLastSequenceNumber;
};

class SrtpPacketCodec {
public:
    // Encrypt a complete plaintext RTP packet (header + payload). Returns the
    // SRTP packet (header in clear + encrypted payload + 10-byte auth tag) or
    // an empty vector on failure (e.g. malformed RTP header).
    //
    // `params.RolloverCounter` and `params.LastSequenceNumber` may be mutated
    // when the supplied `sequenceNumber` rolls over from the previous one.
    static std::vector<uint8_t> Encrypt(SrtpEncryptParams& params,
                                        const std::vector<uint8_t>& rtp,
                                        uint16_t sequenceNumber);

    // Decrypt an incoming SRTP packet. Returns true on success and writes the
    // plaintext RTP packet (header + decrypted payload, no auth tag) to
    // `outRtp`. Returns false if the auth tag does not match or the packet is
    // shorter than a minimal RTP header + tag.
    //
    // For decrypt we recover the ROC from `params.RolloverCounter` (the most
    // recent value the caller has tracked); we do not currently implement
    // RFC 3711 §3.3.1 ROC guess-and-verify because we control both endpoints
    // and feed authoritative ROC state into the codec.
    static bool Decrypt(const SrtpEncryptParams& params,
                        const std::vector<uint8_t>& srtp,
                        std::vector<uint8_t>& outRtp);

    // Authentication tag length in bytes. Profile is HMAC-SHA1-80 → 10 bytes.
    static const size_t kAuthTagSize = 10;
};

}}}} // namespace vianigram::voip::infrastructure::srtp
