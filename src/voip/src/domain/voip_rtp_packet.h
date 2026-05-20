// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipRtpPacket {
    uint8_t PayloadType;
    uint16_t SequenceNumber;
    uint32_t Timestamp;
    uint32_t Ssrc;
    uint8_t TelegramFlags;
    uint32_t TelegramSequenceOrAck;
    std::vector<uint8_t> Payload;

    VoipRtpPacket()
        : PayloadType(96),
          SequenceNumber(0),
          Timestamp(0),
          Ssrc(0),
          TelegramFlags(0),
          TelegramSequenceOrAck(0) {}
};

struct VoipRtpCodecResult {
    bool Success;
    std::string Error;
    VoipRtpPacket Packet;
    std::vector<uint8_t> Bytes;

    VoipRtpCodecResult() : Success(false) {}
};

class VoipRtpCodec {
public:
    static const size_t HeaderBytes = 16;
    static const size_t MaxPayloadBytes = 1200;

    static VoipRtpCodecResult Encode(const VoipRtpPacket& packet);
    static VoipRtpCodecResult Decode(const uint8_t* bytes, size_t length);
};

}}} // namespace vianigram::voip::domain
