// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipStreamDataPacket {
    uint8_t StreamId;
    uint32_t Timestamp;
    std::vector<uint8_t> OpusPayload;

    VoipStreamDataPacket()
        : StreamId(1),
          Timestamp(0) {}
};

struct VoipStreamDataCodecResult {
    bool Success;
    std::string Error;
    VoipStreamDataPacket Packet;
    std::vector<uint8_t> Bytes;

    VoipStreamDataCodecResult() : Success(false) {}
};

class VoipStreamDataPacketCodec {
public:
    enum {
        StreamDataFlagLen16 = 0x40,
        StreamDataFlagHasMoreFlags = 0x80,
        StreamDataXFlagKeyframe = 1 << 15,
        StreamDataXFlagFragmented = 1 << 14,
        StreamDataXFlagExtraFec = 1 << 13,
        StreamDataLengthMask = 0x07FF,
        DefaultAudioStreamId = 1,
        MaxOpusPayloadBytes = 1100
    };

    static VoipStreamDataCodecResult EncodeAudio(
        uint8_t streamId,
        uint32_t timestamp,
        const uint8_t* opusBytes,
        size_t opusLength);

    static VoipStreamDataCodecResult DecodeOne(const uint8_t* bytes, size_t length);
};

}}} // namespace vianigram::voip::domain
