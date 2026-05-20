// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

enum class VoipControlPacketType : uint8_t {
    Init = 1,
    InitAck = 2,
    StreamState = 3,
    StreamData = 4,
    UpdateStreams = 5,
    Ping = 6,
    Pong = 7,
    StreamDataX2 = 8,
    StreamDataX3 = 9,
    LanEndpoint = 10,
    NetworkChanged = 11,
    SwitchPreferredRelay = 12,
    SwitchToP2p = 13,
    Nop = 14,
    StreamEc = 17
};

struct VoipControlPacket {
    VoipControlPacketType Type;
    uint32_t AckSequence;
    uint32_t Sequence;
    uint32_t AckMask;
    uint8_t ExtraFlags;
    std::vector<uint8_t> Payload;

    VoipControlPacket()
        : Type(VoipControlPacketType::Nop),
          AckSequence(0),
          Sequence(0),
          AckMask(0),
          ExtraFlags(0) {}
};

struct VoipInitAckInfo {
    uint32_t PeerVersion;
    uint32_t PeerMinVersion;
    bool HasAudioOpusStream;
    uint8_t AudioStreamId;
    uint16_t FrameDurationMs;
    bool AudioEnabled;

    VoipInitAckInfo()
        : PeerVersion(0),
          PeerMinVersion(0),
          HasAudioOpusStream(false),
          AudioStreamId(0),
          FrameDurationMs(0),
          AudioEnabled(false) {}
};

struct VoipControlCodecResult {
    bool Success;
    std::string Error;
    VoipControlPacket Packet;
    VoipInitAckInfo InitAck;
    std::vector<uint8_t> Bytes;

    VoipControlCodecResult() : Success(false) {}
};

class VoipControlPacketCodec {
public:
    enum {
        ProtocolVersion = 9,
        MinProtocolVersion = 3,
        ProtocolLayer = 92,
        StreamTypeAudio = 1,
        DefaultAudioStreamId = 1,
        DefaultAudioFrameDurationMs = 60,
        HeaderBytes = 14
    };

    static const uint32_t CodecOpus;

    static VoipControlCodecResult EncodeShort(const VoipControlPacket& packet);
    static VoipControlCodecResult DecodeShort(const uint8_t* bytes, size_t length);

    static VoipControlCodecResult BuildInitPayload(bool dataSavingEnabled);
    static VoipControlCodecResult BuildInitAckPayload();
    static VoipControlCodecResult ParseInitAckPayload(const uint8_t* bytes, size_t length);
};

}}} // namespace vianigram::voip::domain
