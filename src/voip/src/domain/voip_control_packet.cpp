// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_control_packet.h"

namespace vianigram { namespace voip { namespace domain {

const uint32_t VoipControlPacketCodec::CodecOpus = 0x4F505553u;

namespace {

const uint8_t kInitFlagDataSavingEnabled = 1;

VoipControlCodecResult Fail(const char* message) {
    VoipControlCodecResult r;
    r.Success = false;
    r.Error = message == 0 ? "" : message;
    return r;
}

void WriteLE16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void WriteLE32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

uint16_t ReadLE16(const uint8_t* bytes) {
    return static_cast<uint16_t>(
        static_cast<uint16_t>(bytes[0]) |
        (static_cast<uint16_t>(bytes[1]) << 8));
}

uint32_t ReadLE32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0])
        | (static_cast<uint32_t>(bytes[1]) << 8)
        | (static_cast<uint32_t>(bytes[2]) << 16)
        | (static_cast<uint32_t>(bytes[3]) << 24);
}

bool IsKnownType(uint8_t type) {
    switch (type) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            return true;
    }
    return false;
}

bool HasBytes(size_t length, size_t offset, size_t count) {
    return offset <= length && count <= length - offset;
}

} // namespace

VoipControlCodecResult VoipControlPacketCodec::EncodeShort(const VoipControlPacket& packet) {
    uint8_t type = static_cast<uint8_t>(packet.Type);
    if (!IsKnownType(type)) {
        return Fail("VoIP control packet type is unknown");
    }
    if (packet.Payload.size() > 1100) {
        return Fail("VoIP control packet payload exceeds relay MTU budget");
    }

    VoipControlCodecResult r;
    r.Success = true;
    r.Packet = packet;
    r.Bytes.reserve(HeaderBytes + packet.Payload.size());
    r.Bytes.push_back(type);
    WriteLE32(r.Bytes, packet.AckSequence);
    WriteLE32(r.Bytes, packet.Sequence);
    WriteLE32(r.Bytes, packet.AckMask);
    r.Bytes.push_back(packet.ExtraFlags);
    r.Bytes.insert(r.Bytes.end(), packet.Payload.begin(), packet.Payload.end());
    return r;
}

VoipControlCodecResult VoipControlPacketCodec::DecodeShort(const uint8_t* bytes, size_t length) {
    if (bytes == 0 || length < HeaderBytes) {
        return Fail("VoIP control packet is too short");
    }
    if (!IsKnownType(bytes[0])) {
        return Fail("VoIP control packet type is unknown");
    }

    VoipControlCodecResult r;
    r.Success = true;
    r.Bytes.assign(bytes, bytes + length);
    r.Packet.Type = static_cast<VoipControlPacketType>(bytes[0]);
    r.Packet.AckSequence = ReadLE32(bytes + 1);
    r.Packet.Sequence = ReadLE32(bytes + 5);
    r.Packet.AckMask = ReadLE32(bytes + 9);
    r.Packet.ExtraFlags = bytes[13];
    r.Packet.Payload.assign(bytes + HeaderBytes, bytes + length);
    return r;
}

VoipControlCodecResult VoipControlPacketCodec::BuildInitPayload(bool dataSavingEnabled) {
    VoipControlCodecResult r;
    r.Success = true;
    WriteLE32(r.Bytes, ProtocolVersion);
    WriteLE32(r.Bytes, MinProtocolVersion);

    uint32_t flags = dataSavingEnabled ? kInitFlagDataSavingEnabled : 0u;
    WriteLE32(r.Bytes, flags);

    r.Bytes.push_back(1); // audio codecs count
    WriteLE32(r.Bytes, CodecOpus);
    r.Bytes.push_back(0); // video decoder count
    r.Bytes.push_back(0); // max video resolution: none
    return r;
}

VoipControlCodecResult VoipControlPacketCodec::BuildInitAckPayload() {
    VoipControlCodecResult r;
    r.Success = true;
    WriteLE32(r.Bytes, ProtocolVersion);
    WriteLE32(r.Bytes, MinProtocolVersion);

    r.Bytes.push_back(1); // outgoing stream count
    r.Bytes.push_back(DefaultAudioStreamId);
    r.Bytes.push_back(StreamTypeAudio);
    WriteLE32(r.Bytes, CodecOpus);
    WriteLE16(r.Bytes, DefaultAudioFrameDurationMs);
    r.Bytes.push_back(1); // enabled
    return r;
}

VoipControlCodecResult VoipControlPacketCodec::ParseInitAckPayload(const uint8_t* bytes, size_t length) {
    if (bytes == 0 || length < 9) {
        return Fail("VoIP INIT_ACK payload is too short");
    }

    size_t offset = 0;
    VoipInitAckInfo ack;
    ack.PeerVersion = ReadLE32(bytes + offset);
    offset += 4;
    ack.PeerMinVersion = ReadLE32(bytes + offset);
    offset += 4;

    if (ack.PeerMinVersion > ProtocolVersion || ack.PeerVersion < MinProtocolVersion) {
        return Fail("VoIP peer protocol version is incompatible");
    }

    uint8_t streamCount = bytes[offset++];
    for (uint8_t i = 0; i < streamCount; i++) {
        if (!HasBytes(length, offset, 1 + 1 + 4 + 2 + 1)) {
            return Fail("VoIP INIT_ACK stream descriptor is truncated");
        }

        uint8_t streamId = bytes[offset++];
        uint8_t streamType = bytes[offset++];
        uint32_t codec = ReadLE32(bytes + offset);
        offset += 4;
        uint16_t frameDuration = ReadLE16(bytes + offset);
        offset += 2;
        bool enabled = bytes[offset++] != 0;

        if (streamType == StreamTypeAudio && codec == CodecOpus && enabled) {
            ack.HasAudioOpusStream = true;
            ack.AudioStreamId = streamId;
            ack.FrameDurationMs = frameDuration;
            ack.AudioEnabled = enabled;
        }
    }

    VoipControlCodecResult r;
    r.Success = true;
    r.InitAck = ack;
    r.Bytes.assign(bytes, bytes + length);
    return r;
}

}}} // namespace vianigram::voip::domain
