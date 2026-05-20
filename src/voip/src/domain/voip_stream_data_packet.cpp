// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_stream_data_packet.h"

namespace vianigram { namespace voip { namespace domain {

namespace {

VoipStreamDataCodecResult Fail(const char* message) {
    VoipStreamDataCodecResult r;
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

} // namespace

VoipStreamDataCodecResult VoipStreamDataPacketCodec::EncodeAudio(
    uint8_t streamId,
    uint32_t timestamp,
    const uint8_t* opusBytes,
    size_t opusLength)
{
    if (streamId == 0 || streamId > 0x3F) {
        return Fail("VoIP stream id must fit in 6 bits");
    }
    if (opusBytes == 0 || opusLength == 0) {
        return Fail("VoIP stream payload is empty");
    }
    if (opusLength > MaxOpusPayloadBytes) {
        return Fail("VoIP stream payload exceeds relay MTU budget");
    }

    VoipStreamDataCodecResult r;
    r.Success = true;
    r.Packet.StreamId = streamId;
    r.Packet.Timestamp = timestamp;
    r.Packet.OpusPayload.assign(opusBytes, opusBytes + opusLength);
    r.Bytes.reserve(1 + 2 + 4 + opusLength);

    uint8_t flags = opusLength > 255 ? StreamDataFlagLen16 : 0;
    r.Bytes.push_back(static_cast<uint8_t>((streamId & 0x3F) | flags));
    if (flags & StreamDataFlagLen16) {
        WriteLE16(r.Bytes, static_cast<uint16_t>(opusLength));
    } else {
        r.Bytes.push_back(static_cast<uint8_t>(opusLength));
    }
    WriteLE32(r.Bytes, timestamp);
    r.Bytes.insert(r.Bytes.end(), opusBytes, opusBytes + opusLength);
    return r;
}

VoipStreamDataCodecResult VoipStreamDataPacketCodec::DecodeOne(const uint8_t* bytes, size_t length) {
    if (bytes == 0 || length < 6) {
        return Fail("VoIP stream data packet is too short");
    }

    size_t offset = 0;
    uint8_t streamAndFlags = bytes[offset++];
    uint8_t streamId = static_cast<uint8_t>(streamAndFlags & 0x3F);
    uint8_t flags = static_cast<uint8_t>(streamAndFlags & 0xC0);
    if (streamId == 0) {
        return Fail("VoIP stream id is zero");
    }
    if (flags & StreamDataFlagHasMoreFlags) {
        return Fail("VoIP extended stream flags are not supported yet");
    }

    uint16_t payloadLength = 0;
    if (flags & StreamDataFlagLen16) {
        if (length < offset + 2 + 4) {
            return Fail("VoIP stream data packet is truncated before length16");
        }
        payloadLength = ReadLE16(bytes + offset);
        offset += 2;
        if (payloadLength & StreamDataXFlagFragmented) {
            return Fail("VoIP fragmented stream data is not supported yet");
        }
        if (payloadLength & StreamDataXFlagExtraFec) {
            return Fail("VoIP extra FEC stream data is not supported yet");
        }
        payloadLength = static_cast<uint16_t>(payloadLength & StreamDataLengthMask);
    } else {
        payloadLength = bytes[offset++];
    }

    if (payloadLength == 0) {
        return Fail("VoIP stream payload is empty");
    }
    if (payloadLength > MaxOpusPayloadBytes) {
        return Fail("VoIP stream payload exceeds relay MTU budget");
    }
    if (length < offset + 4 + payloadLength) {
        return Fail("VoIP stream payload is truncated");
    }

    VoipStreamDataCodecResult r;
    r.Success = true;
    r.Packet.StreamId = streamId;
    r.Packet.Timestamp = ReadLE32(bytes + offset);
    offset += 4;
    r.Packet.OpusPayload.assign(bytes + offset, bytes + offset + payloadLength);
    r.Bytes.assign(bytes, bytes + offset + payloadLength);
    return r;
}

}}} // namespace vianigram::voip::domain
