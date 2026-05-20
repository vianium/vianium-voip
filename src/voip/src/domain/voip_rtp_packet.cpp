// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_rtp_packet.h"

namespace vianigram { namespace voip { namespace domain {

namespace {

void WriteBE16(std::vector<uint8_t>& out, size_t offset, uint16_t value) {
    out[offset] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[offset + 1] = static_cast<uint8_t>(value & 0xFF);
}

void WriteBE24(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    out[offset] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>(value & 0xFF);
}

void WriteBE32(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    out[offset] = static_cast<uint8_t>((value >> 24) & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[offset + 3] = static_cast<uint8_t>(value & 0xFF);
}

uint16_t ReadBE16(const uint8_t* bytes) {
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

uint32_t ReadBE24(const uint8_t* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 16)
        | (static_cast<uint32_t>(bytes[1]) << 8)
        | static_cast<uint32_t>(bytes[2]);
}

uint32_t ReadBE32(const uint8_t* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24)
        | (static_cast<uint32_t>(bytes[1]) << 16)
        | (static_cast<uint32_t>(bytes[2]) << 8)
        | static_cast<uint32_t>(bytes[3]);
}

VoipRtpCodecResult Fail(const char* message) {
    VoipRtpCodecResult r;
    r.Success = false;
    r.Error = message == 0 ? "" : message;
    return r;
}

} // namespace

VoipRtpCodecResult VoipRtpCodec::Encode(const VoipRtpPacket& packet) {
    if (packet.Payload.empty()) {
        return Fail("RTP payload is empty");
    }
    if (packet.Payload.size() > MaxPayloadBytes) {
        return Fail("RTP payload exceeds conservative UDP MTU budget");
    }
    if (packet.PayloadType > 127) {
        return Fail("RTP payload type must fit in 7 bits");
    }
    if (packet.TelegramSequenceOrAck > 0xFFFFFFu) {
        return Fail("Telegram RTP extension sequence/ack must fit in 24 bits");
    }

    VoipRtpCodecResult r;
    r.Success = true;
    r.Packet = packet;
    r.Bytes.resize(HeaderBytes + packet.Payload.size());

    r.Bytes[0] = 0x80; // V=2, no padding, no RTP extension bit, no CSRC.
    r.Bytes[1] = static_cast<uint8_t>(packet.PayloadType & 0x7F);
    WriteBE16(r.Bytes, 2, packet.SequenceNumber);
    WriteBE32(r.Bytes, 4, packet.Timestamp);
    WriteBE32(r.Bytes, 8, packet.Ssrc);

    r.Bytes[12] = packet.TelegramFlags;
    WriteBE24(r.Bytes, 13, packet.TelegramSequenceOrAck);

    for (size_t i = 0; i < packet.Payload.size(); i++) {
        r.Bytes[HeaderBytes + i] = packet.Payload[i];
    }
    return r;
}

VoipRtpCodecResult VoipRtpCodec::Decode(const uint8_t* bytes, size_t length) {
    if (bytes == 0 || length < HeaderBytes) {
        return Fail("RTP packet is too short");
    }

    uint8_t version = static_cast<uint8_t>((bytes[0] >> 6) & 0x03);
    uint8_t csrcCount = static_cast<uint8_t>(bytes[0] & 0x0F);
    if (version != 2) {
        return Fail("RTP version must be 2");
    }
    if (csrcCount != 0) {
        return Fail("RTP CSRC lists are not supported for Telegram calls");
    }

    VoipRtpCodecResult r;
    r.Success = true;
    r.Bytes.assign(bytes, bytes + length);
    r.Packet.PayloadType = static_cast<uint8_t>(bytes[1] & 0x7F);
    r.Packet.SequenceNumber = ReadBE16(bytes + 2);
    r.Packet.Timestamp = ReadBE32(bytes + 4);
    r.Packet.Ssrc = ReadBE32(bytes + 8);
    r.Packet.TelegramFlags = bytes[12];
    r.Packet.TelegramSequenceOrAck = ReadBE24(bytes + 13);
    r.Packet.Payload.assign(bytes + HeaderBytes, bytes + length);

    if (r.Packet.Payload.empty()) {
        return Fail("RTP payload is empty");
    }
    if (r.Packet.Payload.size() > MaxPayloadBytes) {
        return Fail("RTP payload exceeds conservative UDP MTU budget");
    }
    return r;
}

}}} // namespace vianigram::voip::domain
