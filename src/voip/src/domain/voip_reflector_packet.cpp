// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_reflector_packet.h"

#include <cstdio>

namespace vianigram { namespace voip { namespace domain {

namespace {

const uint32_t kAllBits32 = 0xFFFFFFFFu;
const uint64_t kAllBits64 = 0xFFFFFFFFFFFFFFFFULL;
const uint32_t kSelfInfoMagic = 0xc01572c7u;
const uint32_t kMappedIpv4Padding = 0xFFFF0000u;

VoipReflectorPacketResult Fail(const char* message) {
    VoipReflectorPacketResult r;
    r.Success = false;
    r.Error = message == 0 ? "" : message;
    return r;
}

bool HasPeerTag(const std::vector<uint8_t>& peerTag) {
    return peerTag.size() == VoipReflectorPacketCodec::PeerTagBytes;
}

void WriteLE32(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    out[offset] = static_cast<uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void WriteLE64(std::vector<uint8_t>& out, size_t offset, uint64_t value) {
    WriteLE32(out, offset, static_cast<uint32_t>(value & 0xFFFFFFFFu));
    WriteLE32(out, offset + 4, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFu));
}

uint32_t ReadLE32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0])
        | (static_cast<uint32_t>(bytes[1]) << 8)
        | (static_cast<uint32_t>(bytes[2]) << 16)
        | (static_cast<uint32_t>(bytes[3]) << 24);
}

uint64_t ReadLE64(const uint8_t* bytes) {
    uint64_t lo = static_cast<uint64_t>(ReadLE32(bytes));
    uint64_t hi = static_cast<uint64_t>(ReadLE32(bytes + 4));
    return lo | (hi << 32);
}

std::string Ipv4ToString(uint32_t rawIpv4) {
    char buffer[16];
    unsigned int a = static_cast<unsigned int>(rawIpv4 & 0xFF);
    unsigned int b = static_cast<unsigned int>((rawIpv4 >> 8) & 0xFF);
    unsigned int c = static_cast<unsigned int>((rawIpv4 >> 16) & 0xFF);
    unsigned int d = static_cast<unsigned int>((rawIpv4 >> 24) & 0xFF);
#if defined(_MSC_VER)
    _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "%u.%u.%u.%u", a, b, c, d);
#else
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", a, b, c, d);
#endif
    return std::string(buffer);
}

bool SamePeerTag(const uint8_t* bytes, const std::vector<uint8_t>& expected) {
    if (!HasPeerTag(expected)) return true;
    for (size_t i = 0; i < expected.size(); i++) {
        if (bytes[i] != expected[i]) return false;
    }
    return true;
}

} // namespace

VoipReflectorPacketResult VoipReflectorPacketCodec::BuildPeerDiscoveryRequest(
    const std::vector<uint8_t>& peerTag)
{
    if (!HasPeerTag(peerTag)) {
        return Fail("reflector peer_tag must be exactly 16 bytes");
    }

    VoipReflectorPacketResult r;
    r.Success = true;
    r.Bytes.assign(DiscoveryRequestBytes, 0xFF);
    for (size_t i = 0; i < peerTag.size(); i++) {
        r.Bytes[i] = peerTag[i];
    }
    return r;
}

VoipReflectorPacketResult VoipReflectorPacketCodec::BuildSelfInfoRequest(
    const std::vector<uint8_t>& peerTag,
    uint64_t queryId)
{
    if (!HasPeerTag(peerTag)) {
        return Fail("reflector peer_tag must be exactly 16 bytes");
    }

    VoipReflectorPacketResult r;
    r.Success = true;
    r.Bytes.assign(SelfInfoRequestBytes, 0);
    for (size_t i = 0; i < peerTag.size(); i++) {
        r.Bytes[i] = peerTag[i];
    }
    WriteLE32(r.Bytes, 16, kAllBits32);
    WriteLE32(r.Bytes, 20, kAllBits32);
    WriteLE32(r.Bytes, 24, kAllBits32);
    WriteLE32(r.Bytes, 28, 0xFFFFFFFEu);
    WriteLE64(r.Bytes, 32, queryId);
    return r;
}

VoipReflectorPacketResult VoipReflectorPacketCodec::ParseSelfInfoResponse(
    const uint8_t* bytes,
    size_t length,
    const std::vector<uint8_t>& expectedPeerTag)
{
    if (bytes == 0 || length < SelfInfoResponseBytes) {
        return Fail("reflector self-info response is too short");
    }
    if (!expectedPeerTag.empty() && !HasPeerTag(expectedPeerTag)) {
        return Fail("expected reflector peer_tag must be 16 bytes");
    }
    if (!SamePeerTag(bytes, expectedPeerTag)) {
        return Fail("reflector self-info peer_tag mismatch");
    }

    uint64_t sentinel1 = ReadLE64(bytes + 16);
    uint32_t sentinel2 = ReadLE32(bytes + 24);
    uint32_t magic = ReadLE32(bytes + 28);
    uint32_t padding2 = ReadLE32(bytes + 52);
    if (sentinel1 != kAllBits64 || sentinel2 != kAllBits32 || magic != kSelfInfoMagic) {
        return Fail("reflector self-info response has invalid marker");
    }
    if (padding2 != kMappedIpv4Padding) {
        return Fail("reflector self-info response is not IPv4-mapped");
    }

    VoipReflectorPacketResult r;
    r.Success = true;
    r.Bytes.assign(bytes, bytes + length);
    r.SelfInfo.PeerTag.assign(bytes, bytes + PeerTagBytes);
    r.SelfInfo.Date = static_cast<int32_t>(ReadLE32(bytes + 32));
    r.SelfInfo.QueryId = ReadLE64(bytes + 36);
    r.SelfInfo.RawIpv4 = ReadLE32(bytes + 56);
    r.SelfInfo.Ipv4 = Ipv4ToString(r.SelfInfo.RawIpv4);
    r.SelfInfo.Port = static_cast<uint16_t>(ReadLE32(bytes + 60) & 0xFFFFu);
    return r;
}

}}} // namespace vianigram::voip::domain
