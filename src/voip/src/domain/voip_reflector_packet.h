// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipReflectorSelfInfo {
    std::vector<uint8_t> PeerTag;
    int32_t Date;
    uint64_t QueryId;
    uint32_t RawIpv4;
    std::string Ipv4;
    uint16_t Port;

    VoipReflectorSelfInfo()
        : Date(0),
          QueryId(0),
          RawIpv4(0),
          Port(0) {}
};

struct VoipReflectorPacketResult {
    bool Success;
    std::string Error;
    std::vector<uint8_t> Bytes;
    VoipReflectorSelfInfo SelfInfo;

    VoipReflectorPacketResult() : Success(false) {}
};

class VoipReflectorPacketCodec {
public:
    enum {
        PeerTagBytes = 16,
        DiscoveryRequestBytes = 32,
        SelfInfoRequestBytes = 40,
        SelfInfoResponseBytes = 64
    };

    static VoipReflectorPacketResult BuildPeerDiscoveryRequest(
        const std::vector<uint8_t>& peerTag);

    static VoipReflectorPacketResult BuildSelfInfoRequest(
        const std::vector<uint8_t>& peerTag,
        uint64_t queryId);

    static VoipReflectorPacketResult ParseSelfInfoResponse(
        const uint8_t* bytes,
        size_t length,
        const std::vector<uint8_t>& expectedPeerTag);
};

}}} // namespace vianigram::voip::domain
