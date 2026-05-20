// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipEncryptedPacketResult {
    bool Success;
    std::string Error;
    std::vector<uint8_t> Bytes;
    std::vector<uint8_t> Plain;

    VoipEncryptedPacketResult() : Success(false) {}
};

class VoipPacketCrypto {
public:
    static VoipEncryptedPacketResult EncryptRelayPacketMtProto2Short(
        const std::vector<uint8_t>& sharedKey,
        bool localIsOutgoing,
        const std::vector<uint8_t>& peerTag,
        const std::vector<uint8_t>& plain);

    static VoipEncryptedPacketResult DecryptRelayPacketMtProto2Short(
        const std::vector<uint8_t>& sharedKey,
        bool localIsOutgoing,
        const std::vector<uint8_t>& expectedPeerTag,
        const uint8_t* bytes,
        size_t length);
};

}}} // namespace vianigram::voip::domain
