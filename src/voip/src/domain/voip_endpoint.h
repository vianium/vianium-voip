// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipEndpoint {
    int64_t Id;
    std::string Ip;
    std::string Ipv6;
    int Port;
    std::vector<uint8_t> PeerTag;
    bool IsWebRtc;
    bool Tcp;
    bool Stun;
    bool Turn;
    std::string Username;
    std::string Password;
    int64_t ReflectorId;

    VoipEndpoint()
        : Id(0),
          Port(0),
          IsWebRtc(false),
          Tcp(false),
          Stun(false),
          Turn(false),
          ReflectorId(0) {}
};

}}} // namespace vianigram::voip::domain
