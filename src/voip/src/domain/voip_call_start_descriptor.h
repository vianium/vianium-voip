// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "voip_endpoint.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipCallStartDescriptor {
    int64_t CallId;
    int64_t AccessHash;
    bool IsInitiator;
    bool IsVideo;
    bool UdpP2p;
    bool UdpReflector;
    int32_t MinLayer;
    int32_t MaxLayer;
    std::vector<std::string> LibraryVersions;
    int64_t KeyFingerprint;
    std::string KeyHandle;
    std::vector<VoipEndpoint> Endpoints;
    std::string CallConfigJson;

    VoipCallStartDescriptor()
        : CallId(0),
          AccessHash(0),
          IsInitiator(false),
          IsVideo(false),
          UdpP2p(false),
          UdpReflector(false),
          MinLayer(0),
          MaxLayer(0),
          KeyFingerprint(0) {}
};

}}} // namespace vianigram::voip::domain
