// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "voip_endpoint.h"

#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipEndpointSelection {
    bool Found;
    VoipEndpoint Endpoint;
    std::string Reason;

    VoipEndpointSelection() : Found(false) {}
};

class VoipEndpointSelector {
public:
    static bool IsUsableReflectorEndpoint(const VoipEndpoint& endpoint);
    static bool IsUsableWebRtcEndpoint(const VoipEndpoint& endpoint);
    static VoipEndpointSelection SelectReflector(
        const std::vector<VoipEndpoint>& endpoints);
};

}}} // namespace vianigram::voip::domain
