// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_endpoint_selector.h"

namespace vianigram { namespace voip { namespace domain {

namespace {

bool HasAddress(const VoipEndpoint& endpoint) {
    return !endpoint.Ip.empty() || !endpoint.Ipv6.empty();
}

bool HasIpv4(const VoipEndpoint& endpoint) {
    return !endpoint.Ip.empty();
}

} // namespace

bool VoipEndpointSelector::IsUsableReflectorEndpoint(const VoipEndpoint& endpoint) {
    return endpoint.Port > 0
        && endpoint.Port <= 65535
        && HasAddress(endpoint)
        && !endpoint.IsWebRtc
        && !endpoint.PeerTag.empty();
}

bool VoipEndpointSelector::IsUsableWebRtcEndpoint(const VoipEndpoint& endpoint) {
    return endpoint.Port > 0
        && endpoint.Port <= 65535
        && HasAddress(endpoint)
        && endpoint.IsWebRtc
        && (!endpoint.Username.empty() || endpoint.Stun || endpoint.Turn);
}

VoipEndpointSelection VoipEndpointSelector::SelectReflector(
    const std::vector<VoipEndpoint>& endpoints)
{
    VoipEndpointSelection out;
    if (endpoints.empty()) {
        out.Reason = "phoneCall returned no media endpoints";
        return out;
    }

    for (size_t i = 0; i < endpoints.size(); i++) {
        const VoipEndpoint& endpoint = endpoints[i];
        if (IsUsableReflectorEndpoint(endpoint) && HasIpv4(endpoint)) {
            out.Found = true;
            out.Endpoint = endpoint;
            return out;
        }
    }

    for (size_t i = 0; i < endpoints.size(); i++) {
        const VoipEndpoint& endpoint = endpoints[i];
        if (IsUsableReflectorEndpoint(endpoint)) {
            out.Found = true;
            out.Endpoint = endpoint;
            return out;
        }
    }

    out.Reason = "no Telegram reflector endpoint with peer_tag was available";
    return out;
}

}}} // namespace vianigram::voip::domain
