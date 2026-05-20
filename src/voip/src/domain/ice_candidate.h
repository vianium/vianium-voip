// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
//
// Parser/formatter for SDP "candidate:" attribute lines (RFC 5245 §15.1).
//
// Example input:
//   candidate:2188581420 1 udp 2122194688 192.168.3.44 58771 typ host
//   generation 0 ufrag +5to network-id 1 network-cost 10
//

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

enum IceCandidateType {
    IceCandidateType_Host,
    IceCandidateType_Srflx,
    IceCandidateType_Prflx,
    IceCandidateType_Relay,
    IceCandidateType_Unknown
};

struct ParsedIceCandidate {
    std::string Foundation;
    int          ComponentId;
    std::string  Transport;       // typically "udp"
    uint32_t     Priority;
    std::string  Ip;
    int          Port;
    IceCandidateType Type;
    std::string  Ufrag;           // optional ICE2 extension
    int          NetworkId;
    int          NetworkCost;
    int          Generation;

    // Optional for srflx/relay
    std::string  RelatedAddress;  // "raddr"
    int          RelatedPort;     // "rport"

    ParsedIceCandidate()
        : ComponentId(0), Priority(0), Port(0), Type(IceCandidateType_Unknown)
        , NetworkId(0), NetworkCost(0), Generation(0), RelatedPort(0) {}
};

class IceCandidateParser {
public:
    // Accepts both "candidate:..." and bare "..." forms. Returns false on
    // structural failure, true if the four required tokens
    // (foundation, component, transport, priority, ip, port, "typ", type)
    // are all present and parsed.
    static bool Parse(const std::string& sdpLine, ParsedIceCandidate& out);

    // Reverse: produce a "candidate:..." string.
    static std::string Format(const ParsedIceCandidate& c);

    static const char* TypeToString(IceCandidateType t);
    static IceCandidateType TypeFromString(const std::string& s);
};

}}} // namespace vianigram::voip::domain
