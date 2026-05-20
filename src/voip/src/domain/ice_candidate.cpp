// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "ice_candidate.h"

#include <cstdlib>
#include <sstream>

namespace vianigram { namespace voip { namespace domain {

namespace {

// Trim leading/trailing ASCII whitespace.
std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' ||
                     s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// Split on ASCII spaces.
void SplitSpaces(const std::string& s, std::vector<std::string>& out) {
    std::string cur;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == ' ' || s[i] == '\t') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(s[i]);
        }
    }
    if (!cur.empty()) out.push_back(cur);
}

bool ParseInt(const std::string& s, int& out) {
    if (s.empty()) return false;
    char* endp = NULL;
    long v = std::strtol(s.c_str(), &endp, 10);
    if (!endp || *endp != '\0') return false;
    out = static_cast<int>(v);
    return true;
}

bool ParseU32(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    char* endp = NULL;
    unsigned long v = std::strtoul(s.c_str(), &endp, 10);
    if (!endp || *endp != '\0') return false;
    out = static_cast<uint32_t>(v);
    return true;
}

} // namespace

const char* IceCandidateParser::TypeToString(IceCandidateType t) {
    switch (t) {
        case IceCandidateType_Host:  return "host";
        case IceCandidateType_Srflx: return "srflx";
        case IceCandidateType_Prflx: return "prflx";
        case IceCandidateType_Relay: return "relay";
        default:                     return "host";
    }
}

IceCandidateType IceCandidateParser::TypeFromString(const std::string& s) {
    if (s == "host")  return IceCandidateType_Host;
    if (s == "srflx") return IceCandidateType_Srflx;
    if (s == "prflx") return IceCandidateType_Prflx;
    if (s == "relay") return IceCandidateType_Relay;
    return IceCandidateType_Unknown;
}

bool IceCandidateParser::Parse(const std::string& sdpLine, ParsedIceCandidate& out) {
    std::string line = Trim(sdpLine);
    if (line.empty()) return false;

    // Strip "a=" SDP prefix if present, then "candidate:" prefix.
    if (line.size() >= 2 && line[0] == 'a' && line[1] == '=') line = line.substr(2);
    const char* kPrefix = "candidate:";
    if (line.compare(0, 10, kPrefix) == 0) line = line.substr(10);

    std::vector<std::string> tok;
    SplitSpaces(line, tok);
    // foundation component transport priority ip port "typ" type ...
    if (tok.size() < 8) return false;

    out = ParsedIceCandidate();
    out.Foundation = tok[0];
    if (!ParseInt(tok[1], out.ComponentId)) return false;
    out.Transport = tok[2];
    if (!ParseU32(tok[3], out.Priority))    return false;
    out.Ip   = tok[4];
    if (!ParseInt(tok[5], out.Port))        return false;
    if (tok[6] != "typ")                     return false;
    out.Type = TypeFromString(tok[7]);
    if (out.Type == IceCandidateType_Unknown) return false;

    // Remaining are key/value pairs.
    for (size_t i = 8; i + 1 < tok.size(); i += 2) {
        const std::string& k = tok[i];
        const std::string& v = tok[i + 1];
        if      (k == "raddr")        out.RelatedAddress = v;
        else if (k == "rport")        ParseInt(v, out.RelatedPort);
        else if (k == "generation")   ParseInt(v, out.Generation);
        else if (k == "ufrag")        out.Ufrag = v;
        else if (k == "network-id")   ParseInt(v, out.NetworkId);
        else if (k == "network-cost") ParseInt(v, out.NetworkCost);
        // unknown extensions are silently ignored.
    }
    return true;
}

std::string IceCandidateParser::Format(const ParsedIceCandidate& c) {
    std::ostringstream os;
    os << "candidate:" << c.Foundation
       << ' ' << c.ComponentId
       << ' ' << (c.Transport.empty() ? "udp" : c.Transport)
       << ' ' << c.Priority
       << ' ' << c.Ip
       << ' ' << c.Port
       << " typ " << TypeToString(c.Type);
    if (!c.RelatedAddress.empty()) {
        os << " raddr " << c.RelatedAddress << " rport " << c.RelatedPort;
    }
    os << " generation " << c.Generation;
    if (!c.Ufrag.empty())  os << " ufrag "         << c.Ufrag;
    if (c.NetworkId > 0)   os << " network-id "    << c.NetworkId;
    if (c.NetworkCost > 0) os << " network-cost "  << c.NetworkCost;
    return os.str();
}

}}} // namespace vianigram::voip::domain
