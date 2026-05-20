// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "ice_agent.h"

#include <collection.h>

#include <cstring>
#include <sstream>

namespace vianigram { namespace voip { namespace application {

namespace {

uint32_t MakePriority(uint32_t typePref, uint32_t localPref, uint32_t componentId) {
    // RFC 5245 priority formula:
    // priority = (2^24)*type_preference + (2^8)*local_preference + (2^0)*(256 - component_id)
    return (typePref  << 24) |
           (localPref <<  8) |
           static_cast<uint32_t>(256 - componentId);
}

// Copy IBuffer^ -> std::vector<uint8_t> via the WinRT Cryptographic helper
// (matches the idiom used elsewhere in this project, e.g. ecdsa_p256_keypair).
std::vector<uint8_t> RandomBytes(unsigned int n) {
    using namespace Windows::Security::Cryptography;
    using namespace Windows::Storage::Streams;
    IBuffer^ buf = CryptographicBuffer::GenerateRandom(n);
    Platform::Array<uint8>^ arr = nullptr;
    CryptographicBuffer::CopyToByteArray(buf, &arr);
    std::vector<uint8_t> out;
    if (arr != nullptr && arr->Length > 0) {
        out.assign(arr->Data, arr->Data + arr->Length);
    } else {
        out.assign(n, 0);
    }
    return out;
}

} // namespace

IceAgent::IceAgent(IceAgentRole role,
                   const std::string& localUfrag,
                   const std::string& localPwd,
                   const std::string& remoteUfrag,
                   const std::string& remotePwd)
    : m_role(role)
    , m_localUfrag(localUfrag)
    , m_localPwd(localPwd)
    , m_remoteUfrag(remoteUfrag)
    , m_remotePwd(remotePwd)
    , m_tieBreak(0)
    , m_priorityCounter(0)
    , m_connected(false)
{
    // Tie-breaker: 64-bit random per RFC 8445 §16.1.
    std::vector<uint8_t> r = RandomBytes(8);
    for (size_t i = 0; i < r.size(); ++i) {
        m_tieBreak = (m_tieBreak << 8) | static_cast<uint64_t>(r[i]);
    }
}

void IceAgent::AddRemoteCandidate(const domain::ParsedIceCandidate& c) {
    m_remoteCandidates.push_back(c);

    // Add as a check target. Duplicates are harmless; FindPair handles
    // existing entries.
    if (!FindPair(c.Ip, c.Port)) {
        IceCheckTarget t(c.Ip, c.Port);
        m_checkTargets.push_back(t);
        Pair p; p.Target = t;
        m_pairs.push_back(p);
    }
}

std::vector<domain::ParsedIceCandidate>
IceAgent::GenerateLocalCandidates(const std::vector<std::string>& reflectorIps,
                                  int reflectorPort) {
    std::vector<domain::ParsedIceCandidate> out;
    // tgcalls clients normally announce a "relay" candidate per reflector
    // address. We assign descending local preferences so the first
    // reflector in the list is preferred.
    uint32_t lp = 65535;
    for (size_t i = 0; i < reflectorIps.size(); ++i) {
        domain::ParsedIceCandidate c;
        std::ostringstream foundation;
        foundation << "rl" << (++m_priorityCounter);
        c.Foundation  = foundation.str();
        c.ComponentId = 1;
        c.Transport   = "udp";
        // type_preference: relay = 0 (lowest), srflx = 100, host = 126
        c.Priority    = MakePriority(0u, lp, c.ComponentId);
        c.Ip          = reflectorIps[i];
        c.Port        = reflectorPort;
        c.Type        = domain::IceCandidateType_Relay;
        c.Ufrag       = m_localUfrag;
        c.NetworkId   = 1;
        c.NetworkCost = 50;
        c.Generation  = 0;
        out.push_back(c);
        if (lp > 1024) lp -= 1024; else lp = 1;
    }
    return out;
}

std::vector<std::pair<IceCheckTarget, std::vector<uint8_t> > >
IceAgent::GetBindingRequestsToSend() {
    std::vector<std::pair<IceCheckTarget, std::vector<uint8_t> > > out;
    for (size_t i = 0; i < m_pairs.size(); ++i) {
        Pair& p = m_pairs[i];
        // Send USE-CANDIDATE only if controlling AND this pair has succeeded
        // AND we haven't sent it yet.
        bool useCandidate = (m_role == IceAgentRole_Controlling) &&
                            p.Succeeded && !p.UseCandidateSent;
        std::vector<uint8_t> bytes = BuildBindingRequest(useCandidate);
        if (useCandidate) p.UseCandidateSent = true;
        out.push_back(std::make_pair(p.Target, bytes));
    }
    return out;
}

IceAgent::ProcessResult
IceAgent::ProcessIncoming(const std::string& srcIp, int srcPort,
                          const std::vector<uint8_t>& bytes,
                          std::vector<uint8_t>& outResponse) {
    outResponse.clear();
    infrastructure::ice::StunMessage msg;
    if (!infrastructure::ice::StunMessageCodec::Decode(
            bytes.empty() ? NULL : &bytes[0], bytes.size(), msg)) {
        return ProcessResult_Other;
    }

    if (msg.MessageType == infrastructure::ice::kStunBindingRequest) {
        // Verify peer's MESSAGE-INTEGRITY using OUR password (peer signs
        // with our pwd because we are the verifier per RFC 5245).
        if (!infrastructure::ice::StunMessageCodec::VerifyMessageIntegrity(
                bytes, m_localPwd)) {
            return ProcessResult_Other;
        }
        outResponse = BuildBindingResponse(msg, srcIp, srcPort);

        // Peer sending a request from a target we know about counts as
        // observed reachability for that pair. If they include
        // USE-CANDIDATE and we are controlled, that's our selected pair.
        Pair* p = FindPair(srcIp, srcPort);
        if (p) {
            p->Succeeded = true;
            if (msg.UseCandidate && m_role == IceAgentRole_Controlled && !m_connected) {
                m_connected = true;
                m_selected  = p->Target;
                return ProcessResult_ConnectivityEstablished;
            }
        }
        return ProcessResult_BindingRequestProcessed;
    }

    if (msg.MessageType == infrastructure::ice::kStunBindingResponse) {
        // Peer's response is signed with peer's password (the value WE
        // configured as remotePwd).
        if (!infrastructure::ice::StunMessageCodec::VerifyMessageIntegrity(
                bytes, m_remotePwd)) {
            return ProcessResult_Other;
        }
        Pair* p = FindPair(srcIp, srcPort);
        if (!p) return ProcessResult_Other;
        bool wasNew = !p->Succeeded;
        p->Succeeded = true;

        // Controlling side selects on first successful response, then
        // re-issues a USE-CANDIDATE check on next GetBindingRequestsToSend.
        if (m_role == IceAgentRole_Controlling && !m_connected) {
            m_connected = true;
            m_selected  = p->Target;
            return ProcessResult_ConnectivityEstablished;
        }
        return wasNew ? ProcessResult_BindingResponseProcessed
                      : ProcessResult_Other;
    }

    return ProcessResult_Other;
}

IceAgent::Pair* IceAgent::FindPair(const std::string& ip, int port) {
    for (size_t i = 0; i < m_pairs.size(); ++i) {
        if (m_pairs[i].Target.Ip == ip && m_pairs[i].Target.Port == port) {
            return &m_pairs[i];
        }
    }
    return NULL;
}

std::vector<uint8_t> IceAgent::BuildBindingRequest(bool useCandidate) {
    infrastructure::ice::StunMessage msg;
    msg.MessageType = infrastructure::ice::kStunBindingRequest;
    RandomTransactionId(msg.TransactionId);

    // ICE USERNAME = remoteUfrag:localUfrag
    msg.Username = m_remoteUfrag + ":" + m_localUfrag;

    msg.HasPriority = true;
    msg.Priority    = MakePriority(110u, 65535u, 1u); // type_pref=prflx-ish

    if (m_role == IceAgentRole_Controlling) {
        msg.HasIceControlling      = true;
        msg.IceControllingTieBreak = m_tieBreak;
    } else {
        msg.HasIceControlled      = true;
        msg.IceControlledTieBreak = m_tieBreak;
    }
    msg.UseCandidate = useCandidate;

    return infrastructure::ice::StunMessageCodec::Encode(msg, m_remotePwd);
}

std::vector<uint8_t>
IceAgent::BuildBindingResponse(const infrastructure::ice::StunMessage& req,
                               const std::string& srcIp, int srcPort) {
    infrastructure::ice::StunMessage resp;
    resp.MessageType = infrastructure::ice::kStunBindingResponse;
    std::memcpy(resp.TransactionId, req.TransactionId, 12);

    // XOR-MAPPED-ADDRESS = the source address the request came from.
    // Parse a dotted-quad. IPv6 not supported in this minimal codepath.
    unsigned int b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    if (std::sscanf(srcIp.c_str(), "%u.%u.%u.%u", &b0, &b1, &b2, &b3) == 4 &&
        b0 < 256 && b1 < 256 && b2 < 256 && b3 < 256) {
        resp.HasMappedAddress    = true;
        resp.MappedFamily        = 0x01;
        resp.MappedAddress[0]    = static_cast<uint8_t>(b0);
        resp.MappedAddress[1]    = static_cast<uint8_t>(b1);
        resp.MappedAddress[2]    = static_cast<uint8_t>(b2);
        resp.MappedAddress[3]    = static_cast<uint8_t>(b3);
        resp.MappedPort          = static_cast<uint16_t>(srcPort & 0xFFFF);
    }

    // Sign the response with OUR password (the credential we advertised
    // via SDP). The peer verifies with the value they have as remotePwd.
    return infrastructure::ice::StunMessageCodec::Encode(resp, m_localPwd);
}

void IceAgent::RandomTransactionId(uint8_t out[12]) {
    std::vector<uint8_t> r = RandomBytes(12);
    if (r.size() == 12) {
        std::memcpy(out, &r[0], 12);
    } else {
        std::memset(out, 0, 12);
    }
}

}}} // namespace vianigram::voip::application
