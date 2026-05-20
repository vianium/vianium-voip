// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
//
// Minimal ICE connectivity-check controller for tgcalls voice.
//
// Responsibilities:
//   - Track local + remote candidates.
//   - Emit STUN Binding Requests (with USERNAME=remoteUfrag:localUfrag,
//     PRIORITY, ICE-CONTROLLING/CONTROLLED, MESSAGE-INTEGRITY, FINGERPRINT)
//     for each remote candidate.
//   - Process incoming STUN Binding Requests (peer's checks toward us) and
//     produce a Binding Response (XOR-MAPPED-ADDRESS, MI, FINGERPRINT).
//   - Process incoming STUN Binding Responses, mark the corresponding pair
//     as succeeded, pick a "selected" pair and (if controlling) re-issue
//     a Binding Request with USE-CANDIDATE on it.
//
// We implement only the parts of RFC 8445 we actually need:
//   - Ordinary connectivity checks (no aggressive nomination, but USE-CANDIDATE
//     on the selected pair).
//   - Single component (RTP), no RTCP-mux negotiation here (that's handled
//     elsewhere; this agent just gets a path through the reflector).
//   - One credential pair per side (no ICE restarts).
//
// We are a tgcalls client speaking through a Telegram reflector that proxies
// UDP between us and the peer, so all checks go to a single reflector IP/port
// and the actual peer candidates only matter for their ufrag binding. We
// still keep them so we can plug a non-relay path in later.
//

#include "../domain/ice_candidate.h"
#include "../infrastructure/ice/stun_message.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace vianigram { namespace voip { namespace application {

enum IceAgentRole {
    IceAgentRole_Controlling,
    IceAgentRole_Controlled
};

struct IceCheckTarget {
    std::string Ip;
    int         Port;

    IceCheckTarget() : Port(0) {}
    IceCheckTarget(const std::string& ip, int port) : Ip(ip), Port(port) {}
};

class IceAgent {
public:
    IceAgent(IceAgentRole role,
             const std::string& localUfrag,
             const std::string& localPwd,
             const std::string& remoteUfrag,
             const std::string& remotePwd);

    // Add a candidate from the peer's "Candidates" message.
    void AddRemoteCandidate(const domain::ParsedIceCandidate& c);

    // Generate a synthetic local "host" + "relay" candidate set we can
    // advertise back to the peer. In tgcalls the reflector address acts as
    // the relay candidate; the peer never connects to our true host
    // address directly.
    std::vector<domain::ParsedIceCandidate> GenerateLocalCandidates(
        const std::vector<std::string>& reflectorIps,
        int reflectorPort);

    // The set of binding-request datagrams we want to send right now.
    // First element is the (ip,port) target; second is the encoded STUN
    // bytes (already MI+FP-protected).
    std::vector<std::pair<IceCheckTarget, std::vector<uint8_t> > >
        GetBindingRequestsToSend();

    enum ProcessResult {
        ProcessResult_Other,
        ProcessResult_BindingRequestProcessed,
        ProcessResult_BindingResponseProcessed,
        ProcessResult_ConnectivityEstablished
    };

    // Process an incoming STUN datagram from `srcIp:srcPort`. If we need to
    // reply (Binding Request), `outResponse` will be populated; otherwise
    // it is left empty.
    ProcessResult ProcessIncoming(const std::string& srcIp, int srcPort,
                                  const std::vector<uint8_t>& bytes,
                                  std::vector<uint8_t>& outResponse);

    bool        IsConnected() const            { return m_connected; }
    std::string GetSelectedRemoteIp() const    { return m_selected.Ip; }
    int         GetSelectedRemotePort() const  { return m_selected.Port; }

    // Visible for tests.
    const std::string& LocalUfrag()  const { return m_localUfrag; }
    const std::string& RemoteUfrag() const { return m_remoteUfrag; }

private:
    struct Pair {
        IceCheckTarget Target;
        bool           Succeeded;
        bool           UseCandidateSent;
        Pair() : Succeeded(false), UseCandidateSent(false) {}
    };

    Pair* FindPair(const std::string& ip, int port);
    std::vector<uint8_t> BuildBindingRequest(bool useCandidate);
    std::vector<uint8_t> BuildBindingResponse(const infrastructure::ice::StunMessage& req,
                                              const std::string& srcIp, int srcPort);
    static void RandomTransactionId(uint8_t out[12]);

    IceAgentRole       m_role;
    std::string        m_localUfrag;
    std::string        m_localPwd;
    std::string        m_remoteUfrag;
    std::string        m_remotePwd;
    uint64_t           m_tieBreak;
    uint32_t           m_priorityCounter;

    std::vector<domain::ParsedIceCandidate> m_remoteCandidates;
    std::vector<IceCheckTarget>             m_checkTargets;
    std::vector<Pair>                       m_pairs;
    bool                                    m_connected;
    IceCheckTarget                          m_selected;
};

}}} // namespace vianigram::voip::application
