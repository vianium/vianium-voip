// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

// DatagramSocketReflectorTransport
// --------------------------------
// Two-mode WinRT DatagramSocket-backed transport for the Telegram VoIP
// WebRTC reflector at port 1400.
//
// Mode A — synchronous (legacy): ProbeSelfInfo + CreateDatagramSession.
//   These power the older libtgvoip-style reflector poll path (port
//   596/598/599 wire format) where a worker thread spins up a session
//   and pumps Send/Receive against a single endpoint. Used by the
//   classic VoIP loop and self-info probes.
//
// Mode B — async push: OpenSession / SendThroughSession /
//   CloseSession. These power the tgcalls v2 TgcallsConnection
//   orchestrator. ICE/DTLS/SRTP are reactive state machines: they need
//   inbound packets to be PUSHED to a callback, not pulled by a worker
//   thread. Mode B owns the WinRT MessageReceived plumbing and strips
//   the 16-byte peer_tag prefix before delivering the inner payload to
//   the registered handler.
//
// Wire format on port 1400 (WebRTC reflector, both directions):
//
//     [16-byte peer_tag][actual_payload]
//
// The peer_tag is the per-call shared identifier the reflector matches
// on. Outbound, we prepend our local peer_tag. Inbound, the reflector
// echoes our peer_tag back; we strip it and hand the inner payload
// (STUN binding response / DTLS record / SRTP packet) to the callback.
//
// Mode A and Mode B share the same DatagramSocketReflectorTransport
// instance — a single transport object can host both legacy synchronous
// sessions and modern async push sessions concurrently. They live on
// disjoint sockets so they don't interfere.

#include "../ports/outbound/i_voip_reflector_transport.h"
#include "../domain/voip_error.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure {

class DatagramSocketReflectorTransport : public ports::outbound::IVoipReflectorTransport {
public:
    DatagramSocketReflectorTransport();
    virtual ~DatagramSocketReflectorTransport();

    // ---- Mode A: legacy synchronous probe / session API -----------------
    virtual ports::outbound::VoipReflectorProbeResult ProbeSelfInfo(
        const domain::VoipEndpoint& endpoint,
        uint64_t queryId,
        int timeoutMs);

    virtual std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> CreateDatagramSession();

    // ---- Mode B: async push receive -------------------------------------
    //
    // Callback is invoked from the WinRT DatagramSocket MessageReceived
    // worker thread for every datagram delivered to the local UDP socket
    // bound to (reflectorIp, reflectorPort). The payload is the raw
    // bytes AFTER the 16-byte peer_tag prefix has been stripped — the
    // caller sees pure ICE/DTLS/SRTP packets and never touches the
    // reflector wire format.
    typedef std::function<void(
        const std::string& reflectorIp,
        int reflectorPort,
        const std::vector<uint8_t>& payload)>
        AsyncReceiveCallback;

    // Open a long-lived UDP session to (reflectorIp, reflectorPort) with
    // the given 16-byte peer_tag and register a push callback for inbound
    // datagrams. Multiple sessions can coexist on a single transport
    // instance — they're keyed by (ip, port). Returns Ok on success or a
    // structured VoipError describing the WinRT failure.
    domain::VoipError OpenSession(
        const std::string& reflectorIp,
        int reflectorPort,
        const std::vector<uint8_t>& peerTag,
        AsyncReceiveCallback onPacket);

    // Send a payload through an existing session. The 16-byte peer_tag
    // wrap is added internally; the caller passes the pure inner payload.
    domain::VoipError SendThroughSession(
        const std::string& reflectorIp,
        int reflectorPort,
        const std::vector<uint8_t>& payload);

    // Close all open sessions. Idempotent. Each session's MessageReceived
    // handler is detached and the underlying DatagramSocket is released
    // so RAII closes the UDP port.
    void CloseSession();

private:
    struct Session;

    std::mutex m_sessionsMutex;
    std::vector<std::shared_ptr<Session> > m_sessions;

    DatagramSocketReflectorTransport(const DatagramSocketReflectorTransport&);
    DatagramSocketReflectorTransport& operator=(const DatagramSocketReflectorTransport&);
};

}}} // namespace vianigram::voip::infrastructure
