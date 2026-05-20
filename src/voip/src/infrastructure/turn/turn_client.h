// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
//
// turn_client.h --- minimal RFC 5766 TURN allocation client used by the
// tgcalls 2.x WebRtc reflector path.
//
// TgcallsConnection drives this so that for every phoneConnectionWebrtc
// descriptor we
//
//   1. Open a UDP socket to (reflectorIp, reflectorPort=1400).
//   2. Send Allocate Request (no auth) and wait for the 401 challenge that
//      carries REALM + NONCE.
//   3. Re-send Allocate Request with USERNAME + REALM + NONCE +
//      MESSAGE-INTEGRITY (key = MD5(username:realm:password)). The server
//      replies 200 OK with XOR-RELAYED-ADDRESS = our public allocated
//      address on the reflector.
//   4. For each peer's relay candidate address, send CreatePermission so
//      the reflector starts forwarding our Send Indications to that peer.
//   5. Subsequent outbound STUN/DTLS/SRTP bytes travel as Send Indications
//      (TurnClient::Send). Inbound bytes from the peer arrive as Data
//      Indications which we strip and deliver via the configured
//      DataCallback to TgcallsConnection::OnReflectorDatagram.
//
// Lifecycle / threading model mirrors DatagramSocketReflectorTransport:
//   - The MessageReceived event runs on a WinRT thread-pool thread; we
//     hold a std::weak_ptr<State> so a teardown that flips m_active=false
//     is visible without overlapping shared_ptr / function destruction.
//   - OpenAllocation() blocks the calling thread (PPL .get()) for up to
//     ~5 s while the Allocate handshake completes. This matches the
//     synchronous open pattern already used by the existing transport.
//

#include "../../domain/voip_error.h"
#include "turn_message.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace turn {

class TurnClient {
public:
    // Inbound payload delivered by Data Indications. Source is the
    // *peer* address (as decoded from XOR-PEER-ADDRESS), NOT the reflector.
    typedef std::function<void(const std::string& srcIp,
                               int srcPort,
                               const std::vector<uint8_t>& payload)>
        DataCallback;

    TurnClient();
    ~TurnClient();

    // Open one TURN allocation against a single WebRtc reflector with the
    // long-term credentials provided in the phoneConnectionWebrtc TL
    // descriptor. peerAddresses is the initial set of peer relay
    // candidates we want to send to (CreatePermission). Additional peer
    // permissions can be added later via AddPeerPermission(). Returns Ok
    // on a successful 200 OK Allocate response with relayed address.
    domain::VoipError OpenAllocation(
        const std::string& reflectorIp, int reflectorPort,
        const std::string& username, const std::string& password,
        const std::vector<TurnAddress>& peerAddresses,
        DataCallback onDataIndication);

    // Send arbitrary inner bytes to a permitted peer. Wraps in Send
    // Indication. Returns TransportFailed if the underlying UDP send
    // failed; InvalidArgument if the allocation isn't open.
    domain::VoipError Send(const TurnAddress& peer,
                           const std::vector<uint8_t>& bytes);

    // Returns the XOR-RELAYED-ADDRESS we got allocated, or an Address with
    // empty bytes if not yet allocated.
    TurnAddress RelayedAddress() const;

    // Update peer permissions when fresh peer Candidates arrive.
    domain::VoipError AddPeerPermission(const TurnAddress& peer);

    // Reflector endpoint we opened against. Used by TgcallsConnection to
    // route outbound traffic to the matching client.
    std::string ReflectorIp() const { return m_reflectorIp; }
    int ReflectorPort() const { return m_reflectorPort; }

    bool IsAllocated() const { return m_allocated.load(std::memory_order_acquire); }

    // Tear down. Detaches handlers, releases socket. Idempotent.
    void Close();

private:
    // Pending request we are waiting on, looked up by transaction-id.
    struct PendingRequest {
        uint8_t  TxnId[12];
        bool     Completed;
        TurnMessage Response;
        PendingRequest() : Completed(false) {
            for (int i = 0; i < 12; i++) TxnId[i] = 0;
        }
    };

    domain::VoipError DoAllocateHandshake(); // blocks up to ~5s
    domain::VoipError SendCreatePermission(const std::vector<TurnAddress>& peers);
    domain::VoipError SendRawDatagram(const std::vector<uint8_t>& bytes);

    void OnInboundUdp(const std::vector<uint8_t>& bytes);
    void GenerateTxnId(uint8_t out[12]);

    // Wait for a response matching the supplied transaction id (or the
    // first 401 / 200 message belonging to the pending Allocate request).
    bool WaitForResponse(const uint8_t txnId[12], int timeoutMs, TurnMessage& out);

    mutable std::mutex m_lock;
    std::atomic<bool>  m_active;
    std::atomic<bool>  m_allocated;

    // Allocation cache.
    std::string m_realm;
    std::vector<uint8_t> m_nonce;
    std::vector<uint8_t> m_key;        // MD5(user:realm:pwd)
    std::string m_username;
    std::string m_password;
    TurnAddress m_relayed;             // our XOR-RELAYED-ADDRESS
    std::vector<TurnAddress> m_permittedPeers;

    DataCallback m_onData;
    std::string m_reflectorIp;
    int m_reflectorPort;

    // Latest pending request (Allocate / CreatePermission / Refresh) the
    // synchronous helpers are waiting on. Only one outstanding request at
    // a time is supported -- the helpers serialize via DoAllocateHandshake
    // and SendCreatePermission. Indications (Data) skip this path entirely.
    bool m_havePending;
    uint8_t m_pendingTxnId[12];
    bool m_pendingComplete;
    TurnMessage m_pendingResponse;
    std::condition_variable m_pendingCv;

    // The PIMPL-ish socket holder lives in the cpp so this header doesn't
    // have to drag in <ppltasks.h> / Windows::Networking.
    struct SocketState;
    std::shared_ptr<SocketState> m_socketState;

    TurnClient(const TurnClient&);
    TurnClient& operator=(const TurnClient&);
};

}}}} // namespace vianigram::voip::infrastructure::turn
