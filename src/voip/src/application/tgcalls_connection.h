// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

// TgcallsConnection --- orchestrator for a single tgcalls 2.x (modern,
// layer >= 93) voice call. Owns the per-call state machine that wires
// together five subsystems:
//
//   1. tgcalls v2 JSON Signaling (domain/tgcalls_signaling_*.{h,cpp})
//      — encrypted InitialSetup / Candidates / Pong / MediaState messages
//        carried inside updatePhoneCallSignalingData blobs.
//
//   2. ECDSA-P256 self-signed cert + fingerprint
//      (infrastructure/ecdsa_p256_keypair.{h,cpp}) — used as the local
//      DTLS identity. Fingerprint is exchanged in the first InitialSetup.
//
//   3. ICE/STUN connectivity checks (infrastructure/ice/stun_message.h
//      + application/ice_agent.{h,cpp}) — short-term credential STUN
//      binding requests/responses against the WebRTC reflector(s) listed
//      in the start descriptor.
//
//   4. DTLS 1.2 client handshake
//      (infrastructure/dtls/dtls_client_session.{h,cpp}) — runs once
//      ICE finds a working pair, exports SRTP keying material on
//      completion (RFC 5764, label = "EXTRACTOR-dtls_srtp", 60 bytes).
//
//   5. SRTP packet codec (infrastructure/srtp/srtp_packet_codec.{h,cpp})
//      — AES-128-CM_HMAC_SHA1_80 wrapper around RTP carrying Opus 48k
//        mono frames produced by OpusVoipCodec from the existing
//        WinrtVoipAudioDevice.
//
// Subsystems that are optional at build time are held as forward-declared
// members and only constructed under the VIANIGRAM_VOIP_HAVE_<feature>
// macros, so the wire-up surface area in voip_engine.cpp compiles whether
// or not a given subsystem is present.
//
// Lifecycle (see Start() and HandleIncomingSignaling()):
//
//   ctor + Start():
//     - Generate ECDSA cert + fingerprint.
//     - Generate ICE ufrag (4 chars) + pwd (22 chars).
//     - Build & emit first InitialSetup signaling message via
//       SignalingDataCallback.
//     - Open UDP datagram session(s) to each WebRTC reflector listed
//       in StartParams.ReflectorIps with the matching peer_tag.
//
//   HandleIncomingSignaling() (called when MTProto delivers an
//   updatePhoneCallSignalingData):
//     - Decrypt + parse the blob via TgcallsSignalingEnvelope.
//     - Dispatch each TgcallsMessage:
//         InitialSetup -> capture peer ufrag/pwd/fingerprint, kick ICE.
//         Candidates   -> add to ICE agent.
//         Ping/Pong    -> respond with Pong / drop.
//         MediaState   -> apply remote mute/video state.
//
//   Once ICE produces a working pair (Connected) we kick DTLS handshake.
//   Once DTLS reports Established we export SRTP keying material and
//   start the audio capture/playback loops which feed RTP-over-SRTP
//   datagrams across the reflector.
//
// Threading model: HandleIncomingSignaling is invoked on the WinRT
// signaling delivery thread. Audio I/O runs on the WinrtVoipAudioDevice
// capture/render threads. UDP receive runs on WinRT datagram socket
// callbacks. We serialize state mutations through m_lock; the audio
// hot path holds m_lock only briefly to read the SRTP session pointer
// and the outgoing RTP counters.

#include "../domain/tgcalls_signaling_messages.h"
#include "../domain/voip_call_start_descriptor.h"
#include "../domain/voip_error.h"
#include "../ports/outbound/i_voip_reflector_transport.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure {
class EcdsaP256KeyPair;
class WinrtVoipAudioDevice;
class OpusVoipCodec;
class DatagramSocketReflectorTransport;
namespace turn { class TurnClient; struct TurnAddress; }
}}}

namespace vianigram { namespace voip { namespace application {

// Forward declarations for optional subsystems; the .cpp guards their
// instantiation behind feature macros.
class IceAgent;
class DtlsClientSession;

class TgcallsConnection {
public:
    enum class State {
        Connecting = 0,
        IceConnecting = 1,
        DtlsHandshaking = 2,
        Connected = 3,
        Failed = 4,
        Stopped = 5
    };

    typedef std::function<void(int64_t /*callId*/, const std::vector<uint8_t>& /*encrypted*/)>
        SignalingDataCallback;
    typedef std::function<void(State)> StateCallback;

    struct ReflectorEndpoint {
        std::string Ip;
        std::string Ipv6;
        int Port;
        std::vector<uint8_t> PeerTag;       // 16 bytes per RFC of WebRTC reflector wrap

        // When IsWebRtc=true the endpoint is a TURN server (RFC 5766)
        // requiring long-term credential auth. Username/Password come
        // straight from the phoneConnectionWebrtc TL descriptor; the
        // PeerTag field is unused in this mode (the wire framing is the
        // TURN Send Indication envelope rather than a 16-byte peer_tag
        // prefix).
        bool IsWebRtc;
        std::string Username;
        std::string Password;

        ReflectorEndpoint() : Port(0), IsWebRtc(false) {}
    };

    struct StartParams {
        int64_t CallId;
        bool IsOutgoing;
        std::vector<uint8_t> SharedKey;     // 256 bytes from MTProto DH
        std::vector<ReflectorEndpoint> Reflectors;

        StartParams() : CallId(0), IsOutgoing(false) {}
    };

    TgcallsConnection(
        const StartParams& params,
        SignalingDataCallback signalingOut,
        StateCallback stateChanged);

    ~TgcallsConnection();

    // Bootstrap the call: generate cert + ICE creds, emit our first
    // InitialSetup message via the signaling callback, open UDP
    // session(s) to each WebRTC reflector. Returns the first error
    // encountered or Ok() on success.
    domain::VoipError Start();

    // Called by VoipEngine::ReceiveSignalingData when an MTProto
    // updatePhoneCallSignalingData arrives addressed to this call.
    domain::VoipError HandleIncomingSignaling(
        const std::vector<uint8_t>& encryptedBytes);

    // Tear down the call. Idempotent. Safe to call from any thread.
    void Stop();

    State GetState() const;
    int64_t CallId() const { return m_callId; }

    // Apply local mute / speaker route. These also trigger an
    // outgoing MediaState signaling message so the peer's UI reflects
    // the change.
    domain::VoipError SetMuted(bool muted);
    domain::VoipError SetSpeaker(bool on);

private:
    // ===== signaling out path ============================================
    domain::VoipError EmitInitialSetup();
    domain::VoipError EmitCandidates();
    domain::VoipError EmitMediaState();
    domain::VoipError EmitMessages(
        const std::vector<domain::TgcallsMessage>& messages);

    // ===== signaling in path =============================================
    void OnPeerInitialSetup(const domain::InitialSetupMsg& msg);
    void OnPeerCandidates(const domain::CandidatesMsg& msg);
    void OnPeerPing(const domain::PingMsg& msg);
    void OnPeerMediaState(const domain::MediaStateMsg& msg);

    // ===== reflector packet plumbing =====================================
    // Legacy synchronous overload — retained for any callers that hand a
    // single payload buffer without endpoint context (e.g. unit tests).
    void OnReflectorDatagram(const std::vector<uint8_t>& bytes);

    // Async push entry point: invoked by DatagramSocketReflectorTransport's
    // OpenSession() callback for every inbound datagram. The payload has
    // already been stripped of its 16-byte peer_tag prefix; this classifies
    // the packet and routes it into the ICE / DTLS / SRTP layers.
    void OnReflectorDatagram(
        const std::string& srcIp,
        int srcPort,
        const std::vector<uint8_t>& payload);

    void SendViaReflector(const std::vector<uint8_t>& payload);

    // ===== ICE connectivity-check helpers ================================
    // Pull the next batch of STUN Binding Requests from m_iceAgent and
    // forward each one to its target via SendViaReflector(). All targets
    // currently round-trip through the WebRTC reflector listed in
    // m_reflectors[0] because that is the only path the peer can reach
    // us on through Telegram's signaling fabric.
    void SendIceBindingRequests();

    // Schedule a 500ms periodic timer (capped at ~10 seconds / 20 attempts)
    // that re-issues binding requests until the IceAgent reports a working
    // pair. Cancels itself once we transition out of IceConnecting.
    void StartIceRetryTimer();
    void StopIceRetryTimer();

    // Promotion hook: IceAgent has selected a working pair. Cancels the
    // retry timer and kicks off DTLS by transitioning to DtlsHandshaking.
    void OnIceConnected();

    // ===== phase advancement =============================================
    void StartIcePhase();
    void StartDtlsPhase();
    void PumpDtls(const std::vector<std::vector<uint8_t> >& flights);
    void OnDtlsEstablished(const std::vector<uint8_t>& srtpKeyingMaterial);
    void StartAudioPhase(const std::vector<uint8_t>& srtpKeyingMaterial);
    void StopAudioLoop();

    // ===== audio hot path ================================================
    void OnCapturedFrame(const int16_t* samples, size_t sampleCount);
    void OnSrtpDatagram(const std::vector<uint8_t>& bytes);
    void OnRtpPacket(const std::vector<uint8_t>& rtpBytes);
    void RunAudioCaptureLoop();
    // Win32 thread proc signature: DWORD WINAPI = unsigned long __stdcall.
    // Spelled out long-hand so this header does not have to drag in
    // <windows.h>; the cpp casts the address through CreateThread() with a
    // matching reinterpret_cast<LPTHREAD_START_ROUTINE>.
    static unsigned long __stdcall AudioCaptureThreadProc(void* arg);

    // ===== misc helpers ==================================================
    static std::string GenerateRandomToken(size_t length);
    static uint32_t GenerateRandomUint32();
    void TransitionTo(State newState);

    // ---- immutable members ----------------------------------------------
    int64_t m_callId;
    bool m_isOutgoing;
    std::vector<uint8_t> m_sharedKey;
    std::vector<ReflectorEndpoint> m_reflectors;
    SignalingDataCallback m_signalingOut;
    StateCallback m_stateChanged;

    // ---- mutable state, guarded by m_lock -------------------------------
    mutable std::mutex m_lock;
    State m_state;

    std::unique_ptr<infrastructure::EcdsaP256KeyPair> m_localCert;
    std::string m_localFingerprint;
    std::string m_localUfrag;
    std::string m_localPwd;
    std::string m_localSetupRole;       // "actpass" / "active" / "passive"

    bool m_peerInitialReceived;
    std::string m_peerFingerprintHash;
    std::string m_peerFingerprint;
    std::string m_peerSetup;
    std::string m_peerUfrag;
    std::string m_peerPwd;
    std::vector<std::string> m_peerCandidates;

    std::unique_ptr<IceAgent> m_iceAgent;
    std::unique_ptr<DtlsClientSession> m_dtls;

    // SRTP session state for outbound (we are DTLS client unless peer asked
    // otherwise — we use the client_write_* keys for outgoing packets and
    // the server_write_* keys for incoming packets). The two parameter
    // structs hold session-derived keys + per-direction ROC bookkeeping.
    bool m_srtpReady;
    void* m_srtpOutgoing; // -> infrastructure::srtp::SrtpEncryptParams
    void* m_srtpIncoming; // -> infrastructure::srtp::SrtpEncryptParams

    std::unique_ptr<infrastructure::WinrtVoipAudioDevice> m_audio;
    std::unique_ptr<infrastructure::OpusVoipCodec> m_codec;
    std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> m_socket;

    // Shared async push transport used by the modern reactive path
    // (ICE / DTLS / SRTP state machines that need PUSHED inbound
    // datagrams instead of synchronous Receive polling). One instance
    // hosts one OpenSession() per reflector endpoint we want to listen on.
    std::unique_ptr<infrastructure::DatagramSocketReflectorTransport> m_transport;

    // WebRtc TURN clients. One TurnClient per WebRtc reflector endpoint
    // we enrolled. Outbound STUN/DTLS/SRTP are wrapped in Send Indications
    // by TurnClient::Send; inbound Data Indications are stripped and
    // delivered to OnReflectorDatagram.
    std::vector<std::shared_ptr<infrastructure::turn::TurnClient> > m_turnClients;

    // Audio capture pump — drains m_audio->ReadFrame, encodes via Opus,
    // wraps in RTP, encrypts via SRTP, sends through reflector.
    // Stored as void* (HANDLE) so this header does not have to include
    // <windows.h>. The cpp populates and consumes it as HANDLE.
    void* m_audioCaptureThread;
    volatile long m_audioLoopActive;

    // RTP state
    uint32_t m_localSsrc;
    uint32_t m_remoteSsrc;
    uint16_t m_outgoingSeq;
    uint32_t m_outgoingTimestamp;

    // tgcalls Signaling outer-seq counter (per-direction, monotonic).
    uint32_t m_outgoingSignalingSeq;

    // Mute / speaker (echoed in MediaState messages).
    bool m_muted;
    bool m_speakerOn;

    // True once StartIcePhase() has emitted its summary log line and
    // (eventually) handed control to IceAgent. Prevents the same phase
    // transition from running twice when both InitialSetup and the first
    // Candidates message arrive.
    bool m_iceStarted;

    // Periodic ThreadPoolTimer that re-issues binding requests until ICE
    // converges or we time out. Owned via the C++/CX hat handle stored
    // in tgcalls_connection.cpp's translation unit (so consumers of this
    // header don't have to pull in <windows.system.threading.h>). We hold
    // a void* alias here that resolves at runtime to the same handle.
    void* m_iceRetryTimer;

    // Number of binding-request retransmits issued so far. Capped to 20
    // (~10 seconds at 500ms cadence) before we give up and fail the call.
    int m_iceAttempts;

    // Synthetic UDP port advertised in our SDP "candidate:" lines.
    // The actual datagram session is owned by m_socket; the port we
    // advertise here is informational because the WebRTC reflector
    // relays packets based on peer_tag rather than IP/port.
    uint16_t m_localUdpPort;

    // Stop + audio thread coordination.
    volatile long m_stopped;            // 0 = running, 1 = stop requested

    // tx/rx counters for VoipEngine::GetMediaSnapshot. They let
    // GetMediaSnapshot surface UDP traffic from the tgcalls path (the
    // classic m_mediaSession counters stay at 0 on this path). Mutated
    // from multiple threads:
    //   - SendViaReflector / SendIceBindingRequests on caller threads
    //   - OnReflectorDatagram on the WinRT thread-pool MessageReceived
    //     callback
    // so they MUST be atomic; relaxed memory order is fine because the
    // values are observability-only (not used as program state).
    std::atomic<uint64_t> m_txPackets;
    std::atomic<uint64_t> m_rxPackets;
    std::atomic<uint64_t> m_txBytes;
    std::atomic<uint64_t> m_rxBytes;

public:
    // Stat snapshot used by VoipEngine::GetMediaSnapshot when the tgcalls
    // path is active. Returns counters by value (atomic loads, relaxed).
    struct StatsSnapshot {
        uint64_t TxPackets;
        uint64_t RxPackets;
        uint64_t TxBytes;
        uint64_t RxBytes;
        State CurrentState;
    };
    StatsSnapshot GetStatsSnapshot() const;

private:
    TgcallsConnection(const TgcallsConnection&);
    TgcallsConnection& operator=(const TgcallsConnection&);
};

}}} // namespace vianigram::voip::application
