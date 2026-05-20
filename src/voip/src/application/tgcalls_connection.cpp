// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_connection.h"

#include "../domain/tgcalls_signaling_envelope.h"
#include "../domain/ice_candidate.h"
#include "../infrastructure/ecdsa_p256_keypair.h"
#include "../infrastructure/opus_voip_codec.h"
#include "../infrastructure/winrt_voip_audio_device.h"
#include "../infrastructure/datagram_socket_reflector_transport.h"
#include "../infrastructure/turn/turn_client.h"
#include "../infrastructure/turn/turn_message.h"

#include <vianium/crypto/random.h>

#include <cstring>
#include <cstdlib>
#include <sstream>
#include <windows.h>

// The v120_wp81 toolset (VS2013) does not support __has_include (C++17),
// so the optional subsystems are included unconditionally and their
// VIANIGRAM_VOIP_HAVE_<feature> macros are defined here.
#include "ice_agent.h"
#define VIANIGRAM_VOIP_HAVE_ICE_AGENT 1

#include "dtls_client_session.h"

#include "../infrastructure/srtp/srtp_packet_codec.h"
#include "../infrastructure/srtp/srtp_session_keys.h"
#define VIANIGRAM_VOIP_HAVE_SRTP_CODEC 1

namespace vianigram { namespace voip { namespace application {

namespace {

const size_t kSharedKeySize = 256;
const size_t kPeerTagSize = 16;
const size_t kReflectorWebrtcPort = 1400;

void Trace(const std::string& line) {
    std::string out = "[TgcallsConnection] " + line + "\n";
    ::OutputDebugStringA(out.c_str());
}

void TraceFmt(const char* fmt) {
    if (fmt == nullptr) return;
    Trace(std::string(fmt));
}

// Lifted from voip_engine.cpp so we don't have to expose a domain
// helper. Returns "Connecting" / "IceConnecting" / etc.
const char* StateLabel(TgcallsConnection::State s) {
    switch (s) {
        case TgcallsConnection::State::Connecting: return "Connecting";
        case TgcallsConnection::State::IceConnecting: return "IceConnecting";
        case TgcallsConnection::State::DtlsHandshaking: return "DtlsHandshaking";
        case TgcallsConnection::State::Connected: return "Connected";
        case TgcallsConnection::State::Failed: return "Failed";
        case TgcallsConnection::State::Stopped: return "Stopped";
    }
    return "Unknown";
}

// The WebRTC reflector at port 1400 frames every UDP packet as
//   peer_tag (16 bytes) || inner_payload
// The reflector matches on peer_tag and forwards the inner payload
// to the peer that registered with the matching tag. We do the wrap
// on the way out and the strip on the way in.
std::vector<uint8_t> WrapWithPeerTag(
    const std::vector<uint8_t>& peerTag,
    const std::vector<uint8_t>& inner)
{
    std::vector<uint8_t> packet;
    packet.reserve(peerTag.size() + inner.size());
    packet.insert(packet.end(), peerTag.begin(), peerTag.end());
    packet.insert(packet.end(), inner.begin(), inner.end());
    return packet;
}

bool TryStripPeerTag(
    const std::vector<uint8_t>& packet,
    std::vector<uint8_t>& outInner)
{
    if (packet.size() < kPeerTagSize) return false;
    outInner.assign(packet.begin() + kPeerTagSize, packet.end());
    return true;
}

domain::VoipError MakeError(domain::VoipErrorKind kind, const std::string& message) {
    return domain::VoipError::Of(kind, 0, message.c_str());
}

domain::VoipError MakeUnavailable(const std::string& message) {
    return domain::VoipError::Unavailable(message.c_str());
}

domain::VoipError MakeInvalid(const std::string& message) {
    return MakeError(domain::VoipErrorKind::InvalidArgument, message);
}

} // anonymous namespace

// ===========================================================================
// Construction / destruction
// ===========================================================================

TgcallsConnection::TgcallsConnection(
    const StartParams& params,
    SignalingDataCallback signalingOut,
    StateCallback stateChanged)
    : m_callId(params.CallId),
      m_isOutgoing(params.IsOutgoing),
      m_sharedKey(params.SharedKey),
      m_reflectors(params.Reflectors),
      m_signalingOut(signalingOut),
      m_stateChanged(stateChanged),
      m_state(State::Connecting),
      m_localFingerprint(),
      m_localUfrag(),
      m_localPwd(),
      m_localSetupRole(params.IsOutgoing ? "actpass" : "passive"),
      m_peerInitialReceived(false),
      m_srtpReady(false),
      m_srtpOutgoing(nullptr),
      m_srtpIncoming(nullptr),
      m_audioCaptureThread(nullptr),
      m_audioLoopActive(0),
      m_localSsrc(0),
      m_remoteSsrc(0),
      m_outgoingSeq(0),
      m_outgoingTimestamp(0),
      m_outgoingSignalingSeq(0),
      m_muted(false),
      m_speakerOn(false),
      m_iceStarted(false),
      m_iceRetryTimer(nullptr),
      m_iceAttempts(0),
      m_localUdpPort(0),
      m_stopped(0),
      m_txPackets(0),
      m_rxPackets(0),
      m_txBytes(0),
      m_rxBytes(0)
{
    std::ostringstream s;
    s << "ctor callId=" << static_cast<long long>(m_callId)
      << " outgoing=" << (m_isOutgoing ? "yes" : "no")
      << " sharedKey=" << m_sharedKey.size() << "B"
      << " reflectors=" << m_reflectors.size();
    Trace(s.str());
}

TgcallsConnection::~TgcallsConnection() {
    Stop();
    Trace("dtor");
}

// ===========================================================================
// Lifecycle: Start
// ===========================================================================

domain::VoipError TgcallsConnection::Start() {
    Trace("Start invoked");

    if (m_sharedKey.size() != kSharedKeySize) {
        return MakeInvalid("tgcalls connection requires a 256-byte shared key");
    }
    if (m_reflectors.empty()) {
        return MakeInvalid("tgcalls connection requires at least one WebRTC reflector endpoint");
    }
    if (!m_signalingOut) {
        return MakeInvalid("tgcalls connection requires a SignalingDataCallback");
    }

    // ---- 1. Generate our DTLS identity --------------------------------
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_localCert = infrastructure::EcdsaP256KeyPair::Generate();
    }
    if (m_localCert == nullptr) {
        TransitionTo(State::Failed);
        return MakeError(
            domain::VoipErrorKind::CryptoUnavailable,
            "platform ECDSA-P256 provider is unavailable");
    }
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_localFingerprint = m_localCert->ToSha256Fingerprint();
    }

    // ---- 2. Generate ICE short-term credentials -----------------------
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_localUfrag = GenerateRandomToken(4);
        m_localPwd = GenerateRandomToken(22);
        m_localSsrc = GenerateRandomUint32();
        // Synthesize a stable non-zero UDP port (1024..65535) for SDP
        // candidate lines. Reflector-relayed packets do not actually
        // bind to this port; the value is informational so the peer's
        // SDP parser can construct a valid candidate.
        uint16_t port = static_cast<uint16_t>((m_localSsrc & 0xFFFF) | 0x4000);
        if (port < 1024) port = static_cast<uint16_t>(port + 1024);
        m_localUdpPort = port;
    }

    {
        std::ostringstream s;
        s << "identity ufrag=" << m_localUfrag
          << " pwd_len=" << m_localPwd.size()
          << " fp=" << m_localFingerprint
          << " ssrc=" << m_localSsrc;
        Trace(s.str());
    }

    // ---- 3. Emit our first InitialSetup signaling message -------------
    domain::VoipError emitted = EmitInitialSetup();
    if (!emitted.IsOk()) {
        TransitionTo(State::Failed);
        return emitted;
    }

    // ---- 4. Open UDP socket(s) to the reflectors ----------------------
    // Only the first reflector is opened here: the engine's
    // DatagramSocketReflectorTransport::CreateDatagramSession() yields a
    // session bound to a single endpoint. Multi-reflector ICE is handled
    // by the async push sessions opened in step 5 below.
    {
        infrastructure::DatagramSocketReflectorTransport transport;
        std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> socket =
            transport.CreateDatagramSession();
        if (socket == nullptr) {
            TransitionTo(State::Failed);
            return MakeError(
                domain::VoipErrorKind::TransportFailed,
                "failed to create reflector datagram session");
        }

        const ReflectorEndpoint& first = m_reflectors[0];
        domain::VoipEndpoint native;
        native.Ip = first.Ip;
        native.Ipv6 = first.Ipv6;
        native.Port = first.Port;
        native.PeerTag = first.PeerTag;
        native.IsWebRtc = true;

        ports::outbound::VoipReflectorDatagramResult open = socket->Open(native);
        if (!open.Success) {
            TransitionTo(State::Failed);
            return MakeError(
                domain::VoipErrorKind::TransportFailed,
                std::string("reflector open failed: ") + open.Error);
        }

        std::lock_guard<std::mutex> lock(m_lock);
        m_socket = std::move(socket);
    }

    // ---- 5. Open async push sessions for the modern reactive path -----
    // ICE / DTLS / SRTP state machines are reactive — they need PUSHED
    // inbound datagrams (callback-driven), not pull-based Receive() polling.
    //
    // Two transport modes coexist:
    //   - Classic Reflector (peer_tag=16B): DatagramSocketReflectorTransport
    //     wraps payload with peer_tag and strips it on receive.
    //   - WebRtc TURN: TurnClient runs Allocate / CreatePermission
    //     against port 1400 and wraps every outbound datagram in a Send
    //     Indication; inbound Data Indications are stripped and delivered
    //     to OnReflectorDatagram.
    {
        std::unique_ptr<infrastructure::DatagramSocketReflectorTransport> transport(
            new infrastructure::DatagramSocketReflectorTransport());
        std::vector<std::shared_ptr<infrastructure::turn::TurnClient> > turnClients;

        TgcallsConnection* self = this;
        for (size_t i = 0; i < m_reflectors.size(); i++) {
            const ReflectorEndpoint& ep = m_reflectors[i];
            if (ep.Ip.empty()) {
                std::ostringstream s;
                s << "skipping reflector index=" << i << " — empty Ip";
                Trace(s.str());
                continue;
            }

            if (ep.IsWebRtc) {
                // WebRtc TURN endpoint (port 1400). Allocate runs
                // synchronously inside OpenAllocation up to ~5s.
                if (ep.Username.empty() || ep.Password.empty()) {
                    std::ostringstream s;
                    s << "skipping WebRtc reflector " << ep.Ip << ":" << ep.Port
                      << " — missing username/password";
                    Trace(s.str());
                    continue;
                }
                std::shared_ptr<infrastructure::turn::TurnClient> client =
                    std::make_shared<infrastructure::turn::TurnClient>();
                infrastructure::turn::TurnClient::DataCallback cb =
                    [self](const std::string& srcIp,
                           int srcPort,
                           const std::vector<uint8_t>& payload) {
                        if (self == nullptr) return;
                        self->OnReflectorDatagram(srcIp, srcPort, payload);
                    };
                domain::VoipError opened = client->OpenAllocation(
                    ep.Ip, ep.Port,
                    ep.Username, ep.Password,
                    /*peerAddresses=*/std::vector<infrastructure::turn::TurnAddress>(),
                    cb);
                if (!opened.IsOk()) {
                    std::ostringstream s;
                    s << "TurnClient OpenAllocation failed for "
                      << ep.Ip << ":" << ep.Port << " — " << opened.Message;
                    Trace(s.str());
                    continue;
                }
                infrastructure::turn::TurnAddress relayed = client->RelayedAddress();
                std::ostringstream s;
                s << "TurnClient Allocate -> " << ep.Ip << ":" << ep.Port
                  << " OK relayed=" << infrastructure::turn::FormatAddress(relayed);
                Trace(s.str());
                turnClients.push_back(client);
                continue;
            }

            // Classic Reflector path.
            if (ep.PeerTag.size() != kPeerTagSize) {
                std::ostringstream s;
                s << "skipping async open for reflector " << ep.Ip << ":" << ep.Port
                  << " — peer_tag is " << ep.PeerTag.size() << "B (need 16)";
                Trace(s.str());
                continue;
            }

            domain::VoipError opened = transport->OpenSession(
                ep.Ip, ep.Port, ep.PeerTag,
                [self](const std::string& srcIp,
                       int srcPort,
                       const std::vector<uint8_t>& payload) {
                    if (self == nullptr) return;
                    self->OnReflectorDatagram(srcIp, srcPort, payload);
                });

            if (!opened.IsOk()) {
                std::ostringstream s;
                s << "Failed to open reflector " << ep.Ip << ":" << ep.Port
                  << " — " << opened.Message;
                Trace(s.str());
                // Continue: a single reflector failure is non-fatal as long
                // as another reflector succeeds. ICE will discover that.
            } else {
                std::ostringstream s;
                s << "Async session opened on reflector " << ep.Ip << ":" << ep.Port
                  << " (peer_tag=16B)";
                Trace(s.str());
            }
        }

        std::lock_guard<std::mutex> lock(m_lock);
        m_transport = std::move(transport);
        m_turnClients.swap(turnClients);
    }

    TransitionTo(State::IceConnecting);
    Trace("Start completed; awaiting peer InitialSetup + Candidates");
    return domain::VoipError::Ok();
}

// ===========================================================================
// Lifecycle: HandleIncomingSignaling
// ===========================================================================

domain::VoipError TgcallsConnection::HandleIncomingSignaling(
    const std::vector<uint8_t>& encryptedBytes)
{
    if (encryptedBytes.empty()) {
        return MakeInvalid("empty signaling payload");
    }
    if (m_sharedKey.size() != kSharedKeySize) {
        return MakeInvalid("tgcalls connection has no shared key");
    }

    // TgcallsSignalingEnvelope::Decrypt does AES-CTR -> seq strip ->
    // channel frame split -> JSON parse, returning a vector of decoded
    // TgcallsMessage records.
    std::vector<domain::TgcallsMessage> messages =
        domain::TgcallsSignalingEnvelope::Decrypt(
            m_sharedKey, m_isOutgoing, encryptedBytes);

    if (messages.empty()) {
        std::ostringstream s;
        s << "HandleIncomingSignaling decrypt yielded no messages bytes=" << encryptedBytes.size();
        Trace(s.str());
        return domain::VoipError::Ok();
    }

    for (size_t i = 0; i < messages.size(); i++) {
        const domain::TgcallsMessage& m = messages[i];
        switch (m.Type) {
            case domain::TgcallsMessageType_InitialSetup:
                OnPeerInitialSetup(m.Initial);
                break;
            case domain::TgcallsMessageType_Candidates:
                OnPeerCandidates(m.Candidates);
                break;
            case domain::TgcallsMessageType_Ping:
                OnPeerPing(m.Ping);
                break;
            case domain::TgcallsMessageType_MediaState:
            case domain::TgcallsMessageType_RemoteMediaState:
                OnPeerMediaState(m.MediaState);
                break;
            default: {
                std::ostringstream s;
                s << "ignoring peer signaling type=" << m.TypeName;
                Trace(s.str());
                break;
            }
        }
    }
    return domain::VoipError::Ok();
}

// ===========================================================================
// Lifecycle: Stop
// ===========================================================================

void TgcallsConnection::Stop() {
    long previous = ::InterlockedExchange(&m_stopped, 1);
    if (previous != 0) return;

    Trace("Stop invoked");

    // Stop the audio capture pump first so it can't race with the audio
    // device close below. The pump observes m_audioLoopActive and drops
    // out at its next iteration; we then join the thread.
    StopAudioLoop();

    // Cancel any pending ICE retransmit timer. StopIceRetryTimer is
    // idempotent and safe to call even if the timer was never armed.
    StopIceRetryTimer();

    std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> socket;
    std::unique_ptr<infrastructure::DatagramSocketReflectorTransport> transport;
    std::unique_ptr<infrastructure::WinrtVoipAudioDevice> audio;
    std::unique_ptr<infrastructure::OpusVoipCodec> codec;
    std::unique_ptr<infrastructure::EcdsaP256KeyPair> cert;
    std::unique_ptr<DtlsClientSession> dtls;
    std::unique_ptr<IceAgent> iceAgent;
    void* srtpOut = nullptr;
    void* srtpIn = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        socket = std::move(m_socket);
        transport = std::move(m_transport);
        audio = std::move(m_audio);
        codec = std::move(m_codec);
        cert = std::move(m_localCert);
        dtls = std::move(m_dtls);
        iceAgent = std::move(m_iceAgent);
        srtpOut = m_srtpOutgoing;
        srtpIn = m_srtpIncoming;
        m_srtpOutgoing = nullptr;
        m_srtpIncoming = nullptr;
        m_srtpReady = false;
        m_state = State::Stopped;
    }

    if (audio != nullptr) {
        audio->Close();
    }
    if (codec != nullptr) {
        codec->Destroy();
    }
    if (socket != nullptr) {
        socket->Close();
    }
    if (transport != nullptr) {
        // Detach all MessageReceived handlers and release the underlying
        // DatagramSocket(s); the unique_ptr destructor below would do it
        // anyway but calling explicitly here makes the trace ordering
        // deterministic and ensures sockets close before audio threads
        // exit (avoids a stray callback firing on a half-torn-down state).
        transport->CloseSession();
    }
    // The SrtpEncryptParams blobs are allocated with `new` in
    // OnDtlsEstablished and snapshotted under m_lock here as void*.
    // Release them now that no thread can read them.
    if (srtpOut != nullptr) {
        delete reinterpret_cast<infrastructure::srtp::SrtpEncryptParams*>(srtpOut);
    }
    if (srtpIn != nullptr) {
        delete reinterpret_cast<infrastructure::srtp::SrtpEncryptParams*>(srtpIn);
    }
    (void)cert;
    (void)dtls;
    (void)iceAgent;

    if (m_stateChanged) {
        m_stateChanged(State::Stopped);
    }
}

void TgcallsConnection::StopAudioLoop() {
    HANDLE thread = NULL;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        ::InterlockedExchange(&m_audioLoopActive, 0);
        thread = reinterpret_cast<HANDLE>(m_audioCaptureThread);
        m_audioCaptureThread = nullptr;
    }
    if (thread != NULL) {
        // 2s grace; the loop polls m_audioLoopActive every iteration so
        // it should exit well within a single 60ms frame interval.
        ::WaitForSingleObjectEx(thread, 2000, FALSE);
        ::CloseHandle(thread);
    }
}

// ===========================================================================
// State accessors
// ===========================================================================

TgcallsConnection::State TgcallsConnection::GetState() const {
    std::lock_guard<std::mutex> lock(m_lock);
    return m_state;
}

void TgcallsConnection::TransitionTo(State newState) {
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_state == newState) return;
        m_state = newState;
    }
    {
        std::ostringstream s;
        s << "state -> " << StateLabel(newState);
        Trace(s.str());
    }
    if (m_stateChanged) {
        m_stateChanged(newState);
    }
}

domain::VoipError TgcallsConnection::SetMuted(bool muted) {
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_muted = muted;
        if (m_audio) m_audio->SetMuted(muted);
    }
    return EmitMediaState();
}

domain::VoipError TgcallsConnection::SetSpeaker(bool on) {
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_speakerOn = on;
        if (m_audio) m_audio->SetSpeaker(on);
    }
    return domain::VoipError::Ok();
}

// ===========================================================================
// Outgoing signaling
// ===========================================================================

domain::VoipError TgcallsConnection::EmitInitialSetup() {
    domain::TgcallsMessage msg;
    msg.Type = domain::TgcallsMessageType_InitialSetup;
    msg.TypeName = "InitialSetup";
    msg.Initial.Ufrag = m_localUfrag;
    msg.Initial.Pwd = m_localPwd;
    msg.Initial.SupportsRenomination = false;
    msg.Initial.Fingerprint.Hash = "sha-256";
    msg.Initial.Fingerprint.Setup = m_localSetupRole;
    msg.Initial.Fingerprint.Fingerprint = m_localFingerprint;

    std::vector<domain::TgcallsMessage> batch;
    batch.push_back(msg);
    return EmitMessages(batch);
}

namespace {

// Convert a Platform::String^ (UTF-16) to a std::string (UTF-8).
// IPv4/IPv6 textual forms are pure ASCII so a straight cast is sufficient
// here, but we substitute '?' for any non-ASCII character defensively in
// case a future caller passes through a NetbiosName / DNS string.
std::string PlatformStringToUtf8(Platform::String^ s) {
    if (s == nullptr) return std::string();
    const wchar_t* w = s->Data();
    if (w == nullptr) return std::string();
    std::string out;
    out.reserve(s->Length());
    for (unsigned int i = 0; i < s->Length(); i++) {
        wchar_t ch = w[i];
        if (ch < 0x80) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('?');
        }
    }
    return out;
}

bool IsLocalCandidateIp(const std::string& ip) {
    if (ip.empty()) return false;
    // Skip loopback v4 + v6.
    if (ip == "127.0.0.1" || ip == "::1") return false;
    // Skip IPv6 link-local fe80::/10.
    if (ip.size() >= 4) {
        char a = ip[0], b = ip[1], c = ip[2], d = ip[3];
        if ((a == 'f' || a == 'F') && (b == 'e' || b == 'E') &&
            (c == '8' || c == '9') &&
            (d == '0' || d == '1')) {
            return false;
        }
    }
    // Skip embedded zone IDs we don't want to advertise (e.g. fe80::1%4).
    if (ip.find('%') != std::string::npos) return false;
    return true;
}

} // anonymous namespace

domain::VoipError TgcallsConnection::EmitCandidates() {
    domain::TgcallsMessage msg;
    msg.Type = domain::TgcallsMessageType_Candidates;
    msg.TypeName = "Candidates";

    // Snapshot the bits we need under the lock so we don't hold it
    // across the WinRT GetHostNames() call (which can take a few ms).
    std::string ufragSnapshot;
    uint16_t portSnapshot = 0;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        ufragSnapshot = m_localUfrag;
        portSnapshot = m_localUdpPort;
    }

    int foundationCounter = 1;
    try {
        Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName^>^ hostNames =
            Windows::Networking::Connectivity::NetworkInformation::GetHostNames();
        if (hostNames != nullptr) {
            for (unsigned int i = 0; i < hostNames->Size; i++) {
                Windows::Networking::HostName^ host = hostNames->GetAt(i);
                if (host == nullptr) continue;
                if (host->Type != Windows::Networking::HostNameType::Ipv4 &&
                    host->Type != Windows::Networking::HostNameType::Ipv6) {
                    continue;
                }
                std::string ip = PlatformStringToUtf8(host->CanonicalName);
                if (!IsLocalCandidateIp(ip)) continue;

                // RFC 5245 priority for host/component=1 with default prefs:
                // type_pref(126)<<24 | local_pref(65535)<<8 | (256-1) = 2122194688.
                // This is the value Telegram clients emit on the wire.
                std::ostringstream sdp;
                sdp << "candidate:" << foundationCounter
                    << " 1 udp 2122194688 "
                    << ip << " " << portSnapshot
                    << " typ host generation 0 ufrag " << ufragSnapshot
                    << " network-id " << foundationCounter
                    << " network-cost 10";

                domain::IceCandidate cand;
                cand.SdpString = sdp.str();
                msg.Candidates.Candidates.push_back(cand);
                foundationCounter++;
            }
        }
    } catch (Platform::Exception^ ex) {
        std::ostringstream s;
        s << "GetHostNames failed: hr=0x" << std::hex << ex->HResult;
        Trace(s.str());
    }

    {
        std::ostringstream s;
        s << "EmitCandidates produced " << msg.Candidates.Candidates.size()
          << " local candidate(s) port=" << portSnapshot;
        Trace(s.str());
    }

    std::vector<domain::TgcallsMessage> batch;
    batch.push_back(msg);
    return EmitMessages(batch);
}

domain::VoipError TgcallsConnection::EmitMediaState() {
    domain::TgcallsMessage msg;
    msg.Type = domain::TgcallsMessageType_MediaState;
    msg.TypeName = "MediaState";
    msg.MediaState.IsMuted = m_muted;
    msg.MediaState.VideoState = "inactive";
    msg.MediaState.ScreencastState = "inactive";
    msg.MediaState.VideoRotation = 0;
    msg.MediaState.LowBattery = false;

    std::vector<domain::TgcallsMessage> batch;
    batch.push_back(msg);
    return EmitMessages(batch);
}

domain::VoipError TgcallsConnection::EmitMessages(
    const std::vector<domain::TgcallsMessage>& messages)
{
    if (!m_signalingOut) {
        return MakeInvalid("no signaling callback");
    }
    if (messages.empty()) {
        return domain::VoipError::Ok();
    }

    uint32_t seq = 0;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_outgoingSignalingSeq += 1;
        seq = m_outgoingSignalingSeq;
    }

    std::vector<uint8_t> encrypted =
        domain::TgcallsSignalingEnvelope::Encrypt(
            m_sharedKey, m_isOutgoing, seq, messages);

    if (encrypted.empty()) {
        return MakeError(
            domain::VoipErrorKind::CryptoUnavailable,
            "tgcalls signaling envelope encrypt produced empty output");
    }

    {
        std::ostringstream s;
        s << "signaling out seq=" << seq
          << " messages=" << messages.size()
          << " bytes=" << encrypted.size();
        Trace(s.str());
    }

    m_signalingOut(m_callId, encrypted);
    return domain::VoipError::Ok();
}

// ===========================================================================
// Incoming signaling handlers
// ===========================================================================

void TgcallsConnection::OnPeerInitialSetup(const domain::InitialSetupMsg& msg) {
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_peerInitialReceived = true;
        m_peerUfrag = msg.Ufrag;
        m_peerPwd = msg.Pwd;
        m_peerFingerprintHash = msg.Fingerprint.Hash;
        m_peerFingerprint = msg.Fingerprint.Fingerprint;
        m_peerSetup = msg.Fingerprint.Setup;
    }

    {
        std::ostringstream s;
        s << "peer InitialSetup ufrag=" << msg.Ufrag
          << " pwd_len=" << msg.Pwd.size()
          << " setup=" << msg.Fingerprint.Setup
          << " fp=" << msg.Fingerprint.Fingerprint;
        Trace(s.str());
    }

    // If we are the answering peer (incoming call) we need to emit our
    // own InitialSetup now in response — Start() emits it eagerly for
    // the initiator side, but for the answer side we wait for the peer
    // first so we can adopt the correct DTLS role (active vs passive).
    if (!m_isOutgoing) {
        std::string adoptedRole;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            // RFC 8842: if the peer offers actpass we answer with active.
            if (msg.Fingerprint.Setup == "actpass" || msg.Fingerprint.Setup == "passive") {
                m_localSetupRole = "active";
            } else {
                m_localSetupRole = "passive";
            }
            adoptedRole = m_localSetupRole;
        }
        (void)adoptedRole;
    }

    // Kick the ICE phase as soon as we have the peer's ufrag/pwd.
    StartIcePhase();
}

void TgcallsConnection::OnPeerCandidates(const domain::CandidatesMsg& msg) {
    {
        std::ostringstream s;
        s << "peer Candidates count=" << msg.Candidates.size();
        Trace(s.str());
    }

    // Extract peer relay candidate addresses so we can CreatePermission
    // for them on every WebRtc TURN client we have open. The peer's relay
    // candidates resolve to public IPv4 endpoints behind Telegram's
    // reflector pool; once we authorize them via the TURN server we can
    // ship Send Indications targeted at those addresses.
    std::vector<infrastructure::turn::TurnAddress> newPeerRelays;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        for (size_t i = 0; i < msg.Candidates.size(); i++) {
            m_peerCandidates.push_back(msg.Candidates[i].SdpString);
            std::ostringstream s;
            s << "  peer candidate: " << msg.Candidates[i].SdpString;
            Trace(s.str());

            domain::ParsedIceCandidate parsed;
            if (!domain::IceCandidateParser::Parse(
                    msg.Candidates[i].SdpString, parsed)) {
                continue;
            }
            if (parsed.Type != domain::IceCandidateType_Relay) continue;
            if (parsed.Ip.empty() || parsed.Port <= 0) continue;
            // Only IPv4 today -- Telegram relays are always v4-reachable.
            infrastructure::turn::TurnAddress addr =
                infrastructure::turn::MakeAddress(parsed.Ip, parsed.Port);
            if (addr.Family != infrastructure::turn::kFamilyIPv4) continue;
            newPeerRelays.push_back(addr);
        }
    }

    if (!newPeerRelays.empty()) {
        std::vector<std::shared_ptr<infrastructure::turn::TurnClient> > clients;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            clients = m_turnClients;
        }
        for (size_t c = 0; c < clients.size(); c++) {
            for (size_t r = 0; r < newPeerRelays.size(); r++) {
                domain::VoipError perm = clients[c]->AddPeerPermission(newPeerRelays[r]);
                if (!perm.IsOk()) {
                    std::ostringstream s;
                    s << "AddPeerPermission failed for "
                      << infrastructure::turn::FormatAddress(newPeerRelays[r])
                      << " on " << clients[c]->ReflectorIp() << ":"
                      << clients[c]->ReflectorPort()
                      << " — " << perm.Message;
                    Trace(s.str());
                } else {
                    std::ostringstream s;
                    s << "CreatePermission for peer "
                      << infrastructure::turn::FormatAddress(newPeerRelays[r])
                      << " on " << clients[c]->ReflectorIp() << ":"
                      << clients[c]->ReflectorPort() << " OK";
                    Trace(s.str());
                }
            }
        }
    }

    // Now that we have at least one candidate from the peer (in addition
    // to the InitialSetup we received earlier), we can advance the ICE
    // phase. StartIcePhase() is itself idempotent — if InitialSetup
    // hasn't arrived yet it bails out and we'll be invoked again from
    // OnPeerInitialSetup() once it does.
    StartIcePhase();
}

void TgcallsConnection::OnPeerPing(const domain::PingMsg& msg) {
    domain::TgcallsMessage pong;
    pong.Type = domain::TgcallsMessageType_Pong;
    pong.TypeName = "Pong";
    pong.Pong.PingId = msg.PingId;

    std::vector<domain::TgcallsMessage> batch;
    batch.push_back(pong);
    EmitMessages(batch);
}

void TgcallsConnection::OnPeerMediaState(const domain::MediaStateMsg& msg) {
    std::ostringstream s;
    s << "peer MediaState muted=" << (msg.IsMuted ? "yes" : "no")
      << " video=" << msg.VideoState;
    Trace(s.str());
}

// ===========================================================================
// Reflector packet plumbing
// ===========================================================================

void TgcallsConnection::SendViaReflector(const std::vector<uint8_t>& payload) {
    // Send the payload to every open reflector session. Each session
    // wraps the bytes with its own peer_tag (already configured on
    // OpenSession()) and pushes via DatagramSocket->GetOutputStreamAsync.
    //
    // This routes through m_transport (DatagramSocketReflectorTransport),
    // which holds one open Session per reflector — the sessions opened in
    // Start() step 5. Sending to all of them is the right thing to do for
    // ICE: the connectivity-check loop runs against every reflector we
    // have a session on, and the IceAgent's GetBindingRequestsToSend()
    // already produced one request per remote candidate, so we replicate
    // each request across all reflectors and let the peer pick whichever
    // path completes first. The single-socket field m_socket is only
    // populated for the classic libtgvoip path and is not used here.
    infrastructure::DatagramSocketReflectorTransport* transport = nullptr;
    std::vector<ReflectorEndpoint> reflectorsSnapshot;
    std::vector<std::shared_ptr<infrastructure::turn::TurnClient> > turnSnapshot;
    std::vector<std::string> peerRelayCandidates;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        transport = m_transport.get();
        reflectorsSnapshot = m_reflectors;
        turnSnapshot = m_turnClients;
        peerRelayCandidates = m_peerCandidates;
    }
    if (transport == nullptr && turnSnapshot.empty()) {
        Trace("SendViaReflector dropped: no transport initialized");
        return;
    }
    if (reflectorsSnapshot.empty() && turnSnapshot.empty()) {
        Trace("SendViaReflector dropped: no reflectors enrolled");
        return;
    }

    int dispatched = 0;
    int failed = 0;

    // ---- TURN path: WebRtc reflectors -------------------------------------
    // For each TurnClient, ship the payload as one Send Indication per
    // peer relay candidate. The IceAgent's connectivity check will pick
    // whichever path round-trips successfully.
    if (!turnSnapshot.empty()) {
        std::vector<infrastructure::turn::TurnAddress> peerRelayAddrs;
        for (size_t i = 0; i < peerRelayCandidates.size(); ++i) {
            domain::ParsedIceCandidate parsed;
            if (!domain::IceCandidateParser::Parse(peerRelayCandidates[i], parsed)) continue;
            if (parsed.Type != domain::IceCandidateType_Relay) continue;
            if (parsed.Ip.empty() || parsed.Port <= 0) continue;
            infrastructure::turn::TurnAddress a =
                infrastructure::turn::MakeAddress(parsed.Ip, parsed.Port);
            if (a.Family != infrastructure::turn::kFamilyIPv4) continue;
            peerRelayAddrs.push_back(a);
        }

        for (size_t c = 0; c < turnSnapshot.size(); ++c) {
            std::shared_ptr<infrastructure::turn::TurnClient>& client = turnSnapshot[c];
            if (!client) continue;
            if (!client->IsAllocated()) continue;
            if (peerRelayAddrs.empty()) continue;
            for (size_t r = 0; r < peerRelayAddrs.size(); ++r) {
                domain::VoipError sent = client->Send(peerRelayAddrs[r], payload);
                if (sent.IsOk()) {
                    ++dispatched;
                    m_txPackets.fetch_add(1, std::memory_order_relaxed);
                    // The Send Indication envelope adds ~28B (header +
                    // attrs) over the inner payload size; this is a wire
                    // estimate for observability.
                    m_txBytes.fetch_add(
                        static_cast<uint64_t>(payload.size() + 28),
                        std::memory_order_relaxed);
                } else {
                    ++failed;
                    std::ostringstream s;
                    s << "TurnClient::Send failed for "
                      << infrastructure::turn::FormatAddress(peerRelayAddrs[r])
                      << " on " << client->ReflectorIp() << ":"
                      << client->ReflectorPort() << " — " << sent.Message;
                    Trace(s.str());
                }
            }
        }
    }

    // ---- Classic Reflector path: peer_tag wrap ---------------------------
    if (transport != nullptr) {
        for (size_t i = 0; i < reflectorsSnapshot.size(); ++i) {
            const ReflectorEndpoint& ep = reflectorsSnapshot[i];
            if (ep.IsWebRtc) continue; // handled via TurnClient above.
            if (ep.PeerTag.size() != kPeerTagSize) continue;
            if (ep.Ip.empty() || ep.Port <= 0) continue;

            domain::VoipError sent =
                transport->SendThroughSession(ep.Ip, ep.Port, payload);
            if (sent.IsOk()) {
                ++dispatched;
                m_txPackets.fetch_add(1, std::memory_order_relaxed);
                m_txBytes.fetch_add(
                    static_cast<uint64_t>(payload.size() + 16),
                    std::memory_order_relaxed);
            } else {
                ++failed;
                std::ostringstream s;
                s << "SendThroughSession failed for " << ep.Ip << ":" << ep.Port
                  << " — " << sent.Message;
                Trace(s.str());
            }
        }
    }

    if (dispatched == 0) {
        std::ostringstream s;
        s << "SendViaReflector dispatched=0/" << reflectorsSnapshot.size()
          << " (turnClients=" << turnSnapshot.size()
          << ") failed=" << failed;
        Trace(s.str());
    }
}

void TgcallsConnection::OnReflectorDatagram(const std::vector<uint8_t>& bytes) {
    // Surface real wire activity to GetMediaSnapshot. Count even
    // pre-strip bytes — what we care about is "did the wire deliver
    // something to us at all?". The strip happens below; if the inbound
    // is a runt that fails the peer_tag check we still want it visible
    // in rxPackets.
    m_rxPackets.fetch_add(1, std::memory_order_relaxed);
    m_rxBytes.fetch_add(static_cast<uint64_t>(bytes.size()),
                        std::memory_order_relaxed);

    std::vector<uint8_t> inner;
    if (!TryStripPeerTag(bytes, inner)) {
        Trace("OnReflectorDatagram dropped: shorter than peer_tag");
        return;
    }
    if (inner.empty()) return;

    // RFC 7983: a multiplexed UDP flow over a single 5-tuple carries STUN,
    // DTLS, and (S)RTP. Disambiguate by the first byte:
    //   0x00..0x03 -> STUN (binding request msg-type starts 0x00 0x01,
    //                       binding response 0x01 0x01).
    //   0x14..0x1F -> DTLS records (20=CCS, 21=Alert, 22=HS, 23=AppData).
    //   0x80..0xBF -> RTP / RTCP (SRTP encrypted).
    const uint8_t firstByte = inner[0];

    // Every datagram we currently receive arrives through the WebRTC
    // reflector at m_reflectors[0]; the IceAgent matches pairs by
    // (ip,port), so we hand it the reflector address as the source.
    // Multi-reflector ICE will tag bytes with the actual source endpoint
    // once IVoipReflectorDatagramSession surfaces it.
    std::string srcIp;
    int srcPort = 0;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (!m_reflectors.empty()) {
            srcIp = m_reflectors[0].Ip;
            srcPort = m_reflectors[0].Port;
        }
    }

    if (firstByte <= 0x03) {
        // STUN binding request or response.
        IceAgent* agent = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            agent = m_iceAgent.get();
        }
        if (agent == nullptr) {
            Trace("OnReflectorDatagram STUN dropped: IceAgent not yet constructed");
            return;
        }

        std::vector<uint8_t> response;
        IceAgent::ProcessResult result = agent->ProcessIncoming(
            srcIp, srcPort, inner, response);

        if (!response.empty()) {
            // Send STUN response back through the same reflector — the
            // peer_tag wrap is added by SendViaReflector.
            SendViaReflector(response);
            std::ostringstream s;
            s << "ICE STUN response sent back via reflector "
              << srcIp << ":" << srcPort
              << " (" << response.size() << "B)";
            Trace(s.str());
        }

        if (result == IceAgent::ProcessResult_ConnectivityEstablished) {
            std::ostringstream s;
            s << "ICE connectivity established with "
              << agent->GetSelectedRemoteIp() << ":"
              << agent->GetSelectedRemotePort();
            Trace(s.str());
            OnIceConnected();
        } else if (result == IceAgent::ProcessResult_BindingRequestProcessed) {
            Trace("ICE binding request processed (peer-initiated check)");
        } else if (result == IceAgent::ProcessResult_BindingResponseProcessed) {
            Trace("ICE binding response processed (one of our checks succeeded)");
        }
        return;
    }

    if (firstByte >= 0x14 && firstByte <= 0x1F) {
        // DTLS record. Pump it through the client session and ship any
        // outgoing reply datagrams (next handshake flight or alert)
        // back through the reflector.
        DtlsClientSession* dtls = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            dtls = m_dtls.get();
        }
        if (dtls == nullptr) {
            std::ostringstream s;
            s << "DTLS record dropped: session not yet constructed (" << inner.size() << "B)";
            Trace(s.str());
            return;
        }

        std::vector<std::vector<uint8_t> > outDatagrams;
        bool ok = dtls->ProcessDatagram(inner.data(), inner.size(), outDatagrams);
        {
            std::ostringstream s;
            s << "DTLS RX " << inner.size() << "B ok=" << (ok ? "yes" : "no")
              << " outFlights=" << outDatagrams.size()
              << " state=" << (int)dtls->GetState();
            Trace(s.str());
        }
        PumpDtls(outDatagrams);

        bool srtpAlreadyReady = false;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            srtpAlreadyReady = m_srtpReady;
        }
        if (dtls->GetState() == DtlsState_Established && !srtpAlreadyReady) {
            std::vector<uint8_t> srtpKeys = dtls->ExportKeyingMaterial(
                "EXTRACTOR-dtls_srtp", 60);
            OnDtlsEstablished(srtpKeys);
        } else if (dtls->GetState() == DtlsState_Failed) {
            std::ostringstream s;
            s << "DTLS handshake failed: " << dtls->FailureReason();
            Trace(s.str());
            TransitionTo(State::Failed);
        }
        return;
    }

    if (firstByte >= 0x80 && firstByte <= 0xBF) {
        // RTP / RTCP — SRTP encrypted.
        State currentState;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            currentState = m_state;
        }
        if (currentState == State::Connected) {
            OnSrtpDatagram(inner);
        }
        return;
    }

    {
        char buf[96];
        ::_snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "OnReflectorDatagram unknown first byte 0x%02X (%u bytes)",
            (unsigned)firstByte, (unsigned)inner.size());
        Trace(buf);
    }
}

// Async push variant. Invoked by
// DatagramSocketReflectorTransport::OpenSession's MessageReceived handler
// for every inbound datagram that matched our peer_tag. The transport has
// already stripped the 16-byte peer_tag prefix, so payload contains the
// pure inner packet (STUN / DTLS / SRTP).
//
// We re-wrap the payload with a synthetic 16-byte peer_tag prefix and
// hand it to the legacy single-argument overload — that's where the
// RFC 7983 first-byte demultiplex + IceAgent / DTLS / SRTP routing
// already lives. The endpoint info (srcIp, srcPort) overrides what the
// legacy overload would have synthesized from m_reflectors[0], which is
// useful once we listen on multiple reflector endpoints.
void TgcallsConnection::OnReflectorDatagram(
    const std::string& srcIp,
    int srcPort,
    const std::vector<uint8_t>& payload)
{
    {
        std::ostringstream s;
        s << "Reflector RX from " << srcIp << ":" << srcPort
          << " payload=" << payload.size() << "B";
        Trace(s.str());
    }
    if (payload.empty()) return;

    // Re-wrap with a 16-byte zero peer_tag so the legacy overload's
    // TryStripPeerTag() prefix-strip is a no-op for the packet content.
    // TODO: refactor the legacy overload to take payload + (srcIp,
    // srcPort) directly so we can drop this re-wrap.
    std::vector<uint8_t> reframed(16, 0);
    reframed.insert(reframed.end(), payload.begin(), payload.end());
    OnReflectorDatagram(reframed);
}

// ===========================================================================
// Phase advancement
// ===========================================================================

void TgcallsConnection::StartIcePhase() {
    // We need:
    //   - peer's InitialSetup (ufrag + pwd + fingerprint), AND
    //   - at least one peer candidate to direct STUN binding requests to.
    // If either is missing we'll be invoked again later when the relevant
    // signaling message arrives.
    bool peerReady = false;
    bool alreadyStarted = false;
    size_t peerCandidateCount = 0;
    std::string peerUfragSnapshot;
    std::string peerPwdSnapshot;
    std::string localUfragSnapshot;
    std::string localPwdSnapshot;
    std::vector<std::string> peerCandidatesSnapshot;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        peerReady = m_peerInitialReceived
                  && !m_peerUfrag.empty()
                  && !m_peerPwd.empty();
        peerCandidateCount = m_peerCandidates.size();
        alreadyStarted = m_iceStarted;
        peerUfragSnapshot = m_peerUfrag;
        peerPwdSnapshot = m_peerPwd;
        localUfragSnapshot = m_localUfrag;
        localPwdSnapshot = m_localPwd;
        peerCandidatesSnapshot = m_peerCandidates;
    }

    if (!peerReady) {
        Trace("StartIcePhase deferred: peer InitialSetup not yet received");
        return;
    }

    if (!alreadyStarted) {
        // First time through after we have peer InitialSetup — emit our
        // own Candidates message so the peer can start sending STUN
        // binding requests at us. All real packets still round-trip
        // through the reflector, but the peer's signaling state machine
        // wants Candidates before sending its own.
        domain::VoipError emitted = EmitCandidates();
        if (!emitted.IsOk()) {
            Trace(std::string("EmitCandidates failed: ") + emitted.Message);
        }
    }

    // Once we have BOTH the peer's InitialSetup and at least one peer
    // Candidate we can drive the actual STUN connectivity phase. Until
    // then we just sit here with our half of the exchange already on
    // the wire.
    if (peerCandidateCount == 0) {
        Trace("StartIcePhase: peer has not sent Candidates yet, holding");
        return;
    }

    // Latch m_iceStarted so a re-entry from OnPeerCandidates() (extra
    // batches arriving later) does not double-construct the agent.
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_iceStarted) return;
        m_iceStarted = true;
    }

    {
        std::ostringstream s;
        s << "StartIcePhase: peer ufrag=" << peerUfragSnapshot
          << " candidates=" << peerCandidateCount
          << " role=" << (m_isOutgoing ? "Controlling" : "Controlled");
        Trace(s.str());
    }

    // Construct the ICE agent. The initiator (outgoing call) is
    // ICE-Controlling per RFC 8445 — it picks the working pair and sends
    // USE-CANDIDATE on the selected one.
    IceAgentRole role = m_isOutgoing
        ? IceAgentRole_Controlling
        : IceAgentRole_Controlled;

    std::unique_ptr<IceAgent> agent(new IceAgent(
        role,
        localUfragSnapshot,
        localPwdSnapshot,
        peerUfragSnapshot,
        peerPwdSnapshot));

    // Feed the peer's candidates into the agent. We accept both relay
    // and host candidates: relay candidates target a Telegram reflector
    // (which we can already reach via m_socket), and host candidates
    // are kept on the chance that the peer happens to share a LAN with
    // us — connectivity check failure simply prunes them. srflx/prflx
    // require a public IP we typically don't have, so we drop them.
    int addedRelay = 0;
    int addedHost = 0;
    int skipped = 0;
    for (size_t i = 0; i < peerCandidatesSnapshot.size(); ++i) {
        domain::ParsedIceCandidate parsed;
        if (!domain::IceCandidateParser::Parse(peerCandidatesSnapshot[i], parsed)) {
            ++skipped;
            continue;
        }
        if (parsed.Type == domain::IceCandidateType_Relay) {
            agent->AddRemoteCandidate(parsed);
            ++addedRelay;
        } else if (parsed.Type == domain::IceCandidateType_Host) {
            agent->AddRemoteCandidate(parsed);
            ++addedHost;
        } else {
            ++skipped;
        }
    }
    {
        std::ostringstream s;
        s << "StartIcePhase: added " << addedRelay << " relay + "
          << addedHost << " host candidates (skipped " << skipped << ")";
        Trace(s.str());
    }

    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_iceAgent = std::move(agent);
        m_iceAttempts = 0;
    }

    // Send the first batch of binding requests immediately, then arm a
    // 500ms periodic timer to re-issue them until the agent reports a
    // working pair (or we exhaust our retry budget).
    SendIceBindingRequests();
    StartIceRetryTimer();
}

void TgcallsConnection::StartDtlsPhase() {
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_dtls != nullptr) {
            Trace("StartDtlsPhase: DTLS session already in flight");
            return;
        }
    }
    TransitionTo(State::DtlsHandshaking);

    // Steal the local cert (it's the leaf for our self-signed identity)
    // and the peer SHA-256 fingerprint we captured in OnPeerInitialSetup.
    std::unique_ptr<infrastructure::EcdsaP256KeyPair> cert;
    std::string peerFingerprint;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        cert = std::move(m_localCert);
        peerFingerprint = m_peerFingerprint;
    }
    if (cert == nullptr) {
        Trace("StartDtlsPhase: missing local cert (already moved); failing");
        TransitionTo(State::Failed);
        return;
    }
    if (peerFingerprint.empty()) {
        Trace("StartDtlsPhase: missing peer fingerprint; failing");
        TransitionTo(State::Failed);
        return;
    }

    std::unique_ptr<DtlsClientSession> dtls(
        new DtlsClientSession(std::move(cert), peerFingerprint));

    std::vector<std::vector<uint8_t> > initial = dtls->Initiate();

    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_dtls = std::move(dtls);
    }

    {
        std::ostringstream s;
        s << "DTLS ClientHello sent (" << initial.size() << " datagram(s))";
        Trace(s.str());
    }
    PumpDtls(initial);
}

void TgcallsConnection::OnDtlsEstablished(
    const std::vector<uint8_t>& srtpKeyingMaterial)
{
    if (srtpKeyingMaterial.size() != 60) {
        std::ostringstream s;
        s << "DTLS export keying material wrong length: "
          << srtpKeyingMaterial.size() << " (expected 60)";
        Trace(s.str());
        TransitionTo(State::Failed);
        return;
    }
    Trace("DTLS established. Exporting SRTP keying material.");
    StartAudioPhase(srtpKeyingMaterial);
}

void TgcallsConnection::StartAudioPhase(
    const std::vector<uint8_t>& srtpKeyingMaterial)
{
    // ---- 1. Derive SRTP session keys from the 60-byte EKM blob --------
    // Layout per RFC 5764 §4.2:
    //   client_write_SRTP_master_key   (16 B)  -> offsets [0..16)
    //   server_write_SRTP_master_key   (16 B)  -> offsets [16..32)
    //   client_write_SRTP_master_salt  (14 B)  -> offsets [32..46)
    //   server_write_SRTP_master_salt  (14 B)  -> offsets [46..60)
    using infrastructure::srtp::SrtpKeys;
    using infrastructure::srtp::SrtpSessionKeys;
    using infrastructure::srtp::SrtpEncryptParams;

    SrtpKeys outMaster;
    SrtpKeys inMaster;
    std::memcpy(outMaster.MasterKey,  srtpKeyingMaterial.data() + 0,  16);
    std::memcpy(inMaster.MasterKey,   srtpKeyingMaterial.data() + 16, 16);
    std::memcpy(outMaster.MasterSalt, srtpKeyingMaterial.data() + 32, 14);
    std::memcpy(inMaster.MasterSalt,  srtpKeyingMaterial.data() + 46, 14);

    std::unique_ptr<SrtpEncryptParams> outParams(new SrtpEncryptParams());
    std::unique_ptr<SrtpEncryptParams> inParams(new SrtpEncryptParams());

    SrtpSessionKeys::DeriveSessionEncrKey(outMaster, outParams->SessionEncrKey);
    SrtpSessionKeys::DeriveSessionAuthKey(outMaster, outParams->SessionAuthKey);
    SrtpSessionKeys::DeriveSessionSalt   (outMaster, outParams->SessionSalt);
    SrtpSessionKeys::DeriveSessionEncrKey(inMaster,  inParams->SessionEncrKey);
    SrtpSessionKeys::DeriveSessionAuthKey(inMaster,  inParams->SessionAuthKey);
    SrtpSessionKeys::DeriveSessionSalt   (inMaster,  inParams->SessionSalt);

    outParams->Ssrc = m_localSsrc;
    outParams->RolloverCounter = 0;
    outParams->LastSequenceNumber = 0;
    outParams->HasLastSequenceNumber = false;
    // Peer SSRC is filled in lazily on the first inbound RTP packet
    // (see OnSrtpDatagram).
    inParams->Ssrc = 0;
    inParams->RolloverCounter = 0;
    inParams->LastSequenceNumber = 0;
    inParams->HasLastSequenceNumber = false;

    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_srtpOutgoing != nullptr) {
            delete reinterpret_cast<SrtpEncryptParams*>(m_srtpOutgoing);
        }
        if (m_srtpIncoming != nullptr) {
            delete reinterpret_cast<SrtpEncryptParams*>(m_srtpIncoming);
        }
        m_srtpOutgoing = outParams.release();
        m_srtpIncoming = inParams.release();
        m_srtpReady = true;
    }

    Trace("SRTP session ready. Starting audio loop.");

    // ---- 2. Open the audio device + Opus codec ------------------------
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_audio.reset(new infrastructure::WinrtVoipAudioDevice());
        m_codec.reset(new infrastructure::OpusVoipCodec());
    }

    ports::outbound::VoipAudioIoResult opened = m_audio->Open();
    if (!opened.Success) {
        Trace(std::string("audio device open failed: ") + opened.Error);
        TransitionTo(State::Failed);
        return;
    }
    int codecInit = m_codec->Init(infrastructure::OpusVoipCodec::DefaultBitrateBps);
    if (codecInit != 0) {
        Trace("opus codec init failed");
        TransitionTo(State::Failed);
        return;
    }

    TransitionTo(State::Connected);

    // ---- 3. Spin up the capture pump thread ---------------------------
    ::InterlockedExchange(&m_audioLoopActive, 1);
    HANDLE thread = ::CreateThread(NULL, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(&TgcallsConnection::AudioCaptureThreadProc),
        this, 0, NULL);
    if (thread == NULL) {
        ::InterlockedExchange(&m_audioLoopActive, 0);
        Trace("CreateThread for audio capture pump failed");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_audioCaptureThread = thread;
    }

    Trace("Audio loop started (48kHz mono, 60ms frames)");
}

unsigned long __stdcall TgcallsConnection::AudioCaptureThreadProc(void* arg) {
    TgcallsConnection* self = reinterpret_cast<TgcallsConnection*>(arg);
    if (self != nullptr) {
        self->RunAudioCaptureLoop();
    }
    return 0;
}

void TgcallsConnection::RunAudioCaptureLoop() {
    using infrastructure::srtp::SrtpEncryptParams;
    using infrastructure::srtp::SrtpPacketCodec;

    const int kFrameSamples = infrastructure::OpusVoipCodec::SamplesPerFrame; // 2880
    const uint8_t kOpusPayloadType = 111;  // standard WebRTC Opus PT

    std::vector<int16_t> pcm;
    pcm.reserve(kFrameSamples);
    std::vector<uint8_t> opusFrame;
    opusFrame.resize(infrastructure::OpusVoipCodec::MaxPacketBytes);

    Trace("RunAudioCaptureLoop entered");
    while (::InterlockedCompareExchange(&m_audioLoopActive, 1, 1) == 1) {
        infrastructure::WinrtVoipAudioDevice* audio = nullptr;
        infrastructure::OpusVoipCodec* codec = nullptr;
        SrtpEncryptParams* outParams = nullptr;
        uint16_t seq = 0;
        uint32_t ts = 0;
        uint32_t ssrc = 0;
        bool srtpReady = false;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            audio = m_audio.get();
            codec = m_codec.get();
            outParams = reinterpret_cast<SrtpEncryptParams*>(m_srtpOutgoing);
            srtpReady = m_srtpReady;
            seq = m_outgoingSeq;
            ts = m_outgoingTimestamp;
            ssrc = m_localSsrc;
        }
        if (audio == nullptr || codec == nullptr || !srtpReady || outParams == nullptr) {
            ::Sleep(10);
            continue;
        }

        // ReadFrame blocks up to ~timeoutMs for one frame's worth of PCM.
        // A timeout / failure means the device hasn't produced data yet
        // (e.g. just after Open) — try again, don't fail the call.
        ports::outbound::VoipAudioIoResult readResult =
            audio->ReadFrame(&pcm, /*timeoutMs=*/100);
        if (!readResult.Success || pcm.empty()) {
            ::Sleep(5);
            continue;
        }

        int opusLen = codec->EncodeFrame(
            pcm.data(), static_cast<int>(pcm.size()),
            opusFrame.data(), opusFrame.size());
        if (opusLen <= 0) continue;

        // ---- Build a 12-byte RTP header (V=2, no padding/ext/CSRC) ----
        std::vector<uint8_t> rtpPacket;
        rtpPacket.reserve(12 + opusLen);
        rtpPacket.push_back(0x80);                       // V=2, P=0, X=0, CC=0
        rtpPacket.push_back(kOpusPayloadType & 0x7F);    // M=0, PT=111
        rtpPacket.push_back(static_cast<uint8_t>((seq >> 8) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>(seq & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>((ts >> 24) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>((ts >> 16) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>((ts >> 8) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>(ts & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>((ssrc >> 24) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>((ssrc >> 16) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>((ssrc >> 8) & 0xFF));
        rtpPacket.push_back(static_cast<uint8_t>(ssrc & 0xFF));
        rtpPacket.insert(rtpPacket.end(),
            opusFrame.begin(), opusFrame.begin() + opusLen);

        // SRTP encrypt under the lock so ROC bookkeeping is race-free.
        std::vector<uint8_t> srtpPacket;
        {
            std::lock_guard<std::mutex> lock(m_lock);
            srtpPacket = SrtpPacketCodec::Encrypt(*outParams, rtpPacket, seq);
        }
        if (!srtpPacket.empty()) {
            SendViaReflector(srtpPacket);
        }

        seq = static_cast<uint16_t>(seq + 1);
        ts += static_cast<uint32_t>(kFrameSamples);
        {
            std::lock_guard<std::mutex> lock(m_lock);
            m_outgoingSeq = seq;
            m_outgoingTimestamp = ts;
        }
    }
    Trace("RunAudioCaptureLoop exited");
}

// ===========================================================================
// ICE connectivity-check helpers.
// SendIceBindingRequests() pumps the agent's pending check list onto the
// wire; StartIceRetryTimer() arms a 500ms periodic ThreadPoolTimer that
// re-issues that pump until ICE converges or we exhaust 20 attempts
// (~10 seconds). OnIceConnected() is invoked once the IceAgent reports
// ProcessResult_ConnectivityEstablished from OnReflectorDatagram().
// ===========================================================================

void TgcallsConnection::SendIceBindingRequests() {
    IceAgent* agent = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        agent = m_iceAgent.get();
    }
    if (agent == nullptr) return;

    std::vector<std::pair<IceCheckTarget, std::vector<uint8_t> > > requests
        = agent->GetBindingRequestsToSend();

    if (requests.empty()) {
        Trace("SendIceBindingRequests: agent produced no requests this cycle");
        return;
    }

    int sent = 0;
    for (size_t i = 0; i < requests.size(); ++i) {
        const IceCheckTarget& target = requests[i].first;
        const std::vector<uint8_t>& bytes = requests[i].second;

        // Wrap with peer_tag and ship via the reflector. The reflector
        // matches on peer_tag rather than IP, so the candidate's target
        // address is informational here -- we still log it for diagnostics.
        SendViaReflector(bytes);
        ++sent;

        std::ostringstream s;
        s << "ICE binding request -> " << target.Ip << ":" << target.Port
          << " via reflector (" << bytes.size() << "B)";
        Trace(s.str());
    }

    {
        std::ostringstream s;
        s << "SendIceBindingRequests: dispatched " << sent
          << "/" << requests.size() << " checks";
        Trace(s.str());
    }
}

void TgcallsConnection::StartIceRetryTimer() {
    using namespace Windows::Foundation;
    using namespace Windows::System::Threading;

    StopIceRetryTimer();

    TgcallsConnection* self = this;
    TimeSpan period;
    period.Duration = 500LL * 10000LL;  // 500ms in 100ns ticks.

    ThreadPoolTimer^ timer = ThreadPoolTimer::CreatePeriodicTimer(
        ref new TimerElapsedHandler([self](ThreadPoolTimer^ source) {
            // Stop firing once we've moved past IceConnecting (DtlsHandshaking,
            // Connected, Failed, or Stopped) or once Stop() has been requested.
            TgcallsConnection::State currentState;
            int attempts = 0;
            bool stopRequested = false;
            {
                std::lock_guard<std::mutex> lock(self->m_lock);
                currentState = self->m_state;
                attempts = self->m_iceAttempts;
                stopRequested = (self->m_stopped != 0);
            }
            if (stopRequested ||
                currentState == TgcallsConnection::State::DtlsHandshaking ||
                currentState == TgcallsConnection::State::Connected ||
                currentState == TgcallsConnection::State::Failed ||
                currentState == TgcallsConnection::State::Stopped) {
                source->Cancel();
                return;
            }
            if (attempts >= 20) {
                Trace("ICE retry timer giving up after 20 attempts (~10s)");
                source->Cancel();
                self->TransitionTo(TgcallsConnection::State::Failed);
                return;
            }
            self->SendIceBindingRequests();
            {
                std::lock_guard<std::mutex> lock(self->m_lock);
                self->m_iceAttempts = self->m_iceAttempts + 1;
            }
        }),
        period);

    {
        std::lock_guard<std::mutex> lock(m_lock);
        m_iceRetryTimer = reinterpret_cast<void*>(timer);
    }
    Trace("ICE retry timer armed (500ms period, 20 attempt cap)");
}

void TgcallsConnection::StopIceRetryTimer() {
    using namespace Windows::System::Threading;

    void* raw = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        raw = m_iceRetryTimer;
        m_iceRetryTimer = nullptr;
    }
    if (raw != nullptr) {
        ThreadPoolTimer^ timer = reinterpret_cast<ThreadPoolTimer^>(raw);
        try {
            timer->Cancel();
        } catch (Platform::Exception^) {
            // Timer may already have been cancelled by its own handler.
        }
        Trace("ICE retry timer cancelled");
    }
}

void TgcallsConnection::OnIceConnected() {
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_state >= State::DtlsHandshaking) return;
    }
    StopIceRetryTimer();
    Trace("ICE connected -> starting DTLS handshake");
    StartDtlsPhase();
}

// ---------------------------------------------------------------------------
// PumpDtls --- forward each datagram emitted by DtlsClientSession
// (Initiate() / ProcessDatagram) out through the reflector channel. Each
// element is one wire-format DTLS record (or coalesced flight); the
// reflector layer adds the peer_tag prefix in SendViaReflector().
// ---------------------------------------------------------------------------
void TgcallsConnection::PumpDtls(const std::vector<std::vector<uint8_t> >& flights) {
    for (size_t i = 0; i < flights.size(); ++i) {
        const std::vector<uint8_t>& dgram = flights[i];
        if (dgram.empty()) continue;
        SendViaReflector(dgram);
    }
}

// ===========================================================================
// Audio hot path
// ===========================================================================

void TgcallsConnection::OnCapturedFrame(const int16_t* /*samples*/, size_t /*sampleCount*/) {
    // Legacy hook from the classic stack; the modern stack drives capture
    // off the dedicated audio pump thread (RunAudioCaptureLoop) instead,
    // so this entry point is currently unused.
}

void TgcallsConnection::OnSrtpDatagram(const std::vector<uint8_t>& bytes) {
    using infrastructure::srtp::SrtpEncryptParams;
    using infrastructure::srtp::SrtpPacketCodec;

    if (bytes.size() < 12 + SrtpPacketCodec::kAuthTagSize) return;

    // Snapshot incoming SRTP state. We need at least one inbound packet
    // to discover the peer's SSRC; once known we hold it stable so the
    // codec's IV construction matches across re-keys.
    SrtpEncryptParams* inParams = nullptr;
    bool srtpReady = false;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        inParams = reinterpret_cast<SrtpEncryptParams*>(m_srtpIncoming);
        srtpReady = m_srtpReady;
    }
    if (!srtpReady || inParams == nullptr) return;

    // RTP header SSRC is at byte offset 8..11 (big-endian).
    uint32_t pktSsrc =
          (static_cast<uint32_t>(bytes[8])  << 24)
        | (static_cast<uint32_t>(bytes[9])  << 16)
        | (static_cast<uint32_t>(bytes[10]) <<  8)
        |  static_cast<uint32_t>(bytes[11]);

    std::vector<uint8_t> rtp;
    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        if (inParams->Ssrc == 0) {
            inParams->Ssrc = pktSsrc;
            m_remoteSsrc = pktSsrc;
        }
        // If a different SSRC arrives mid-call we just drop it; tgcalls
        // 1-on-1 audio is single-stream.
        if (inParams->Ssrc != pktSsrc) {
            return;
        }
        ok = SrtpPacketCodec::Decrypt(*inParams, bytes, rtp);
    }
    if (!ok) {
        Trace("SRTP decrypt failed (auth tag mismatch or short)");
        return;
    }
    OnRtpPacket(rtp);
}

void TgcallsConnection::OnRtpPacket(const std::vector<uint8_t>& rtpBytes) {
    if (rtpBytes.size() < 12) return;

    // Parse RTP header — minimal (V=2 fixed-size + optional CSRC + ext).
    const uint8_t firstByte = rtpBytes[0];
    const int csrcCount = firstByte & 0x0F;
    const bool hasExt   = (firstByte & 0x10) != 0;

    int headerLen = 12 + csrcCount * 4;
    if (hasExt) {
        if (static_cast<int>(rtpBytes.size()) < headerLen + 4) return;
        const int extLen =
            (static_cast<int>(rtpBytes[headerLen + 2]) << 8) |
             static_cast<int>(rtpBytes[headerLen + 3]);
        headerLen += 4 + extLen * 4;
    }
    if (static_cast<int>(rtpBytes.size()) <= headerLen) return;

    const uint8_t* opusPayload = &rtpBytes[headerLen];
    const int opusPayloadLen = static_cast<int>(rtpBytes.size()) - headerLen;

    infrastructure::OpusVoipCodec* codec = nullptr;
    infrastructure::WinrtVoipAudioDevice* audio = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_lock);
        codec = m_codec.get();
        audio = m_audio.get();
    }
    if (codec == nullptr || audio == nullptr) return;

    // 80ms ceiling at 48kHz mono = 3840 samples; the codec is configured
    // for 60ms, so this gives one frame of headroom for late jitter.
    int16_t pcmOut[3840];
    int decoded = codec->DecodeFrame(
        opusPayload, static_cast<size_t>(opusPayloadLen),
        pcmOut,
        static_cast<int>(sizeof(pcmOut) / sizeof(pcmOut[0])));
    if (decoded <= 0) return;

    audio->WriteFrame(pcmOut, static_cast<size_t>(decoded));
}

// ===========================================================================
// Random helpers
// ===========================================================================

namespace {

void FillSecureRandom(uint8_t* out, size_t length) {
    if (length == 0) return;
    using namespace Windows::Security::Cryptography;
    using namespace Windows::Storage::Streams;
    try {
        IBuffer^ buf = CryptographicBuffer::GenerateRandom((unsigned int)length);
        Platform::Array<uint8>^ arr;
        CryptographicBuffer::CopyToByteArray(buf, &arr);
        if (arr != nullptr && arr->Length >= length) {
            std::memcpy(out, arr->Data, length);
            return;
        }
    } catch (Platform::Exception^) {
        // fall through to rand()
    }
    for (size_t i = 0; i < length; i++) {
        out[i] = static_cast<uint8_t>(::rand() & 0xff);
    }
}

} // namespace

std::string TgcallsConnection::GenerateRandomToken(size_t length) {
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const size_t kAlphabetSize = sizeof(kAlphabet) - 1;

    std::vector<uint8_t> entropy(length);
    if (length > 0) FillSecureRandom(&entropy[0], length);

    std::string out;
    out.resize(length);
    for (size_t i = 0; i < length; i++) {
        out[i] = kAlphabet[entropy[i] % kAlphabetSize];
    }
    return out;
}

uint32_t TgcallsConnection::GenerateRandomUint32() {
    uint8_t bytes[4] = {0, 0, 0, 0};
    FillSecureRandom(bytes, 4);
    return (static_cast<uint32_t>(bytes[0]) << 24)
         | (static_cast<uint32_t>(bytes[1]) << 16)
         | (static_cast<uint32_t>(bytes[2]) << 8)
         |  static_cast<uint32_t>(bytes[3]);
}

// Stats snapshot consumed by VoipEngine::GetMediaSnapshot. Lock-free
// reads using relaxed memory order — the values are observability-only
// (UI polling, ETW), not used to drive program state, so cache coherency
// on each individual atomic is sufficient.
TgcallsConnection::StatsSnapshot TgcallsConnection::GetStatsSnapshot() const {
    StatsSnapshot s;
    s.TxPackets = m_txPackets.load(std::memory_order_relaxed);
    s.RxPackets = m_rxPackets.load(std::memory_order_relaxed);
    s.TxBytes   = m_txBytes.load(std::memory_order_relaxed);
    s.RxBytes   = m_rxBytes.load(std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lock(m_lock);
        s.CurrentState = m_state;
    }
    return s;
}

}}} // namespace vianigram::voip::application
