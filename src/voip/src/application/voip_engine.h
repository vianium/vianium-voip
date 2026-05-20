// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../ports/inbound/i_voip_engine.h"
#include "../ports/outbound/i_voip_audio_runtime.h"
#include "../ports/outbound/i_voip_reflector_transport.h"
#include "../ports/outbound/i_tgcalls_media_graph.h"
#include "../domain/voip_media_session.h"

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <ppl.h>

namespace vianigram { namespace voip { namespace application {

struct VoipActiveMediaContext;
class TgcallsConnection;

class VoipEngine : public ports::inbound::IVoipEngine {
public:
    VoipEngine();
    explicit VoipEngine(ports::outbound::IVoipReflectorTransport* reflectorTransport);
    VoipEngine(
        ports::outbound::IVoipReflectorTransport* reflectorTransport,
        ports::outbound::IVoipAudioRuntimeFactory* audioFactory);
    VoipEngine(
        ports::outbound::IVoipReflectorTransport* reflectorTransport,
        ports::outbound::IVoipAudioRuntimeFactory* audioFactory,
        ports::outbound::ITgcallsMediaGraph* tgcallsGraph);
    virtual ~VoipEngine();

    virtual domain::VoipCapability Capability() const;

    virtual domain::VoipDhMaterial CreateOutgoingDh(
        int32_t randomId,
        int32_t g,
        const std::vector<uint8_t>& p);

    virtual domain::VoipError BindOutgoingCall(int32_t randomId, int64_t callId);

    virtual domain::VoipError RegisterIncomingGAHash(
        int64_t callId,
        const std::vector<uint8_t>& gAHash);

    virtual domain::VoipDhMaterial CreateIncomingDh(
        int64_t callId,
        int32_t g,
        const std::vector<uint8_t>& p);

    virtual domain::VoipDhMaterial AcceptPeerGB(
        int64_t callId,
        const std::vector<uint8_t>& gB);

    virtual domain::VoipError ConfirmPeerGAOrB(
        int64_t callId,
        const std::vector<uint8_t>& gAOrB,
        int64_t expectedFingerprint);

    virtual int64_t GetLocalFingerprint(int64_t callId);
    virtual std::string GetKeyHandle(int64_t callId);
    virtual void DropCall(int64_t callId);

    // Diagnostic-only helper: returns the 256-byte DH shared key for the given
    // callId so callers can locally decrypt updatePhoneCallSignalingData blobs
    // through TgcallsSignalingCodec. Returns an empty vector if the call has
    // not finished its DH yet, or if it has been dropped. Not part of the
    // production media path — used by the managed adapter to print decrypted
    // tgcalls 2.x signaling for debugging tgcalls support.
    std::vector<uint8_t> GetSharedKeyDiagnosticBytes(int64_t callId) const;

    virtual domain::VoipError StartMedia(
        int64_t callId,
        const std::string& keyHandle,
        const std::vector<domain::VoipEndpoint>& endpoints);

    virtual domain::VoipError StartMedia(
        const domain::VoipCallStartDescriptor& descriptor);

    virtual domain::VoipError ReceiveSignalingData(
        int64_t callId,
        const std::vector<uint8_t>& data);

    void SetSignalingDataProducedHandler(
        ports::outbound::TgcallsSignalingDataProducedHandler handler);

    virtual domain::VoipError StopMedia();
    virtual domain::VoipError SetMuted(bool muted);
    virtual domain::VoipError SetSpeaker(bool on);
    virtual domain::VoipMediaSnapshot GetMediaSnapshot() const;

private:
    struct DhSession {
        int32_t RandomId;
        int64_t CallId;
        int32_t G;
        bool Incoming;
        bool SharedReady;
        std::vector<uint8_t> P;
        std::vector<uint8_t> PrivateValue;
        std::vector<uint8_t> PublicValue;
        std::vector<uint8_t> PublicHash;
        std::vector<uint8_t> PeerGAHash;
        std::vector<uint8_t> SharedKey;
        int64_t KeyFingerprint;
        uint32_t NextLocalSequence;
        uint32_t LastRemoteSequence;
        uint32_t SignalingPacketsReceived;
        uint32_t SignalingBytesReceived;
        uint32_t SignalingPacketsDropped;
        std::vector<std::vector<uint8_t> > PendingSignalingPackets;

        DhSession()
            : RandomId(0), CallId(0), G(0), Incoming(false),
              SharedReady(false), KeyFingerprint(0),
              NextLocalSequence(1), LastRemoteSequence(0),
              SignalingPacketsReceived(0), SignalingBytesReceived(0),
              SignalingPacketsDropped(0) {}
    };

    static size_t PendingSignalingBytes(const DhSession& session);
    static void QueuePendingSignaling(
        DhSession* session,
        const std::vector<uint8_t>& data);

    mutable concurrency::critical_section m_lock;
    std::map<int32_t, DhSession> m_outgoingByRandom;
    std::map<int64_t, DhSession> m_calls;
    std::set<int64_t> m_droppedCallIds;
    domain::VoipMediaSession m_mediaSession;
    std::shared_ptr<VoipActiveMediaContext> m_activeMedia;
    ports::outbound::IVoipReflectorTransport* m_reflectorTransport;
    ports::outbound::IVoipAudioRuntimeFactory* m_audioFactory;
    ports::outbound::ITgcallsMediaGraph* m_tgcallsGraph;
    ports::outbound::TgcallsSignalingDataProducedHandler m_signalingDataProduced;
    int64_t m_tgcallsCallId;

    // In-process tgcalls 2.x orchestrator. Owned by VoipEngine because
    // it requires direct access to the DH shared key (kept in m_calls)
    // and the reflector transport (kept in m_reflectorTransport). Bound
    // for non-classic descriptors when StartMedia decides the call must
    // run the modern stack and the external ITgcallsMediaGraph is not
    // available (the placeholder Vianium.Tgcalls.dll cannot link back
    // to VianiumVoIP without forming a project cycle, so the in-process
    // path here is the production media path for layer >= 93 calls).
    std::shared_ptr<TgcallsConnection> m_tgcallsConnection;

    VoipEngine(const VoipEngine&);
    VoipEngine& operator=(const VoipEngine&);
};

}}} // namespace vianigram::voip::application
