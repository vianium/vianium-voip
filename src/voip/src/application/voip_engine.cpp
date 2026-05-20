// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_engine.h"

#include "../domain/voip_control_packet.h"
#include "../domain/voip_endpoint_selector.h"
#include "../domain/voip_jitter_buffer.h"
#include "../domain/voip_packet_crypto.h"
#include "../domain/voip_reflector_packet.h"
#include "../domain/voip_stream_data_packet.h"
#include "tgcalls_connection.h"
#include "ice_agent.h"

#include <vianium/crypto/bignum.h>
#include <vianium/crypto/random.h>
#include <vianium/crypto/sha1.h>
#include <vianium/crypto/sha256.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <sstream>
#include <atomic>
#include <thread>
#include <utility>
#include <ppltasks.h>
#include <windows.h>

namespace vianigram { namespace voip { namespace application {

struct VoipActiveMediaContext {
    std::atomic<bool> StopRequested;
    std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> Socket;
    std::unique_ptr<ports::outbound::IVoipAudioDevice> Audio;
    std::unique_ptr<ports::outbound::IVoipAudioCodec> Codec;
    domain::VoipJitterBuffer Jitter;
    std::vector<uint8_t> SharedKey;
    std::vector<uint8_t> PeerTag;
    bool LocalIsOutgoing;
    uint32_t NextLocalSequence;
    uint32_t LastRemoteSequence;
    uint32_t AudioTimestampOut;
    std::atomic<bool> InitAckReceived;
    std::atomic<bool> MediaReady;
    std::atomic<uint32_t> MediaPacketsSent;
    std::atomic<uint32_t> MediaPacketsReceived;
    std::atomic<uint32_t> MediaBytesSent;
    std::atomic<uint32_t> MediaBytesReceived;
    std::atomic<uint32_t> AudioUnderruns;
    std::atomic<int> OutboundLevelPermille;
    std::atomic<int> InboundLevelPermille;

    VoipActiveMediaContext()
        : StopRequested(false),
          Jitter(domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs),
          LocalIsOutgoing(false),
          NextLocalSequence(1),
          LastRemoteSequence(0),
          AudioTimestampOut(0),
          InitAckReceived(false),
          MediaReady(false),
          MediaPacketsSent(0),
          MediaPacketsReceived(0),
          MediaBytesSent(0),
          MediaBytesReceived(0),
          AudioUnderruns(0),
          OutboundLevelPermille(0),
          InboundLevelPermille(0) {}
};

namespace {
const char* const kUnavailableReason =
    "VianiumVoIP call key exchange, UDP reflector probing, encrypted VoIP control packets, and native Opus codec are available; "
    "audio capture/playback and acoustic echo cancellation are not enabled in this build";

const int kDhBytes = 256;
// Classic INIT/INIT_ACK handshake retry policy.
// 12 attempts with exponential backoff 250ms -> 1500ms gives ~12s of denser
// early retries (better for TCP-like rapid-establish networks, harmless for
// slow ones). Was 6 attempts at fixed 500ms / 3000ms total before.
const int kInitialRetryMs = 250;
const int kMaxRetryMs = 1500;
const int kMaxInitAttempts = 12;
const int kControlHandshakeTimeoutMs = 13000;
const size_t kMaxPendingSignalingPackets = 128;
const size_t kMaxPendingSignalingBytes = 512 * 1024;

struct ScopedLock {
    concurrency::critical_section::scoped_lock Lock;
    explicit ScopedLock(concurrency::critical_section* cs) : Lock(*cs) {}
};

domain::VoipError Invalid(const char* message) {
    return domain::VoipError::Of(domain::VoipErrorKind::InvalidArgument, 0, message);
}

domain::VoipError CryptoError(const char* message) {
    return domain::VoipError::Of(domain::VoipErrorKind::CryptoUnavailable, 0, message);
}

std::string HandleForCall(int64_t callId) {
    std::ostringstream s;
    s << "voip-call:" << (long long)callId;
    return s.str();
}

uint64_t QueryIdForCall(int64_t callId) {
    uint64_t x = static_cast<uint64_t>(callId);
    return (x << 1) ^ 0x5A17C011BADC0DEULL;
}

domain::VoipControlCodecResult BuildControlPacket(
    domain::VoipControlPacketType type,
    uint32_t localSeq,
    uint32_t ackSeq,
    const std::vector<uint8_t>& payload)
{
    domain::VoipControlPacket packet;
    packet.Type = type;
    packet.AckSequence = ackSeq;
    packet.Sequence = localSeq;
    packet.AckMask = 0;
    packet.ExtraFlags = 0;
    packet.Payload = payload;
    return domain::VoipControlPacketCodec::EncodeShort(packet);
}

domain::VoipError TransportError(const std::string& message) {
    return domain::VoipError::Of(
        domain::VoipErrorKind::TransportFailed,
        0,
        message.c_str());
}

domain::VoipError PacketCryptoError(const std::string& message) {
    return domain::VoipError::Of(
        domain::VoipErrorKind::CryptoUnavailable,
        0,
        message.c_str());
}

uint32_t TakeNextSequence(uint32_t* nextSequence) {
    if (nextSequence == nullptr) return 1;
    uint32_t seq = *nextSequence;
    if (seq == 0) seq = 1;
    *nextSequence = seq + 1;
    if (*nextSequence == 0) *nextSequence = 1;
    return seq;
}

int RemainingMs(std::chrono::steady_clock::time_point deadline) {
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    if (now >= deadline) return 0;
    int ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    return ms < 1 ? 1 : ms;
}

int64_t NowMs() {
    return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

int PcmLevelPermille(const std::vector<int16_t>& pcm) {
    if (pcm.empty()) return 0;
    uint64_t total = 0;
    for (size_t i = 0; i < pcm.size(); i++) {
        int sample = pcm[i];
        total += (uint64_t)(sample < 0 ? -sample : sample);
    }
    uint64_t avg = total / (uint64_t)pcm.size();
    uint64_t permille = (avg * 1000ULL) / 32768ULL;
    return permille > 1000ULL ? 1000 : (int)permille;
}

bool EncodeAndSendAudioFrame(
    std::shared_ptr<VoipActiveMediaContext> ctx,
    const std::vector<int16_t>& pcm,
    std::vector<uint8_t>* opus)
{
    if (!ctx || !ctx->Codec || !ctx->Socket || pcm.empty() || opus == nullptr || opus->empty()) {
        return false;
    }

    int encodedBytes = ctx->Codec->EncodeFrame(
        &pcm[0],
        static_cast<int>(pcm.size()),
        &(*opus)[0],
        opus->size());
    if (encodedBytes <= 0) return false;

    domain::VoipStreamDataCodecResult payload =
        domain::VoipStreamDataPacketCodec::EncodeAudio(
            domain::VoipStreamDataPacketCodec::DefaultAudioStreamId,
            ctx->AudioTimestampOut,
            &(*opus)[0],
            static_cast<size_t>(encodedBytes));
    if (!payload.Success) return false;

    domain::VoipControlCodecResult packet = BuildControlPacket(
        domain::VoipControlPacketType::StreamData,
        TakeNextSequence(&ctx->NextLocalSequence),
        ctx->LastRemoteSequence,
        payload.Bytes);
    if (!packet.Success) return false;

    domain::VoipEncryptedPacketResult encrypted =
        domain::VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
            ctx->SharedKey,
            ctx->LocalIsOutgoing,
            ctx->PeerTag,
            packet.Bytes);
    if (!encrypted.Success) return false;

    ports::outbound::VoipReflectorDatagramResult sent = ctx->Socket->Send(encrypted.Bytes);
    if (!sent.Success) return false;

    ctx->MediaPacketsSent.fetch_add(1);
    ctx->MediaBytesSent.fetch_add((uint32_t)encrypted.Bytes.size());
    ctx->OutboundLevelPermille.store(PcmLevelPermille(pcm));
    ctx->AudioTimestampOut += domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs;
    return true;
}

bool IsReceiveTimeout(const ports::outbound::VoipReflectorDatagramResult& result) {
    return !result.Success && result.Error.find("timed out") != std::string::npos;
}

bool EndpointHasIpv4(const domain::VoipEndpoint& endpoint) {
    return !endpoint.Ip.empty();
}

std::string EndpointAddress(const domain::VoipEndpoint& endpoint) {
    return endpoint.Ip.empty() ? endpoint.Ipv6 : endpoint.Ip;
}

std::string EndpointLabel(const domain::VoipEndpoint& endpoint) {
    std::ostringstream s;
    s << "0x" << std::hex << (unsigned long long)endpoint.Id
      << "@" << EndpointAddress(endpoint)
      << ":" << std::dec << endpoint.Port;
    return s.str();
}

// Returns true for WebRTC reflector endpoints that we want to ALSO probe with a
// classic INIT packet. Some peers (and certain reflector layer-92 compatibility
// shims) accept classic INIT on the WebRTC reflector port (1400). It's a
// long-shot but cheap: each probe adds ~200 bytes and the same retry budget,
// and crucially: if it fails it adds another data point to the diagnostic
// summary so the next call gives concrete evidence.
bool IsClassicProbableEndpoint(const domain::VoipEndpoint& endpoint) {
    return endpoint.Port > 0
        && endpoint.Port <= 65535
        && (!endpoint.Ip.empty() || !endpoint.Ipv6.empty())
        && !endpoint.PeerTag.empty();
}

const char* EndpointKindLabel(const domain::VoipEndpoint& endpoint) {
    return endpoint.IsWebRtc ? "WebRtc" : "Reflector";
}

std::vector<domain::VoipEndpoint> OrderedReflectorEndpoints(
    const std::vector<domain::VoipEndpoint>& endpoints)
{
    std::vector<domain::VoipEndpoint> ordered;
    ordered.reserve(endpoints.size());

    // Pass 1: classic reflector endpoints with IPv4 (preferred).
    for (size_t i = 0; i < endpoints.size(); i++) {
        const domain::VoipEndpoint& endpoint = endpoints[i];
        if (domain::VoipEndpointSelector::IsUsableReflectorEndpoint(endpoint)
            && EndpointHasIpv4(endpoint)) {
            ordered.push_back(endpoint);
        }
    }

    // Pass 2: classic reflector endpoints, IPv6-only.
    for (size_t i = 0; i < endpoints.size(); i++) {
        const domain::VoipEndpoint& endpoint = endpoints[i];
        if (domain::VoipEndpointSelector::IsUsableReflectorEndpoint(endpoint)
            && !EndpointHasIpv4(endpoint)) {
            ordered.push_back(endpoint);
        }
    }

    // Pass 3: WebRTC reflector endpoints — long-shot probe with classic INIT.
    // PeerTag is required (we use the same MTProto2 short crypto). We probe
    // these LAST so genuine classic reflectors always get the first-class
    // attempt, and only fall through to WebRtc if no classic responded.
    for (size_t i = 0; i < endpoints.size(); i++) {
        const domain::VoipEndpoint& endpoint = endpoints[i];
        if (endpoint.IsWebRtc
            && IsClassicProbableEndpoint(endpoint)
            && !endpoint.PeerTag.empty()) {
            ordered.push_back(endpoint);
        }
    }

    return ordered;
}

bool HasWebRtcEndpoint(const std::vector<domain::VoipEndpoint>& endpoints) {
    for (size_t i = 0; i < endpoints.size(); i++) {
        if (endpoints[i].IsWebRtc) return true;
    }
    return false;
}

std::string JoinLibraryVersions(const std::vector<std::string>& versions) {
    if (versions.empty()) return "none";
    std::ostringstream s;
    for (size_t i = 0; i < versions.size(); i++) {
        if (i > 0) s << ",";
        s << versions[i];
    }
    return s.str();
}

std::string SelectedLibraryVersion(
    const domain::VoipCallStartDescriptor& descriptor)
{
    if (descriptor.LibraryVersions.empty()) return "classic-default";
    return descriptor.LibraryVersions[0];
}

bool IsClassicReflectorDescriptor(
    const domain::VoipCallStartDescriptor& descriptor)
{
    // Library-version rule (highest-priority).
    // The negotiated `library_versions` field in `phoneCallProtocol` is the
    // CANONICAL signal of which wire protocol the peer will speak.
    //
    // Telegram's server includes WebRtc endpoints in *every* descriptor
    // regardless of which protocol was negotiated — they're a fallback for
    // clients that asked for tgcalls 2.x. "WebRtc endpoints exist" must NOT
    // be treated as the tgcalls 2.x signal: a descriptor can contain WebRtc
    // endpoints alongside classic Reflector endpoints even when the peer
    // accepted only classic libtgvoip (e.g. libs=[5.0.0]). Routing such a
    // call to TgcallsConnection makes the peer's binary classic-libtgvoip
    // signaling unparseable as tgcalls JSON, ICE never starts, and
    // txPackets stay at 0.
    //
    // Correct rule: classic libtgvoip wire format <-> libs containing only
    // ["2.4.4", "2.7.7", "5.0.0", "7.0.0"] strings. Anything with "8.0.0"
    // or higher is tgcalls 2.x. This routes us through the classic
    // libtgvoip path (init/init_ack via reflector with peer_tag wrap),
    // which is the implementation that works on WP8.1.
    bool sawAnyVersion = false;
    bool sawNonClassic = false;
    for (size_t i = 0; i < descriptor.LibraryVersions.size(); ++i) {
        const std::string& v = descriptor.LibraryVersions[i];
        if (v.empty()) continue;
        sawAnyVersion = true;
        // Classic libtgvoip family: 2.x, 5.x, 6.x, 7.x. Modern tgcalls is
        // 8.0.0 and above. We treat anything starting with "8.", "9.",
        // "10.", "11.", "12.", "13." as modern.
        const char first = v[0];
        if (first == '8' || first == '9') {
            sawNonClassic = true;
        } else if (first == '1' && v.size() >= 2
                   && (v[1] == '0' || v[1] == '1' || v[1] == '2' || v[1] == '3')) {
            // "10.x" / "11.x" / "12.x" / "13.x" — modern.
            sawNonClassic = true;
        }
    }
    if (sawAnyVersion) {
        return !sawNonClassic; // classic if NO modern version was negotiated
    }

    // ----- Fallback: protocol-layer rule (legacy) ---------------------------
    // Empty libs vector — fall back to layer (some old peers omit libs).
    const int32_t kClassicMaxLayer = 92;
    if (descriptor.MaxLayer != 0 && descriptor.MaxLayer <= kClassicMaxLayer) return true;
    if (descriptor.MinLayer != 0 && descriptor.MinLayer <= kClassicMaxLayer
        && descriptor.MaxLayer == 0) return true;
    return true;
}

domain::VoipError WithEndpoint(
    const domain::VoipError& error,
    const domain::VoipEndpoint& endpoint,
    const char* prefix)
{
    if (error.IsOk()) return error;
    std::ostringstream s;
    s << (prefix == nullptr ? "VoIP endpoint failed" : prefix)
      << " endpoint=" << EndpointLabel(endpoint)
      << ": " << error.Message;
    return domain::VoipError::Of(error.Kind, error.Code, s.str().c_str());
}

struct ControlHandshakeOutcome {
    domain::VoipError Error;
    uint32_t PacketsSent;
    uint32_t PacketsReceived;
    uint32_t BytesSent;
    uint32_t BytesReceived;
    int RttMs;
    uint32_t PeerVersion;
    uint16_t AudioFrameDurationMs;
    uint32_t SelfInfoResponses;
    uint32_t DecryptFailures;
    uint32_t DecodeFailures;
    uint32_t InitAttempts;
    bool InitAckReceived;

    ControlHandshakeOutcome()
        : Error(domain::VoipError::Ok()),
          PacketsSent(0),
          PacketsReceived(0),
          BytesSent(0),
          BytesReceived(0),
          RttMs(0),
          PeerVersion(0),
          AudioFrameDurationMs(0),
          SelfInfoResponses(0),
          DecryptFailures(0),
          DecodeFailures(0),
          InitAttempts(0),
          InitAckReceived(false) {}
};

// Per-endpoint handshake summary trace. Emitted for both success and failure
// so the next run gives concrete data for each endpoint. We always log this
// (even in non-VERBOSE builds) because diagnosing classic-VoIP regressions
// without it requires a re-build.
void EmitHandshakeStats(
    const domain::VoipEndpoint& endpoint,
    const ControlHandshakeOutcome& outcome)
{
    std::ostringstream s;
    s << "[VoipEngine.HandshakeStats]"
      << " endpoint=0x" << std::hex << (unsigned long long)endpoint.Id << std::dec
      << " kind=" << EndpointKindLabel(endpoint)
      << " ip=" << EndpointAddress(endpoint) << ":" << endpoint.Port
      << " txPackets=" << outcome.PacketsSent
      << " rxPackets=" << outcome.PacketsReceived
      << " selfInfo=" << outcome.SelfInfoResponses
      << " rxBytes=" << outcome.BytesReceived
      << " txBytes=" << outcome.BytesSent
      << " decryptFailures=" << outcome.DecryptFailures
      << " decodeFailures=" << outcome.DecodeFailures
      << " initAttempts=" << outcome.InitAttempts
      << " initAckReceived=" << (outcome.InitAckReceived ? "true" : "false")
      << "\n";
    ::OutputDebugStringA(s.str().c_str());
}

void MediaSendLoop(std::shared_ptr<VoipActiveMediaContext> ctx) {
    if (!ctx || !ctx->Audio || !ctx->Codec || !ctx->Socket) return;
    std::vector<int16_t> pcm;
    std::vector<uint8_t> opus(domain::VoipStreamDataPacketCodec::MaxOpusPayloadBytes);
    std::vector<int16_t> silence(
        (48000 / 1000) * domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs,
        0);

    while (!ctx->StopRequested.load()) {
        if (!ctx->InitAckReceived.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(
                domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs));
            continue;
        }

        ports::outbound::VoipAudioIoResult audio =
            ctx->Audio->ReadFrame(&pcm, domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs);
        if (!audio.Success) {
            ctx->AudioUnderruns.fetch_add(1);
            pcm = silence;
        } else if (pcm.empty()) {
            ctx->AudioUnderruns.fetch_add(1);
            pcm = silence;
        }

        EncodeAndSendAudioFrame(ctx, pcm, &opus);
    }
}

void DrainJitterToAudio(std::shared_ptr<VoipActiveMediaContext> ctx) {
    if (!ctx || !ctx->Audio || !ctx->Codec) return;

    for (;;) {
        domain::VoipJitterFrame frame = ctx->Jitter.NextPlayoutFrame(NowMs());
        if (!frame.Ready) return;

        std::vector<int16_t> pcm(
            (48000 / 1000) * domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs,
            0);

        int decoded = 0;
        if (frame.HasPacket && !frame.Payload.empty()) {
            decoded = ctx->Codec->DecodeFrame(
                &frame.Payload[0],
                frame.Payload.size(),
                &pcm[0],
                static_cast<int>(pcm.size()));
        } else {
            decoded = ctx->Codec->DecodePlc(&pcm[0], static_cast<int>(pcm.size()));
        }
        if (decoded > 0) {
            ctx->InboundLevelPermille.store(PcmLevelPermille(pcm));
            ctx->Audio->WriteFrame(&pcm[0], static_cast<size_t>(decoded));
        }
    }
}

void SendPong(
    std::shared_ptr<VoipActiveMediaContext> ctx,
    const domain::VoipControlPacket& ping)
{
    domain::VoipControlCodecResult pong = BuildControlPacket(
        domain::VoipControlPacketType::Pong,
        TakeNextSequence(&ctx->NextLocalSequence),
        ctx->LastRemoteSequence == 0 ? ping.Sequence : ctx->LastRemoteSequence,
        ping.Payload);
    if (!pong.Success) return;
    domain::VoipEncryptedPacketResult encrypted =
        domain::VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
            ctx->SharedKey,
            ctx->LocalIsOutgoing,
            ctx->PeerTag,
            pong.Bytes);
    if (!encrypted.Success) return;
    ctx->Socket->Send(encrypted.Bytes);
}

bool SendInit(std::shared_ptr<VoipActiveMediaContext> ctx) {
    if (!ctx || !ctx->Socket) return false;

    domain::VoipControlCodecResult initPayload =
        domain::VoipControlPacketCodec::BuildInitPayload(false);
    if (!initPayload.Success) return false;

    domain::VoipControlCodecResult initPacket = BuildControlPacket(
        domain::VoipControlPacketType::Init,
        TakeNextSequence(&ctx->NextLocalSequence),
        ctx->LastRemoteSequence,
        initPayload.Bytes);
    if (!initPacket.Success) return false;

    domain::VoipEncryptedPacketResult encrypted =
        domain::VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
            ctx->SharedKey,
            ctx->LocalIsOutgoing,
            ctx->PeerTag,
            initPacket.Bytes);
    if (!encrypted.Success) return false;

    return ctx->Socket->Send(encrypted.Bytes).Success;
}

void SendInitAck(
    std::shared_ptr<VoipActiveMediaContext> ctx,
    const domain::VoipControlPacket& init)
{
    if (!ctx || !ctx->Socket) return;

    domain::VoipControlCodecResult ackPayload =
        domain::VoipControlPacketCodec::BuildInitAckPayload();
    if (!ackPayload.Success) return;

    domain::VoipControlCodecResult ackPacket = BuildControlPacket(
        domain::VoipControlPacketType::InitAck,
        TakeNextSequence(&ctx->NextLocalSequence),
        ctx->LastRemoteSequence == 0 ? init.Sequence : ctx->LastRemoteSequence,
        ackPayload.Bytes);
    if (!ackPacket.Success) return;

    domain::VoipEncryptedPacketResult encryptedAck =
        domain::VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
            ctx->SharedKey,
            ctx->LocalIsOutgoing,
            ctx->PeerTag,
            ackPacket.Bytes);
    if (!encryptedAck.Success) return;

    ctx->Socket->Send(encryptedAck.Bytes);
}

void InitLoop(std::shared_ptr<VoipActiveMediaContext> ctx) {
    if (!ctx || !ctx->Socket) return;

    int attempts = 0;
    while (!ctx->StopRequested.load() && !ctx->InitAckReceived.load()) {
        SendInit(ctx);
        attempts++;
        int delayMs = attempts < 3 ? 500 : 1000;
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }
}

void MediaReceiveLoop(std::shared_ptr<VoipActiveMediaContext> ctx) {
    if (!ctx || !ctx->Audio || !ctx->Codec || !ctx->Socket) return;

    while (!ctx->StopRequested.load()) {
        ports::outbound::VoipReflectorDatagramResult received =
            ctx->Socket->Receive(
                ctx->PeerTag,
                domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs);

        if (received.Success) {
            domain::VoipEncryptedPacketResult decrypted =
                domain::VoipPacketCrypto::DecryptRelayPacketMtProto2Short(
                    ctx->SharedKey,
                    ctx->LocalIsOutgoing,
                    ctx->PeerTag,
                    received.Bytes.empty() ? nullptr : &received.Bytes[0],
                    received.Bytes.size());
            if (decrypted.Success) {
                domain::VoipControlCodecResult decoded =
                    domain::VoipControlPacketCodec::DecodeShort(
                        decrypted.Plain.empty() ? nullptr : &decrypted.Plain[0],
                        decrypted.Plain.size());
                if (decoded.Success) {
                    if (decoded.Packet.Sequence != 0
                        && (ctx->LastRemoteSequence == 0 || decoded.Packet.Sequence > ctx->LastRemoteSequence)) {
                        ctx->LastRemoteSequence = decoded.Packet.Sequence;
                    }

                    if (decoded.Packet.Type == domain::VoipControlPacketType::InitAck) {
                        domain::VoipControlCodecResult parsedAck =
                            domain::VoipControlPacketCodec::ParseInitAckPayload(
                                decoded.Packet.Payload.empty() ? nullptr : &decoded.Packet.Payload[0],
                                decoded.Packet.Payload.size());
                        if (parsedAck.Success && parsedAck.InitAck.HasAudioOpusStream) {
                            ctx->InitAckReceived.store(true);
                        }
                    } else if (decoded.Packet.Type == domain::VoipControlPacketType::Init) {
                        SendInitAck(ctx, decoded.Packet);
                    } else if (decoded.Packet.Type == domain::VoipControlPacketType::StreamData) {
                        domain::VoipStreamDataCodecResult stream =
                            domain::VoipStreamDataPacketCodec::DecodeOne(
                                decoded.Packet.Payload.empty() ? nullptr : &decoded.Packet.Payload[0],
                                decoded.Packet.Payload.size());
                        if (stream.Success) {
                            ctx->MediaReady.store(true);
                            ctx->MediaPacketsReceived.fetch_add(1);
                            ctx->MediaBytesReceived.fetch_add((uint32_t)received.Bytes.size());
                            ctx->Jitter.Insert(
                                static_cast<uint16_t>(decoded.Packet.Sequence & 0xFFFFu),
                                stream.Packet.Timestamp,
                                stream.Packet.OpusPayload,
                                NowMs());
                        }
                    } else if (decoded.Packet.Type == domain::VoipControlPacketType::Ping) {
                        SendPong(ctx, decoded.Packet);
                    }
                }
            }
        } else if (!IsReceiveTimeout(received)) {
            break;
        }

        DrainJitterToAudio(ctx);
    }
}

bool EncryptAndSendControlPacket(
    ports::outbound::IVoipReflectorDatagramSession* socket,
    const domain::VoipEndpoint& endpoint,
    const std::vector<uint8_t>& sharedKey,
    bool localIsOutgoing,
    const std::vector<uint8_t>& plain,
    ControlHandshakeOutcome* outcome,
    std::string* error)
{
    if (socket == nullptr) {
        if (error != nullptr) *error = "VoIP reflector socket is unavailable";
        return false;
    }

    domain::VoipEncryptedPacketResult encrypted =
        domain::VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
            sharedKey,
            localIsOutgoing,
            endpoint.PeerTag,
            plain);
    if (!encrypted.Success) {
        if (error != nullptr) *error = encrypted.Error;
        return false;
    }

    ports::outbound::VoipReflectorDatagramResult sent = socket->Send(encrypted.Bytes);
    if (!sent.Success) {
        if (error != nullptr) *error = sent.Error;
        return false;
    }
    if (outcome != nullptr) {
        outcome->PacketsSent += 1;
        outcome->BytesSent += (uint32_t)encrypted.Bytes.size();
    }
    return true;
}

bool SendInitPacket(
    ports::outbound::IVoipReflectorDatagramSession* socket,
    const domain::VoipEndpoint& endpoint,
    const std::vector<uint8_t>& sharedKey,
    bool localIsOutgoing,
    uint32_t* nextLocalSequence,
    uint32_t lastRemoteSequence,
    ControlHandshakeOutcome* outcome,
    std::string* error)
{
    domain::VoipControlCodecResult initPayload =
        domain::VoipControlPacketCodec::BuildInitPayload(false);
    if (!initPayload.Success) {
        if (error != nullptr) *error = initPayload.Error;
        return false;
    }

    domain::VoipControlCodecResult initPacket = BuildControlPacket(
        domain::VoipControlPacketType::Init,
        TakeNextSequence(nextLocalSequence),
        lastRemoteSequence,
        initPayload.Bytes);
    if (!initPacket.Success) {
        if (error != nullptr) *error = initPacket.Error;
        return false;
    }

    return EncryptAndSendControlPacket(
        socket,
        endpoint,
        sharedKey,
        localIsOutgoing,
        initPacket.Bytes,
        outcome,
        error);
}

ControlHandshakeOutcome RunControlHandshake(
    ports::outbound::IVoipReflectorDatagramSession* socket,
    const domain::VoipEndpoint& endpoint,
    uint64_t queryId,
    const std::vector<uint8_t>& sharedKey,
    bool localIsOutgoing,
    uint32_t* nextLocalSequence,
    uint32_t* lastRemoteSequence)
{
    ControlHandshakeOutcome outcome;
    if (socket == nullptr) {
        outcome.Error = TransportError("VoIP reflector datagram session is unavailable");
        return outcome;
    }

    domain::VoipReflectorPacketResult selfInfo =
        domain::VoipReflectorPacketCodec::BuildSelfInfoRequest(endpoint.PeerTag, queryId);
    if (!selfInfo.Success) {
        outcome.Error = TransportError(selfInfo.Error);
        return outcome;
    }

    for (int i = 0; i < 2; i++) {
        ports::outbound::VoipReflectorDatagramResult warmupSent = socket->Send(selfInfo.Bytes);
        if (!warmupSent.Success) {
            outcome.Error = TransportError(warmupSent.Error);
            return outcome;
        }
        outcome.PacketsSent += 1;
        outcome.BytesSent += (uint32_t)selfInfo.Bytes.size();
    }

    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kControlHandshakeTimeoutMs);
    std::chrono::steady_clock::time_point nextInitAt = std::chrono::steady_clock::now();
    int initAttempts = 0;
    int currentRetryMs = kInitialRetryMs;
    int selfInfoResponses = 0;
    int decryptFailures = 0;
    int decodeFailures = 0;
    std::string lastPacketError;

    while (RemainingMs(deadline) > 0 && initAttempts < kMaxInitAttempts) {
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        if (initAttempts == 0 || now >= nextInitAt) {
            std::string sendError;
            uint32_t ackSeq = lastRemoteSequence == nullptr ? 0 : *lastRemoteSequence;
            if (!SendInitPacket(
                    socket,
                    endpoint,
                    sharedKey,
                    localIsOutgoing,
                    nextLocalSequence,
                    ackSeq,
                    &outcome,
                    &sendError)) {
                outcome.Error = TransportError(sendError);
                return outcome;
            }
            initAttempts++;
            nextInitAt = now + std::chrono::milliseconds(currentRetryMs);
            // Exponential backoff capped at kMaxRetryMs (250 -> 500 -> 1000 -> 1500 -> 1500 ...)
            int doubled = currentRetryMs * 2;
            currentRetryMs = doubled > kMaxRetryMs ? kMaxRetryMs : doubled;
        }

        int remaining = RemainingMs(deadline);
        int waitMs = remaining < 250 ? remaining : 250;
        ports::outbound::VoipReflectorDatagramResult received =
            socket->Receive(endpoint.PeerTag, waitMs);
        if (!received.Success) {
            if (IsReceiveTimeout(received)) {
                continue;
            }
            outcome.Error = TransportError(received.Error);
            return outcome;
        }

        outcome.PacketsReceived += 1;
        outcome.BytesReceived += (uint32_t)received.Bytes.size();
        if (received.RttMs > 0) outcome.RttMs = received.RttMs;

        domain::VoipReflectorPacketResult parsedSelfInfo =
            domain::VoipReflectorPacketCodec::ParseSelfInfoResponse(
                received.Bytes.empty() ? nullptr : &received.Bytes[0],
                received.Bytes.size(),
                endpoint.PeerTag);
        if (parsedSelfInfo.Success) {
            if (parsedSelfInfo.SelfInfo.QueryId == queryId) {
                selfInfoResponses++;
            }
            continue;
        }

        domain::VoipEncryptedPacketResult decrypted =
            domain::VoipPacketCrypto::DecryptRelayPacketMtProto2Short(
                sharedKey,
                localIsOutgoing,
                endpoint.PeerTag,
                received.Bytes.empty() ? nullptr : &received.Bytes[0],
                received.Bytes.size());
        if (!decrypted.Success) {
            decryptFailures++;
            lastPacketError = decrypted.Error;
            continue;
        }

        domain::VoipControlCodecResult decoded =
            domain::VoipControlPacketCodec::DecodeShort(
                decrypted.Plain.empty() ? nullptr : &decrypted.Plain[0],
                decrypted.Plain.size());
        if (!decoded.Success) {
            decodeFailures++;
            lastPacketError = decoded.Error;
            continue;
        }

        if (decoded.Packet.Sequence != 0 && lastRemoteSequence != nullptr) {
            if (*lastRemoteSequence == 0 || decoded.Packet.Sequence > *lastRemoteSequence) {
                *lastRemoteSequence = decoded.Packet.Sequence;
            }
        }

        if (decoded.Packet.Type == domain::VoipControlPacketType::InitAck) {
            domain::VoipControlCodecResult parsedAck =
                domain::VoipControlPacketCodec::ParseInitAckPayload(
                    decoded.Packet.Payload.empty() ? nullptr : &decoded.Packet.Payload[0],
                    decoded.Packet.Payload.size());
            if (!parsedAck.Success) {
                outcome.Error = TransportError(parsedAck.Error);
                return outcome;
            }
            if (!parsedAck.InitAck.HasAudioOpusStream) {
                outcome.Error = domain::VoipError::Of(
                    domain::VoipErrorKind::CodecFailed,
                    0,
                    "VoIP peer did not advertise an enabled OPUS audio stream");
                return outcome;
            }
            outcome.PeerVersion = parsedAck.InitAck.PeerVersion;
            outcome.AudioFrameDurationMs = parsedAck.InitAck.FrameDurationMs;
            outcome.SelfInfoResponses = (uint32_t)selfInfoResponses;
            outcome.DecryptFailures = (uint32_t)decryptFailures;
            outcome.DecodeFailures = (uint32_t)decodeFailures;
            outcome.InitAttempts = (uint32_t)initAttempts;
            outcome.InitAckReceived = true;
            return outcome;
        }

        if (decoded.Packet.Type == domain::VoipControlPacketType::Init) {
            domain::VoipControlCodecResult ackPayload =
                domain::VoipControlPacketCodec::BuildInitAckPayload();
            if (!ackPayload.Success) {
                outcome.Error = TransportError(ackPayload.Error);
                return outcome;
            }
            domain::VoipControlCodecResult ackPacket = BuildControlPacket(
                domain::VoipControlPacketType::InitAck,
                TakeNextSequence(nextLocalSequence),
                lastRemoteSequence == nullptr ? decoded.Packet.Sequence : *lastRemoteSequence,
                ackPayload.Bytes);
            if (!ackPacket.Success) {
                outcome.Error = TransportError(ackPacket.Error);
                return outcome;
            }
            std::string ackError;
            if (!EncryptAndSendControlPacket(
                    socket,
                    endpoint,
                    sharedKey,
                    localIsOutgoing,
                    ackPacket.Bytes,
                    &outcome,
                    &ackError)) {
                outcome.Error = TransportError(ackError);
                return outcome;
            }
            continue;
        }

        if (decoded.Packet.Type == domain::VoipControlPacketType::Ping) {
            domain::VoipControlCodecResult pongPacket = BuildControlPacket(
                domain::VoipControlPacketType::Pong,
                TakeNextSequence(nextLocalSequence),
                lastRemoteSequence == nullptr ? decoded.Packet.Sequence : *lastRemoteSequence,
                decoded.Packet.Payload);
            if (!pongPacket.Success) {
                outcome.Error = TransportError(pongPacket.Error);
                return outcome;
            }
            std::string pongError;
            if (!EncryptAndSendControlPacket(
                    socket,
                    endpoint,
                    sharedKey,
                    localIsOutgoing,
                    pongPacket.Bytes,
                    &outcome,
                    &pongError)) {
                outcome.Error = TransportError(pongError);
                return outcome;
            }
        }
    }

    outcome.SelfInfoResponses = (uint32_t)selfInfoResponses;
    outcome.DecryptFailures = (uint32_t)decryptFailures;
    outcome.DecodeFailures = (uint32_t)decodeFailures;
    outcome.InitAttempts = (uint32_t)initAttempts;
    outcome.InitAckReceived = false;

    std::ostringstream s;
    s << "VoIP INIT/INIT_ACK handshake timed out"
      << " attempts=" << initAttempts
      << " selfInfo=" << selfInfoResponses
      << " txPackets=" << outcome.PacketsSent
      << " rxPackets=" << outcome.PacketsReceived
      << " txBytes=" << outcome.BytesSent
      << " rxBytes=" << outcome.BytesReceived
      << " decryptFailures=" << decryptFailures
      << " decodeFailures=" << decodeFailures;
    if (!lastPacketError.empty()) {
        s << " lastPacketError=" << lastPacketError;
    }
    outcome.Error = domain::VoipError::Of(
        domain::VoipErrorKind::HandshakeTimeout,
        0,
        s.str().c_str());
    return outcome;
}

bool IsSupportedGenerator(int32_t g) {
    return g >= 2 && g <= 7;
}

bool ValidateDhConfig(int32_t g, const std::vector<uint8_t>& p, domain::VoipError* error) {
    if (!IsSupportedGenerator(g)) {
        if (error) *error = Invalid("DH generator must be in Telegram range {2..7}");
        return false;
    }
    if (p.size() != kDhBytes) {
        if (error) *error = Invalid("DH prime must be exactly 256 bytes");
        return false;
    }
    vianium::crypto::BigNum pBn(&p[0], p.size());
    if (pBn.GetBitLength() < 2048 || !pBn.GetBit(0)) {
        if (error) *error = Invalid("DH prime failed structural validation");
        return false;
    }
    return true;
}

bool ValidatePublicValue(
    const std::vector<uint8_t>& value,
    const std::vector<uint8_t>& p,
    domain::VoipError* error)
{
    if (p.size() != kDhBytes) {
        if (error) *error = Invalid("DH prime is missing for call state");
        return false;
    }
    if (value.size() != kDhBytes) {
        if (error) *error = Invalid("peer DH public value must be exactly 256 bytes");
        return false;
    }

    vianium::crypto::BigNum one(1);
    one.WordRef(0) = 1;
    vianium::crypto::BigNum peer(&value[0], value.size());
    vianium::crypto::BigNum pBn(&p[0], p.size());
    if (vianium::crypto::BigNum::Compare(peer, one) <= 0 ||
        vianium::crypto::BigNum::Compare(peer, pBn) >= 0) {
        if (error) *error = Invalid("peer DH public value is outside valid range");
        return false;
    }
    return true;
}

std::vector<uint8_t> PickPrivateExponent(const std::vector<uint8_t>& p) {
    vianium::crypto::BigNum one(1);
    one.WordRef(0) = 1;
    vianium::crypto::BigNum pBn(&p[0], p.size());

    for (int attempt = 0; attempt < 8; attempt++) {
        std::vector<uint8_t> candidate(kDhBytes);
        vianium::crypto::GenerateRandom(&candidate[0], kDhBytes);
        vianium::crypto::BigNum priv(&candidate[0], candidate.size());
        if (vianium::crypto::BigNum::Compare(priv, one) > 0 &&
            vianium::crypto::BigNum::Compare(priv, pBn) < 0) {
            return candidate;
        }
    }

    std::vector<uint8_t> fallback(kDhBytes, 0);
    fallback[kDhBytes - 1] = 2;
    return fallback;
}

std::vector<uint8_t> ComputePublic(
    int32_t g,
    const std::vector<uint8_t>& privateValue,
    const std::vector<uint8_t>& p)
{
    vianium::crypto::BigNum gBn(1);
    gBn.WordRef(0) = (uint32_t)g;
    vianium::crypto::BigNum priv(&privateValue[0], privateValue.size());
    vianium::crypto::BigNum pBn(&p[0], p.size());
    vianium::crypto::BigNum pub = gBn.ModPow(priv, pBn);

    std::vector<uint8_t> out(kDhBytes);
    pub.ToBytesFixedLen(&out[0], kDhBytes);
    return out;
}

std::vector<uint8_t> Sha256Bytes(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> out(vianium::crypto::Sha256::DIGEST_SIZE);
    vianium::crypto::Sha256::Hash(bytes.empty() ? nullptr : &bytes[0], bytes.size(), &out[0]);
    return out;
}

int64_t FingerprintForKey(const std::vector<uint8_t>& sharedKey) {
    uint8_t digest[vianium::crypto::Sha1::DIGEST_SIZE];
    vianium::crypto::Sha1::Hash(&sharedKey[0], sharedKey.size(), digest);
    uint64_t fp = 0;
    for (int i = 0; i < 8; i++) {
        fp |= ((uint64_t)digest[12 + i]) << (i * 8);
    }
    return (int64_t)fp;
}

std::vector<uint8_t> ComputeShared(
    const std::vector<uint8_t>& peerPublic,
    const std::vector<uint8_t>& privateValue,
    const std::vector<uint8_t>& p)
{
    vianium::crypto::BigNum peer(&peerPublic[0], peerPublic.size());
    vianium::crypto::BigNum priv(&privateValue[0], privateValue.size());
    vianium::crypto::BigNum pBn(&p[0], p.size());
    vianium::crypto::BigNum shared = peer.ModPow(priv, pBn);
    std::vector<uint8_t> out(kDhBytes);
    shared.ToBytesFixedLen(&out[0], kDhBytes);
    return out;
}

void SecureClear(std::vector<uint8_t>* bytes) {
    if (bytes == nullptr || bytes->empty()) return;
    volatile uint8_t* p = &(*bytes)[0];
    for (size_t i = 0; i < bytes->size(); i++) p[i] = 0;
    bytes->clear();
}
}

size_t VoipEngine::PendingSignalingBytes(const DhSession& session) {
    size_t bytes = 0;
    for (size_t i = 0; i < session.PendingSignalingPackets.size(); i++) {
        bytes += session.PendingSignalingPackets[i].size();
    }
    return bytes;
}

void VoipEngine::QueuePendingSignaling(
    DhSession* session,
    const std::vector<uint8_t>& data)
{
    if (session == nullptr || data.empty()) return;
    session->PendingSignalingPackets.push_back(data);

    while (session->PendingSignalingPackets.size() > kMaxPendingSignalingPackets
        || PendingSignalingBytes(*session) > kMaxPendingSignalingBytes) {
        if (session->PendingSignalingPackets.empty()) break;
        session->PendingSignalingPackets.erase(session->PendingSignalingPackets.begin());
        session->SignalingPacketsDropped += 1;
    }
}

VoipEngine::VoipEngine()
    : m_reflectorTransport(nullptr),
      m_audioFactory(nullptr),
      m_tgcallsGraph(nullptr),
      m_tgcallsCallId(0) {
}

VoipEngine::VoipEngine(ports::outbound::IVoipReflectorTransport* reflectorTransport)
    : m_reflectorTransport(reflectorTransport),
      m_audioFactory(nullptr),
      m_tgcallsGraph(nullptr),
      m_tgcallsCallId(0) {
}

VoipEngine::VoipEngine(
    ports::outbound::IVoipReflectorTransport* reflectorTransport,
    ports::outbound::IVoipAudioRuntimeFactory* audioFactory)
    : m_reflectorTransport(reflectorTransport),
      m_audioFactory(audioFactory),
      m_tgcallsGraph(nullptr),
      m_tgcallsCallId(0) {
}

VoipEngine::VoipEngine(
    ports::outbound::IVoipReflectorTransport* reflectorTransport,
    ports::outbound::IVoipAudioRuntimeFactory* audioFactory,
    ports::outbound::ITgcallsMediaGraph* tgcallsGraph)
    : m_reflectorTransport(reflectorTransport),
      m_audioFactory(audioFactory),
      m_tgcallsGraph(tgcallsGraph),
      m_tgcallsCallId(0) {
}

VoipEngine::~VoipEngine() {
    StopMedia();
    {
        ScopedLock lock(&m_lock);
        for (std::map<int64_t, DhSession>::iterator it = m_calls.begin(); it != m_calls.end(); ++it) {
            SecureClear(&it->second.PrivateValue);
            SecureClear(&it->second.SharedKey);
        }
        for (std::map<int32_t, DhSession>::iterator it = m_outgoingByRandom.begin(); it != m_outgoingByRandom.end(); ++it) {
            SecureClear(&it->second.PrivateValue);
            SecureClear(&it->second.SharedKey);
        }
        m_calls.clear();
        m_outgoingByRandom.clear();
    }
}

domain::VoipCapability VoipEngine::Capability() const {
    if (m_reflectorTransport == nullptr || m_audioFactory == nullptr) {
        return domain::VoipCapability::KeyExchangeOnly(kUnavailableReason);
    }
    std::string reason;
    if (!m_audioFactory->IsAvailable(&reason)) {
        return domain::VoipCapability::KeyExchangeOnly(
            reason.empty() ? kUnavailableReason : reason.c_str());
    }
    return domain::VoipCapability::MediaReady();
}

domain::VoipDhMaterial VoipEngine::CreateOutgoingDh(
    int32_t randomId,
    int32_t g,
    const std::vector<uint8_t>& p)
{
    domain::VoipError validation;
    if (!ValidateDhConfig(g, p, &validation))
        return domain::VoipDhMaterial::Fail(validation);

    DhSession session;
    session.RandomId = randomId;
    session.CallId = 0;
    session.G = g;
    session.Incoming = false;
    session.P = p;
    session.PrivateValue = PickPrivateExponent(p);
    session.PublicValue = ComputePublic(g, session.PrivateValue, p);
    session.PublicHash = Sha256Bytes(session.PublicValue);

    domain::VoipDhMaterial out = domain::VoipDhMaterial::Ok();
    out.PublicValue = session.PublicValue;
    out.PublicHash = session.PublicHash;

    {
        ScopedLock lock(&m_lock);
        m_outgoingByRandom[randomId] = session;
    }
    return out;
}

domain::VoipError VoipEngine::BindOutgoingCall(int32_t randomId, int64_t callId) {
    if (callId <= 0) return Invalid("callId must be positive");
    ScopedLock lock(&m_lock);
    std::map<int32_t, DhSession>::iterator it = m_outgoingByRandom.find(randomId);
    if (it == m_outgoingByRandom.end())
        return Invalid("outgoing DH state not found for random_id");
    DhSession session = it->second;
    session.CallId = callId;
    m_calls[callId] = session;
    m_droppedCallIds.erase(callId);
    m_outgoingByRandom.erase(it);
    return domain::VoipError::Ok();
}

domain::VoipError VoipEngine::RegisterIncomingGAHash(
    int64_t callId,
    const std::vector<uint8_t>& gAHash)
{
    if (callId <= 0) return Invalid("callId must be positive");
    if (gAHash.size() != vianium::crypto::Sha256::DIGEST_SIZE)
        return Invalid("incoming g_a_hash must be exactly 32 bytes");

    ScopedLock lock(&m_lock);
    DhSession session;
    std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
    if (it != m_calls.end()) session = it->second;
    session.CallId = callId;
    session.Incoming = true;
    session.PeerGAHash = gAHash;
    m_calls[callId] = session;
    m_droppedCallIds.erase(callId);
    return domain::VoipError::Ok();
}

domain::VoipDhMaterial VoipEngine::CreateIncomingDh(
    int64_t callId,
    int32_t g,
    const std::vector<uint8_t>& p)
{
    domain::VoipError validation;
    if (!ValidateDhConfig(g, p, &validation))
        return domain::VoipDhMaterial::Fail(validation);

    DhSession session;
    {
        ScopedLock lock(&m_lock);
        std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
        if (it == m_calls.end() || it->second.PeerGAHash.empty())
            return domain::VoipDhMaterial::Fail(Invalid("incoming g_a_hash was not registered"));
        session = it->second;
    }

    session.G = g;
    session.P = p;
    session.Incoming = true;
    session.PrivateValue = PickPrivateExponent(p);
    session.PublicValue = ComputePublic(g, session.PrivateValue, p);
    session.PublicHash = Sha256Bytes(session.PublicValue);

    domain::VoipDhMaterial out = domain::VoipDhMaterial::Ok();
    out.PublicValue = session.PublicValue;
    out.PublicHash = session.PublicHash;

    {
        ScopedLock lock(&m_lock);
        m_calls[callId] = session;
    }
    return out;
}

domain::VoipDhMaterial VoipEngine::AcceptPeerGB(
    int64_t callId,
    const std::vector<uint8_t>& gB)
{
    DhSession session;
    {
        ScopedLock lock(&m_lock);
        std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
        if (it == m_calls.end())
            return domain::VoipDhMaterial::Fail(Invalid("call DH state not found"));
        session = it->second;
    }

    domain::VoipError validation;
    if (!ValidatePublicValue(gB, session.P, &validation))
        return domain::VoipDhMaterial::Fail(validation);

    session.SharedKey = ComputeShared(gB, session.PrivateValue, session.P);
    session.KeyFingerprint = FingerprintForKey(session.SharedKey);
    session.SharedReady = true;

    domain::VoipDhMaterial out = domain::VoipDhMaterial::Ok();
    out.PublicValue = session.PublicValue;
    out.PublicHash = session.PublicHash;
    out.KeyFingerprint = session.KeyFingerprint;
    out.KeyHandle = HandleForCall(callId);

    {
        ScopedLock lock(&m_lock);
        m_calls[callId] = session;
    }
    return out;
}

domain::VoipError VoipEngine::ConfirmPeerGAOrB(
    int64_t callId,
    const std::vector<uint8_t>& gAOrB,
    int64_t expectedFingerprint)
{
    DhSession session;
    {
        ScopedLock lock(&m_lock);
        std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
        if (it == m_calls.end()) return Invalid("call DH state not found");
        session = it->second;
    }

    if (session.PeerGAHash.size() == vianium::crypto::Sha256::DIGEST_SIZE) {
        std::vector<uint8_t> gotHash = Sha256Bytes(gAOrB);
        if (std::memcmp(&gotHash[0], &session.PeerGAHash[0], gotHash.size()) != 0) {
            return domain::VoipError::Of(
                domain::VoipErrorKind::FingerprintMismatch,
                0,
                "SHA256(g_a) does not match the caller's committed g_a_hash");
        }
    }

    domain::VoipError validation;
    if (!ValidatePublicValue(gAOrB, session.P, &validation))
        return validation;

    session.SharedKey = ComputeShared(gAOrB, session.PrivateValue, session.P);
    session.KeyFingerprint = FingerprintForKey(session.SharedKey);
    session.SharedReady = true;

    if (expectedFingerprint != 0 && session.KeyFingerprint != expectedFingerprint) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::FingerprintMismatch,
            0,
            "shared-key fingerprint does not match phoneCall.key_fingerprint");
    }

    {
        ScopedLock lock(&m_lock);
        m_calls[callId] = session;
    }
    return domain::VoipError::Ok();
}

int64_t VoipEngine::GetLocalFingerprint(int64_t callId) {
    ScopedLock lock(&m_lock);
    std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
    if (it == m_calls.end()) return 0;
    return it->second.KeyFingerprint;
}

std::string VoipEngine::GetKeyHandle(int64_t callId) {
    ScopedLock lock(&m_lock);
    std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
    if (it == m_calls.end() || !it->second.SharedReady) return std::string();
    return HandleForCall(callId);
}

std::vector<uint8_t> VoipEngine::GetSharedKeyDiagnosticBytes(int64_t callId) const {
    ScopedLock lock(const_cast<concurrency::critical_section*>(&m_lock));
    std::map<int64_t, DhSession>::const_iterator it = m_calls.find(callId);
    if (it == m_calls.end() || !it->second.SharedReady) return std::vector<uint8_t>();
    if (it->second.SharedKey.size() != 256) return std::vector<uint8_t>();
    return it->second.SharedKey;
}

void VoipEngine::DropCall(int64_t callId) {
    std::shared_ptr<TgcallsConnection> conn;
    {
        ScopedLock lock(&m_lock);
        std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
        if (it != m_calls.end()) {
            SecureClear(&it->second.PrivateValue);
            SecureClear(&it->second.SharedKey);
            m_calls.erase(it);
        }
        m_droppedCallIds.insert(callId);
        if (m_tgcallsCallId == callId) {
            conn = m_tgcallsConnection;
            m_tgcallsConnection.reset();
            m_tgcallsCallId = 0;
        }
    }
    if (conn) {
        conn->Stop();
    }
}

domain::VoipError VoipEngine::StartMedia(
    int64_t callId,
    const std::string& keyHandle,
    const std::vector<domain::VoipEndpoint>& endpoints)
{
    domain::VoipCallStartDescriptor descriptor;
    descriptor.CallId = callId;
    descriptor.KeyHandle = keyHandle;
    descriptor.Endpoints = endpoints;
    descriptor.UdpReflector = true;
    descriptor.MinLayer = 92;
    descriptor.MaxLayer = 92;
    descriptor.LibraryVersions.push_back("2.4.4");
    return StartMedia(descriptor);
}

domain::VoipError VoipEngine::StartMedia(
    const domain::VoipCallStartDescriptor& descriptor)
{
    const int64_t callId = descriptor.CallId;
    const std::string& keyHandle = descriptor.KeyHandle;
    const std::vector<domain::VoipEndpoint>& endpoints = descriptor.Endpoints;

    if (callId <= 0) return Invalid("callId must be positive");
    if (keyHandle.empty()) return Invalid("call key handle is missing");

    DhSession session;
    {
        ScopedLock lock(&m_lock);
        std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
        if (it == m_calls.end() || !it->second.SharedReady) {
            return Invalid("call shared key is not ready");
        }
        if (HandleForCall(callId) != keyHandle) {
            return Invalid("call key handle does not belong to this call");
        }
        session = it->second;
    }

    // Media-plane routing: decide on the negotiated library_versions only.
    //
    // Pending signaling packets are NOT a tgcalls signal. When the peer
    // negotiates only classic versions ([2.4.4, 5.0.0, 7.0.0]) it picks
    // classic libtgvoip and sends classic init/init_ack via the reflector,
    // with no tgcalls 2.x JSON signaling at all; any pending packets in
    // that case are just classic libtgvoip wire packets that
    // updatePhoneCallSignalingData transports. Routing them to tgcalls 2.x
    // would make the peer's binary classic signaling unparseable, so the
    // negotiated library_versions are the sole routing input here.
    const bool descriptorIsModern = !IsClassicReflectorDescriptor(descriptor);
    const bool routeToTgcalls     = descriptorIsModern;

    int webrtcEndpointCount = 0;
    int reflectorEndpointCount = 0;
    for (size_t i = 0; i < descriptor.Endpoints.size(); ++i) {
        if (descriptor.Endpoints[i].IsWebRtc) ++webrtcEndpointCount;
        else ++reflectorEndpointCount;
    }
    {
        std::ostringstream trace;
        trace << "[VoipEngine.MediaPlaneRouting]"
              << " callId=" << (long long)callId
              << " minLayer=" << descriptor.MinLayer
              << " maxLayer=" << descriptor.MaxLayer
              << " webrtcEndpoints=" << webrtcEndpointCount
              << " reflectorEndpoints=" << reflectorEndpointCount
              << " descriptorIsModern=" << (descriptorIsModern ? "yes" : "no")
              << " pendingSignalingPackets=" << session.PendingSignalingPackets.size()
              << " route=" << (routeToTgcalls ? "tgcalls" : "classic")
              << "\n";
        ::OutputDebugStringA(trace.str().c_str());
    }

    if (routeToTgcalls) {
        // Prefer the in-process TgcallsConnection orchestrator. It owns
        // the DTLS / SRTP / ICE pipelines directly inside VianiumVoIP so
        // it has linker access to OpusVoipCodec, WinrtVoipAudioDevice,
        // EcdsaP256KeyPair and the signaling envelope without forming a
        // project cycle through Vianium.Tgcalls.dll.
        {
            std::shared_ptr<TgcallsConnection> conn;
            ports::outbound::TgcallsSignalingDataProducedHandler signalingOut;
            {
                ScopedLock lock(&m_lock);
                signalingOut = m_signalingDataProduced;
            }

            TgcallsConnection::StartParams params;
            params.CallId = callId;
            params.IsOutgoing = descriptor.IsInitiator;
            params.SharedKey = session.SharedKey;
            //
            // Enroll classic Reflector endpoints (peer_tag=16B) as the
            // primary tgcalls 2.x media-plane reflectors. The classic
            // reflectors are protocol-agnostic — they just forward any
            // bytes prefixed with peer_tag to the matching peer, so they
            // work for tgcalls 2.x ICE/DTLS/SRTP wire content the same
            // way they work for classic libtgvoip control packets.
            //
            // WebRtc endpoints (port 1400, no peer_tag) are TURN servers
            // (RFC 5766) requiring username/password long-term credentials.
            // TgcallsConnection handles them via the TurnClient state
            // machine — we enroll them with IsWebRtc=true and the creds
            // come from the phoneConnectionWebrtc descriptor.
            //
            // We also still enroll classic Reflector endpoints (peer_tag=16B)
            // as a fallback path. TgcallsConnection's Start() opens both —
            // a TurnClient per WebRtc endpoint, and a peer_tag Session per
            // classic endpoint. SendViaReflector routes outbound traffic
            // through whichever path completes first.
            //
            for (size_t i = 0; i < descriptor.Endpoints.size(); i++) {
                const domain::VoipEndpoint& ep = descriptor.Endpoints[i];
                TgcallsConnection::ReflectorEndpoint r;
                r.Ip = ep.Ip;
                r.Ipv6 = ep.Ipv6;
                r.Port = ep.Port;
                if (ep.IsWebRtc) {
                    // Need username/password to do TURN Allocate. Skip if
                    // either is missing (server bug or descriptor parse
                    // mismatch — fall back to classic only).
                    if (ep.Username.empty() || ep.Password.empty()) continue;
                    r.IsWebRtc = true;
                    r.Username = ep.Username;
                    r.Password = ep.Password;
                    // PeerTag intentionally left empty for WebRtc — the
                    // TURN wire framing (Send Indication / Data Indication)
                    // doesn't use it.
                } else {
                    if (ep.PeerTag.size() != 16) continue; // need a wrap key
                    r.IsWebRtc = false;
                    r.PeerTag = ep.PeerTag;
                }
                params.Reflectors.push_back(r);
            }

            if (params.Reflectors.empty()) {
                // No WebRTC reflectors in the descriptor — drop through
                // to the legacy ITgcallsMediaGraph path / unavailable
                // failure below.
            } else {
                TgcallsConnection::SignalingDataCallback signalingCb =
                    [signalingOut](int64_t cid, const std::vector<uint8_t>& bytes) {
                        if (signalingOut) signalingOut(cid, bytes);
                    };
                TgcallsConnection::StateCallback stateCb =
                    [](TgcallsConnection::State /*s*/) { /* TODO: bridge to media snapshot */ };

                conn = std::make_shared<TgcallsConnection>(params, signalingCb, stateCb);
                domain::VoipError started = conn->Start();
                if (!started.IsOk()) return started;

                // Drain any signaling that arrived before Start.
                std::vector<std::vector<uint8_t> > pending;
                {
                    ScopedLock lock(&m_lock);
                    std::map<int64_t, DhSession>::iterator activeIt = m_calls.find(callId);
                    if (activeIt != m_calls.end()) {
                        pending.swap(activeIt->second.PendingSignalingPackets);
                    }
                    m_tgcallsConnection = conn;
                    m_tgcallsCallId = callId;
                }

                for (size_t i = 0; i < pending.size(); i++) {
                    domain::VoipError delivered = conn->HandleIncomingSignaling(pending[i]);
                    if (!delivered.IsOk()) {
                        ScopedLock lock(&m_lock);
                        m_tgcallsConnection.reset();
                        m_tgcallsCallId = 0;
                        return delivered;
                    }
                }
                return domain::VoipError::Ok();
            }
        }

        if (m_tgcallsGraph != nullptr) {
            ports::outbound::TgcallsMediaGraphStartContext context;
            context.Descriptor = descriptor;
            context.SharedKey = session.SharedKey;
            {
                ScopedLock lock(&m_lock);
                context.SignalingDataProduced = m_signalingDataProduced;
            }
            domain::VoipError start = m_tgcallsGraph->Start(context);
            if (!start.IsOk()) return start;

            for (;;) {
                std::vector<std::vector<uint8_t> > pending;
                {
                    ScopedLock lock(&m_lock);
                    std::map<int64_t, DhSession>::iterator activeIt = m_calls.find(callId);
                    if (activeIt == m_calls.end()) {
                        m_tgcallsCallId = 0;
                    }
                    if (activeIt == m_calls.end()) break;

                    if (activeIt->second.PendingSignalingPackets.empty()) {
                        m_tgcallsCallId = callId;
                        break;
                    }

                    pending.swap(activeIt->second.PendingSignalingPackets);
                }

                for (size_t i = 0; i < pending.size(); i++) {
                    domain::VoipError delivered =
                        m_tgcallsGraph->ReceiveSignalingData(callId, pending[i]);
                    if (!delivered.IsOk()) {
                        m_tgcallsGraph->Stop(callId);
                        ScopedLock lock(&m_lock);
                        if (m_tgcallsCallId == callId) m_tgcallsCallId = 0;
                        return delivered;
                    }
                }
            }
            bool graphActive = false;
            {
                ScopedLock lock(&m_lock);
                graphActive = m_tgcallsCallId == callId;
            }
            if (!graphActive) {
                m_tgcallsGraph->Stop(callId);
                return Invalid("call DH state was dropped while starting tgcalls media graph");
            }
            return domain::VoipError::Ok();
        }

        std::ostringstream s;
        s << "negotiated Telegram VoIP protocol "
          << SelectedLibraryVersion(descriptor)
          << " requires the VianiumVoIP native tgcalls/WebRTC media graph";
        if (HasWebRtcEndpoint(endpoints)) {
            s << " (phoneConnectionWebrtc endpoints present)";
        }
        if (session.SignalingPacketsReceived > 0) {
            s << "; received "
              << session.SignalingPacketsReceived
              << " signaling packet(s)/"
              << session.SignalingBytesReceived
              << "B before media start";
        }
        if (!session.PendingSignalingPackets.empty()) {
            s << "; queued "
              << session.PendingSignalingPackets.size()
              << " early signaling packet(s)/"
              << PendingSignalingBytes(session)
              << "B for tgcalls startup";
        }
        if (session.SignalingPacketsDropped > 0) {
            s << "; dropped "
              << session.SignalingPacketsDropped
              << " early signaling packet(s) because the native queue limit was reached";
        }
        s << "; advertised_versions=["
          << JoinLibraryVersions(descriptor.LibraryVersions)
          << "] callConfig="
          << descriptor.CallConfigJson.size()
          << "B. No ITgcallsMediaGraph backend is bound in this WP81 build. "
          << "Classic reflector fallback is intentionally blocked for this negotiation.";
        return domain::VoipError::Unavailable(s.str().c_str());
    }

    std::vector<domain::VoipEndpoint> candidates = OrderedReflectorEndpoints(endpoints);
    if (candidates.empty()) {
        domain::VoipEndpointSelection selected =
            domain::VoipEndpointSelector::SelectReflector(endpoints);
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed,
            0,
            selected.Reason.c_str());
    }

    if (m_reflectorTransport == nullptr) {
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed,
            0,
            "VoIP reflector transport is unavailable");
    }
    if (m_audioFactory == nullptr) {
        return domain::VoipError::Unavailable(kUnavailableReason);
    }

    domain::VoipEndpoint selectedEndpoint;
    bool selectedEndpointReady = false;
    std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> selectedSocket;
    uint32_t selectedNextLocalSequence = session.NextLocalSequence;
    uint32_t selectedLastRemoteSequence = session.LastRemoteSequence;
    ControlHandshakeOutcome selectedHandshake;
    domain::VoipError lastEndpointError =
        TransportError("no Telegram reflector endpoint completed VoIP control handshake");
    std::vector<std::string> endpointErrors;

    // Per-endpoint counters for the soft-fail HandshakeFailure summary.
    int classicEndpointsTotal = 0;
    int classicEndpointsResponded = 0;
    int webrtcEndpointsTotal = 0;
    int webrtcEndpointsResponded = 0;
    int classicEndpointsWithSelfInfo = 0;

    for (size_t i = 0; i < candidates.size(); i++) {
        const domain::VoipEndpoint& endpoint = candidates[i];
        if (endpoint.IsWebRtc) {
            webrtcEndpointsTotal++;
        } else {
            classicEndpointsTotal++;
        }

        domain::VoipError prepared = m_mediaSession.Prepare(callId, keyHandle, endpoint);
        if (!prepared.IsOk()) {
            lastEndpointError = WithEndpoint(prepared, endpoint, "VoIP media session prepare failed");
            endpointErrors.push_back(lastEndpointError.Message);
            m_mediaSession.Stop();
            continue;
        }
        domain::VoipError connecting = m_mediaSession.MarkConnecting();
        if (!connecting.IsOk()) {
            lastEndpointError = WithEndpoint(connecting, endpoint, "VoIP media session connecting failed");
            endpointErrors.push_back(lastEndpointError.Message);
            m_mediaSession.Stop();
            continue;
        }

        std::unique_ptr<ports::outbound::IVoipReflectorDatagramSession> candidateSocket =
            m_reflectorTransport->CreateDatagramSession();
        if (!candidateSocket) {
            std::string detail = "endpoint=" + EndpointLabel(endpoint)
                + ": VoIP reflector transport did not create a datagram session";
            lastEndpointError = domain::VoipError::Of(
                domain::VoipErrorKind::TransportFailed,
                0,
                detail.c_str());
            endpointErrors.push_back(lastEndpointError.Message);
            m_mediaSession.Stop();
            continue;
        }

        ports::outbound::VoipReflectorDatagramResult opened = candidateSocket->Open(endpoint);
        if (!opened.Success) {
            std::string detail = "endpoint=" + EndpointLabel(endpoint) + ": " + opened.Error;
            lastEndpointError = domain::VoipError::Of(
                domain::VoipErrorKind::TransportFailed,
                0,
                detail.c_str());
            endpointErrors.push_back(lastEndpointError.Message);
            candidateSocket->Close();
            m_mediaSession.Stop();
            continue;
        }

        uint32_t candidateNextLocalSequence = session.NextLocalSequence;
        uint32_t candidateLastRemoteSequence = session.LastRemoteSequence;
        ControlHandshakeOutcome handshake = RunControlHandshake(
            candidateSocket.get(),
            endpoint,
            QueryIdForCall(callId),
            session.SharedKey,
            !session.Incoming,
            &candidateNextLocalSequence,
            &candidateLastRemoteSequence);

        // Per-endpoint stats trace (success or failure).
        EmitHandshakeStats(endpoint, handshake);
        if (handshake.PacketsReceived > 0) {
            if (endpoint.IsWebRtc) webrtcEndpointsResponded++;
            else classicEndpointsResponded++;
        }
        if (!endpoint.IsWebRtc && handshake.SelfInfoResponses > 0) {
            classicEndpointsWithSelfInfo++;
        }

        if (!handshake.Error.IsOk()) {
            std::ostringstream detail;
            detail << "endpoint=" << EndpointLabel(endpoint)
                   << " kind=" << EndpointKindLabel(endpoint)
                   << ": " << handshake.Error.Message;
            lastEndpointError = domain::VoipError::Of(
                handshake.Error.Kind,
                handshake.Error.Code,
                detail.str().c_str());
            endpointErrors.push_back(lastEndpointError.Message);
            candidateSocket->Close();
            m_mediaSession.Stop();
            continue;
        }

        m_mediaSession.RecordHandshake(
            handshake.PacketsSent,
            handshake.PacketsReceived,
            handshake.BytesSent,
            handshake.BytesReceived,
            handshake.RttMs);
        selectedEndpoint = endpoint;
        selectedSocket = std::move(candidateSocket);
        selectedNextLocalSequence = candidateNextLocalSequence;
        selectedLastRemoteSequence = candidateLastRemoteSequence;
        selectedHandshake = handshake;
        selectedEndpointReady = true;
        break;
    }

    if (!selectedEndpointReady) {
        m_mediaSession.Stop();

        // ---- Soft-fail diagnostic path -----------------------------------
        // After 12 attempts x N endpoints (classic + WebRtc probe) and still
        // no INIT_ACK, classify the failure mode and emit a structured
        // HandshakeFailure trace so the next call gives concrete data.
        //
        // CRITICAL: re-read the live signaling counter from m_calls[callId]
        // because `session` here is a copy snapshotted at handshake start —
        // it does NOT reflect tgcalls signaling that arrived AFTER the local
        // copy was taken. Without this re-read, modern-peer calls misreport
        // hint=peerOffline even when 10+ Candidates packets were received
        // and routed to TgcallsConnection.
        uint32_t liveSignalingCount = session.SignalingPacketsReceived;
        uint32_t liveSignalingBytes = session.SignalingBytesReceived;
        {
            ScopedLock lock(&m_lock);
            std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
            if (it != m_calls.end()) {
                liveSignalingCount = it->second.SignalingPacketsReceived;
                liveSignalingBytes = it->second.SignalingBytesReceived;
            }
        }

        const char* hint = "peerOffline";
        if (liveSignalingCount > 0) {
            // Modern peer: signaling packets arrived but classic INIT_ACK
            // never did -> peer is on tgcalls and won't fall back.
            hint = "peerLikelyTgcalls";
        } else if (classicEndpointsTotal > 0 && classicEndpointsWithSelfInfo == 0) {
            // We never reached any reflector at all -> network is blocking
            // outbound UDP to the reflector pool (not just peer-side issue).
            hint = "networkBlocked";
        }

        {
            std::ostringstream trace;
            trace << "[VoipEngine.HandshakeFailure]"
                  << " callId=" << (long long)callId
                  << " signalingPacketsReceived=" << liveSignalingCount
                  << " signalingBytesReceived=" << liveSignalingBytes
                  << " classicEndpointsResponded=" << classicEndpointsResponded
                  << "/" << classicEndpointsTotal
                  << " webrtcEndpointsResponded=" << webrtcEndpointsResponded
                  << "/" << webrtcEndpointsTotal
                  << " classicEndpointsWithSelfInfo=" << classicEndpointsWithSelfInfo
                  << " hint=" << hint
                  << "\n";
            ::OutputDebugStringA(trace.str().c_str());
        }

        if (!endpointErrors.empty()) {
            std::ostringstream summary;
            summary << "VoIP control handshake timed out across "
                    << candidates.size() << " endpoint(s)"
                    << " (classic=" << classicEndpointsTotal
                    << ", webrtc=" << webrtcEndpointsTotal << ")"
                    << "; classicResponded=" << classicEndpointsResponded
                    << "/" << classicEndpointsTotal
                    << "; webrtcResponded=" << webrtcEndpointsResponded
                    << "/" << webrtcEndpointsTotal
                    << "; signalingPacketsReceived=" << liveSignalingCount
                    << "; hint=" << hint;
            return domain::VoipError::Of(
                domain::VoipErrorKind::HandshakeTimeout,
                0,
                summary.str().c_str());
        }
        return lastEndpointError;
    }

    std::unique_ptr<ports::outbound::IVoipAudioDevice> audio = m_audioFactory->CreateDevice();
    if (!audio) {
        m_mediaSession.Stop();
        return domain::VoipError::Of(
            domain::VoipErrorKind::AudioDeviceFailed,
            0,
            "VoIP audio device factory returned null");
    }
    ports::outbound::VoipAudioIoResult audioOpen = audio->Open();
    if (!audioOpen.Success) {
        m_mediaSession.Stop();
        return domain::VoipError::Of(
            domain::VoipErrorKind::AudioDeviceFailed,
            0,
            audioOpen.Error.c_str());
    }

    std::unique_ptr<ports::outbound::IVoipAudioCodec> codec = m_audioFactory->CreateCodec();
    if (!codec) {
        audio->Close();
        m_mediaSession.Stop();
        return domain::VoipError::Of(
            domain::VoipErrorKind::CodecFailed,
            0,
            "VoIP audio codec factory returned null");
    }
    int codecInit = codec->Init(24000);
    if (codecInit != 0 || !codec->Ready()) {
        audio->Close();
        m_mediaSession.Stop();
        std::ostringstream s;
        s << "Opus VoIP codec init failed code=" << codecInit;
        return domain::VoipError::Of(
            domain::VoipErrorKind::CodecFailed,
            codecInit,
            s.str().c_str());
    }

    if (!selectedSocket) {
        audio->Close();
        codec->Destroy();
        m_mediaSession.Stop();
        return domain::VoipError::Of(
            domain::VoipErrorKind::TransportFailed,
            0,
            "VoIP media datagram session was not selected");
    }

    std::shared_ptr<VoipActiveMediaContext> active(new VoipActiveMediaContext());
    active->Socket = std::move(selectedSocket);
    active->Audio = std::move(audio);
    active->Codec = std::move(codec);
    active->SharedKey = session.SharedKey;
    active->PeerTag = selectedEndpoint.PeerTag;
    active->LocalIsOutgoing = !session.Incoming;
    active->NextLocalSequence = selectedNextLocalSequence;
    active->LastRemoteSequence = selectedLastRemoteSequence;
    active->InitAckReceived.store(selectedHandshake.Error.IsOk());

    {
        ScopedLock lock(&m_lock);
        m_activeMedia = active;
    }

    concurrency::create_task([active]() { InitLoop(active); });
    concurrency::create_task([active]() { MediaSendLoop(active); });
    concurrency::create_task([active]() { MediaReceiveLoop(active); });
    return domain::VoipError::Ok();
}

domain::VoipError VoipEngine::ReceiveSignalingData(
    int64_t callId,
    const std::vector<uint8_t>& data)
{
    if (callId <= 0) return Invalid("callId must be positive");
    if (data.empty()) return Invalid("VoIP signaling data is empty");

    bool deliverToGraph = false;
    std::shared_ptr<TgcallsConnection> conn;
    {
        ScopedLock lock(&m_lock);
        std::map<int64_t, DhSession>::iterator it = m_calls.find(callId);
        if (it == m_calls.end()) {
            if (m_droppedCallIds.find(callId) != m_droppedCallIds.end()) {
                return domain::VoipError::Ok();
            }
            return Invalid("call DH state not found for signaling data");
        }

        it->second.SignalingPacketsReceived += 1;
        it->second.SignalingBytesReceived += static_cast<uint32_t>(data.size());

        if (m_tgcallsConnection && m_tgcallsCallId == callId) {
            conn = m_tgcallsConnection;
        } else {
            deliverToGraph = m_tgcallsGraph != nullptr && m_tgcallsCallId == callId;
            if (!deliverToGraph) {
                QueuePendingSignaling(&it->second, data);
            }
        }
    }

    if (conn) {
        domain::VoipError delivered = conn->HandleIncomingSignaling(data);
        if (!delivered.IsOk()) return delivered;
        return domain::VoipError::Ok();
    }

    if (deliverToGraph) {
        domain::VoipError delivered = m_tgcallsGraph->ReceiveSignalingData(callId, data);
        if (!delivered.IsOk()) return delivered;
    }

    return domain::VoipError::Ok();
}

void VoipEngine::SetSignalingDataProducedHandler(
    ports::outbound::TgcallsSignalingDataProducedHandler handler)
{
    ScopedLock lock(&m_lock);
    m_signalingDataProduced = handler;
}

domain::VoipError VoipEngine::StopMedia() {
    std::shared_ptr<VoipActiveMediaContext> active;
    std::shared_ptr<TgcallsConnection> conn;
    int64_t tgcallsCallId = 0;
    {
        ScopedLock lock(&m_lock);
        active = m_activeMedia;
        m_activeMedia.reset();
        conn = m_tgcallsConnection;
        m_tgcallsConnection.reset();
        tgcallsCallId = m_tgcallsCallId;
        m_tgcallsCallId = 0;
    }
    if (active) {
        active->StopRequested.store(true);
        if (active->Socket) active->Socket->Close();
        if (active->Audio) active->Audio->Close();
        if (active->Codec) active->Codec->Destroy();
    }
    if (conn) {
        conn->Stop();
    }
    if (m_tgcallsGraph != nullptr && tgcallsCallId > 0 && !conn) {
        domain::VoipError stopped = m_tgcallsGraph->Stop(tgcallsCallId);
        if (!stopped.IsOk()) return stopped;
    }
    m_mediaSession.Stop();
    return domain::VoipError::Ok();
}

domain::VoipError VoipEngine::SetMuted(bool muted) {
    domain::VoipError result = m_mediaSession.SetMuted(muted);
    std::shared_ptr<VoipActiveMediaContext> active;
    std::shared_ptr<TgcallsConnection> conn;
    int64_t tgcallsCallId = 0;
    {
        ScopedLock lock(&m_lock);
        active = m_activeMedia;
        conn = m_tgcallsConnection;
        tgcallsCallId = m_tgcallsCallId;
    }
    if (active && active->Audio) active->Audio->SetMuted(muted);
    if (conn) {
        domain::VoipError tgc = conn->SetMuted(muted);
        if (!tgc.IsOk()) return tgc;
        return result;
    }
    if (m_tgcallsGraph != nullptr && tgcallsCallId > 0) {
        domain::VoipError graph = m_tgcallsGraph->SetMuted(tgcallsCallId, muted);
        if (!graph.IsOk()) return graph;
    }
    return result;
}

domain::VoipError VoipEngine::SetSpeaker(bool on) {
    domain::VoipError result = m_mediaSession.SetSpeaker(on);
    std::shared_ptr<VoipActiveMediaContext> active;
    std::shared_ptr<TgcallsConnection> conn;
    int64_t tgcallsCallId = 0;
    {
        ScopedLock lock(&m_lock);
        active = m_activeMedia;
        conn = m_tgcallsConnection;
        tgcallsCallId = m_tgcallsCallId;
    }
    if (active && active->Audio) active->Audio->SetSpeaker(on);
    if (conn) {
        domain::VoipError tgc = conn->SetSpeaker(on);
        if (!tgc.IsOk()) return tgc;
        return result;
    }
    if (m_tgcallsGraph != nullptr && tgcallsCallId > 0) {
        domain::VoipError graph = m_tgcallsGraph->SetSpeaker(tgcallsCallId, on);
        if (!graph.IsOk()) return graph;
    }
    return result;
}

domain::VoipMediaSnapshot VoipEngine::GetMediaSnapshot() const {
    domain::VoipMediaSnapshot snapshot = m_mediaSession.Snapshot();
    std::shared_ptr<VoipActiveMediaContext> active;
    int64_t tgcallsCallId = 0;
    std::shared_ptr<TgcallsConnection> tgcallsConn;
    {
        ScopedLock lock(&m_lock);
        active = m_activeMedia;
        tgcallsCallId = m_tgcallsCallId;
        tgcallsConn = m_tgcallsConnection;
    }
    // When the in-process TgcallsConnection orchestrator is active (modern
    // path), surface its real tx/rx counters so the managed-side
    // WaitForNativeMediaActiveAsync poll shows actual wire traffic instead
    // of an always-zero classic m_mediaSession. This also makes "did STUN
    // binding requests reach the wire?" answerable from the managed log
    // channel.
    if (tgcallsConn && tgcallsCallId > 0) {
        TgcallsConnection::StatsSnapshot ts = tgcallsConn->GetStatsSnapshot();
        switch (ts.CurrentState) {
            case TgcallsConnection::State::Connected:
                snapshot.State = domain::VoipMediaState::Active;
                break;
            case TgcallsConnection::State::Failed:
                // No "Failed" enumerator on VoipMediaState; use Stopped
                // for both terminal states. Managed surfaces the failure
                // detail string separately via RaiseMediaState() inside
                // VianiumVoipCallsAdapter.StartAsync().
                snapshot.State = domain::VoipMediaState::Stopped;
                break;
            case TgcallsConnection::State::Stopped:
                snapshot.State = domain::VoipMediaState::Stopped;
                break;
            default:
                // Initial / IceConnecting / DtlsHandshaking all map to
                // Connecting from the user's point of view (the call is
                // negotiating but has not yet produced audio). Audio only
                // starts after Connected -> Audio loop transition.
                snapshot.State = domain::VoipMediaState::Connecting;
                break;
        }
        snapshot.Stats.PacketsSent     = static_cast<uint32_t>(ts.TxPackets);
        snapshot.Stats.PacketsReceived = static_cast<uint32_t>(ts.RxPackets);
        snapshot.Stats.BytesSent       = static_cast<uint32_t>(ts.TxBytes);
        snapshot.Stats.BytesReceived   = static_cast<uint32_t>(ts.RxBytes);
        return snapshot;
    }
    if (!active && m_tgcallsGraph != nullptr && tgcallsCallId > 0) {
        return m_tgcallsGraph->Snapshot(tgcallsCallId);
    }
    if (active) {
        snapshot.State = active->MediaReady.load()
            ? domain::VoipMediaState::Active
            : domain::VoipMediaState::Connecting;
        snapshot.Stats.PacketsSent += active->MediaPacketsSent.load();
        snapshot.Stats.PacketsReceived += active->MediaPacketsReceived.load();
        snapshot.Stats.BytesSent += active->MediaBytesSent.load();
        snapshot.Stats.BytesReceived += active->MediaBytesReceived.load();
        snapshot.Stats.Underruns += (int32_t)active->AudioUnderruns.load();
        snapshot.Stats.OutboundLevel =
            (float)active->OutboundLevelPermille.load() / 1000.0f;
        snapshot.Stats.InboundLevel =
            (float)active->InboundLevelPermille.load() / 1000.0f;
        uint32_t mediaPackets = active->MediaPacketsSent.load();
        snapshot.Stats.BitrateBps =
            (int32_t)((active->MediaBytesSent.load() * 8U * 1000U)
                / (mediaPackets == 0 ? 1000U : (mediaPackets * (uint32_t)domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs)));
    }
    return snapshot;
}

}}} // namespace vianigram::voip::application
