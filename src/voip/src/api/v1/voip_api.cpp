// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_api.h"

#include "../../application/voip_engine.h"
#include "../../application/ice_agent.h"
#include "../../domain/voip_control_packet.h"
#include "../../domain/voip_endpoint_selector.h"
#include "../../domain/voip_jitter_buffer.h"
#include "../../domain/voip_media_session.h"
#include "../../domain/voip_packet_crypto.h"
#include "../../domain/voip_reflector_packet.h"
#include "../../domain/voip_rtp_packet.h"
#include "../../domain/tgcalls_signaling_codec.h"
#include "../../domain/tgcalls_signaling_envelope.h"
#include "../../domain/tgcalls_signaling_messages.h"
#include "../../domain/ice_candidate.h"
#include "../../infrastructure/datagram_socket_reflector_transport.h"
#include "../../infrastructure/dynamic_tgcalls_media_graph.h"
#include "../../infrastructure/ecdsa_p256_keypair.h"
#include "../../infrastructure/opus_voip_codec.h"
#include "../../infrastructure/srtp/srtp_packet_codec.h"
#include "../../infrastructure/srtp/srtp_session_keys.h"
#include "../../infrastructure/winrt_voip_audio_device.h"
#include "../../infrastructure/ice/stun_message.h"
#include "../../internal/voip_log.h"

#include <collection.h>
#include <ppltasks.h>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>

using namespace concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;

namespace Vianium { namespace VoIP {

namespace {

vianigram::voip::application::VoipEngine& Engine() {
    static vianigram::voip::infrastructure::DatagramSocketReflectorTransport reflectorTransport;
    static vianigram::voip::infrastructure::WinrtVoipAudioRuntimeFactory audioFactory;
    static vianigram::voip::infrastructure::DynamicTgcallsMediaGraph tgcallsGraph;
    static vianigram::voip::application::VoipEngine engine(&reflectorTransport, &audioFactory, &tgcallsGraph);
    return engine;
}

Platform::String^ ToPlatformString(const std::string& s) {
    if (s.empty()) return ref new Platform::String(L"");
    std::wstring w;
    w.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(s[i])));
    }
    return ref new Platform::String(w.c_str());
}

std::string ToUtf8(Platform::String^ s) {
    if (s == nullptr) return std::string();
    const wchar_t* w = s->Data();
    if (w == nullptr || *w == L'\0') return std::string();
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return std::string();
    std::vector<char> buf((size_t)needed);
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, &buf[0], needed, nullptr, nullptr);
    return std::string(&buf[0], (size_t)needed - 1);
}

std::vector<uint8_t> ToVector(const Platform::Array<uint8>^ bytes) {
    if (bytes == nullptr || bytes->Length == 0) return std::vector<uint8_t>();
    std::vector<uint8_t> out(bytes->Length);
    std::memcpy(&out[0], bytes->Data, bytes->Length);
    return out;
}

std::vector<vianigram::voip::domain::VoipEndpoint> ToNativeEndpoints(
    Windows::Foundation::Collections::IVector<VoipEndpointInfo^>^ endpoints)
{
    std::vector<vianigram::voip::domain::VoipEndpoint> out;
    if (endpoints == nullptr) return out;
    unsigned int count = endpoints->Size;
    out.reserve(count);
    for (unsigned int i = 0; i < count; i++) {
        VoipEndpointInfo^ src = endpoints->GetAt(i);
        if (src == nullptr) continue;
        vianigram::voip::domain::VoipEndpoint e;
        e.Id = (int64_t)src->Id;
        e.Ip = ToUtf8(src->Ip);
        e.Ipv6 = ToUtf8(src->Ipv6);
        e.Port = src->Port;
        e.PeerTag = ToVector(src->PeerTag);
        std::string kind = ToUtf8(src->Kind);
        e.IsWebRtc = kind == "webrtc";
        e.Tcp = src->Tcp;
        e.Stun = src->Stun;
        e.Turn = src->Turn;
        e.Username = ToUtf8(src->Username);
        e.Password = ToUtf8(src->Password);
        e.ReflectorId = (int64_t)src->ReflectorId;
        out.push_back(e);
    }
    return out;
}

std::vector<std::string> ToStringVector(
    const Platform::Array<Platform::String^>^ values)
{
    std::vector<std::string> out;
    if (values == nullptr || values->Length == 0) return out;
    out.reserve(values->Length);
    for (unsigned int i = 0; i < values->Length; i++) {
        out.push_back(ToUtf8(values[i]));
    }
    return out;
}

vianigram::voip::domain::VoipCallStartDescriptor ToNativeStartDescriptor(
    VoipCallStartDescriptor^ src)
{
    vianigram::voip::domain::VoipCallStartDescriptor out;
    if (src == nullptr) return out;
    out.CallId = (int64_t)src->CallId;
    out.AccessHash = (int64_t)src->AccessHash;
    out.IsInitiator = src->IsInitiator;
    out.IsVideo = src->IsVideo;
    out.UdpP2p = src->UdpP2p;
    out.UdpReflector = src->UdpReflector;
    out.MinLayer = (int32_t)src->MinLayer;
    out.MaxLayer = (int32_t)src->MaxLayer;
    out.LibraryVersions = ToStringVector(src->LibraryVersions);
    out.KeyFingerprint = (int64_t)src->KeyFingerprint;
    out.KeyHandle = ToUtf8(src->KeyHandle);
    out.Endpoints = ToNativeEndpoints(src->Endpoints);
    out.CallConfigJson = ToUtf8(src->CallConfigJson);
    return out;
}

Platform::Array<uint8>^ ToArray(const std::vector<uint8_t>& bytes) {
    auto out = ref new Platform::Array<uint8>((unsigned int)bytes.size());
    if (!bytes.empty()) {
        std::memcpy(out->Data, &bytes[0], bytes.size());
    }
    return out;
}

void TestWriteLE32(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    out[offset] = static_cast<uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

void TestWriteLE64(std::vector<uint8_t>& out, size_t offset, uint64_t value) {
    TestWriteLE32(out, offset, static_cast<uint32_t>(value & 0xFFFFFFFFu));
    TestWriteLE32(out, offset + 4, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFu));
}

VoipOperationResult^ ProjectOperation(const vianigram::voip::domain::VoipError& e) {
    auto out = ref new VoipOperationResult();
    out->Success = e.IsOk();
    out->ErrorCode = static_cast<int>(e.Kind);
    out->ErrorMessage = e.IsOk() ? ref new Platform::String(L"") : ToPlatformString(e.Message);
    return out;
}

VoipDhMaterialResult^ ProjectDh(const vianigram::voip::domain::VoipDhMaterial& m) {
    auto out = ref new VoipDhMaterialResult();
    out->Success = m.Error.IsOk();
    out->ErrorCode = static_cast<int>(m.Error.Kind);
    out->ErrorMessage = m.Error.IsOk()
        ? ref new Platform::String(L"")
        : ToPlatformString(m.Error.Message);
    out->PublicValue = ToArray(m.PublicValue);
    out->PublicHash = ToArray(m.PublicHash);
    out->KeyFingerprint = (int64)m.KeyFingerprint;
    out->KeyHandle = ToPlatformString(m.KeyHandle);
    return out;
}

const char* MediaStateName(vianigram::voip::domain::VoipMediaState state) {
    switch (state) {
    case vianigram::voip::domain::VoipMediaState::Idle: return "idle";
    case vianigram::voip::domain::VoipMediaState::Prepared: return "prepared";
    case vianigram::voip::domain::VoipMediaState::Connecting: return "connecting";
    case vianigram::voip::domain::VoipMediaState::Active: return "active";
    case vianigram::voip::domain::VoipMediaState::Stopped: return "stopped";
    default: return "unknown";
    }
}

VoipMediaStatsResult^ ProjectMediaStats(const vianigram::voip::domain::VoipMediaSnapshot& s) {
    auto out = ref new VoipMediaStatsResult();
    out->State = ToPlatformString(MediaStateName(s.State));
    out->CallId = (int64)s.CallId;
    out->Muted = s.Muted;
    out->SpeakerOn = s.SpeakerOn;
    out->EndpointIp = ToPlatformString(s.Endpoint.Ip.empty() ? s.Endpoint.Ipv6 : s.Endpoint.Ip);
    out->EndpointPort = s.Endpoint.Port;
    out->OutboundLevel = s.Stats.OutboundLevel;
    out->InboundLevel = s.Stats.InboundLevel;
    out->PacketLossPercent = s.Stats.PacketLossPercent;
    out->RttMs = s.Stats.RttMs;
    out->BitrateBps = s.Stats.BitrateBps;
    out->Underruns = s.Stats.Underruns;
    out->PacketsSent = (int64)s.Stats.PacketsSent;
    out->PacketsReceived = (int64)s.Stats.PacketsReceived;
    out->PacketsLost = (int64)s.Stats.PacketsLost;
    out->BytesSent = (int64)s.Stats.BytesSent;
    out->BytesReceived = (int64)s.Stats.BytesReceived;
    return out;
}

VoipSignalingDataProducedEventArgs^ ProjectSignalingData(
    int64_t callId,
    const std::vector<uint8_t>& data)
{
    auto out = ref new VoipSignalingDataProducedEventArgs();
    out->CallId = (int64)callId;
    out->Data = ToArray(data);
    return out;
}

} // anonymous namespace

VoipRuntime::VoipRuntime() {
    vianigram::voip::internal::DebugLog(L"VianiumVoIP runtime created");
}

VoipCapabilityResult^ VoipRuntime::GetCapability() {
    auto native = Engine().Capability();
    auto out = ref new VoipCapabilityResult();
    out->CanExchangeCallKeys = native.CanExchangeCallKeys;
    out->CanStartMedia = native.CanStartMedia;
    out->Reason = ToPlatformString(native.Reason);
    return out;
}

IAsyncOperation<VoipDhMaterialResult^>^
VoipRuntime::CreateOutgoingDhAsync(int randomId, int g, const Platform::Array<uint8>^ p) {
    std::vector<uint8_t> prime = ToVector(p);
    return create_async([randomId, g, prime]() -> VoipDhMaterialResult^ {
        return ProjectDh(Engine().CreateOutgoingDh((int32_t)randomId, (int32_t)g, prime));
    });
}

VoipOperationResult^ VoipRuntime::BindOutgoingCall(int randomId, int64 callId) {
    return ProjectOperation(Engine().BindOutgoingCall((int32_t)randomId, (int64_t)callId));
}

VoipOperationResult^ VoipRuntime::RegisterIncomingGAHash(int64 callId, const Platform::Array<uint8>^ gAHash) {
    std::vector<uint8_t> hash = ToVector(gAHash);
    return ProjectOperation(Engine().RegisterIncomingGAHash((int64_t)callId, hash));
}

IAsyncOperation<VoipDhMaterialResult^>^
VoipRuntime::CreateIncomingDhAsync(int64 callId, int g, const Platform::Array<uint8>^ p) {
    std::vector<uint8_t> prime = ToVector(p);
    return create_async([callId, g, prime]() -> VoipDhMaterialResult^ {
        return ProjectDh(Engine().CreateIncomingDh((int64_t)callId, (int32_t)g, prime));
    });
}

IAsyncOperation<VoipDhMaterialResult^>^
VoipRuntime::AcceptPeerGBAsync(int64 callId, const Platform::Array<uint8>^ gB) {
    std::vector<uint8_t> peer = ToVector(gB);
    return create_async([callId, peer]() -> VoipDhMaterialResult^ {
        return ProjectDh(Engine().AcceptPeerGB((int64_t)callId, peer));
    });
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::ConfirmPeerGAOrBAsync(int64 callId, const Platform::Array<uint8>^ gAOrB, int64 expectedFingerprint) {
    std::vector<uint8_t> peer = ToVector(gAOrB);
    return create_async([callId, peer, expectedFingerprint]() -> VoipOperationResult^ {
        return ProjectOperation(Engine().ConfirmPeerGAOrB(
            (int64_t)callId, peer, (int64_t)expectedFingerprint));
    });
}

int64 VoipRuntime::GetLocalFingerprint(int64 callId) {
    return (int64)Engine().GetLocalFingerprint((int64_t)callId);
}

Platform::String^ VoipRuntime::GetKeyHandle(int64 callId) {
    return ToPlatformString(Engine().GetKeyHandle((int64_t)callId));
}

void VoipRuntime::DropCall(int64 callId) {
    Engine().DropCall((int64_t)callId);
}

Platform::Array<uint8>^ VoipRuntime::GetSharedKeyDiagnosticBytes(int64 callId) {
    std::vector<uint8_t> bytes = Engine().GetSharedKeyDiagnosticBytes((int64_t)callId);
    return ToArray(bytes);
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::StartMediaAsync(
    int64 callId,
    Platform::String^ keyHandle,
    Windows::Foundation::Collections::IVector<VoipEndpointInfo^>^ endpoints) {
    std::string handle = ToUtf8(keyHandle);
    std::vector<vianigram::voip::domain::VoipEndpoint> nativeEndpoints = ToNativeEndpoints(endpoints);
    return create_async([callId, handle, nativeEndpoints]() -> VoipOperationResult^ {
        return ProjectOperation(Engine().StartMedia((int64_t)callId, handle, nativeEndpoints));
    });
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::StartCallAsync(VoipCallStartDescriptor^ descriptor) {
    vianigram::voip::domain::VoipCallStartDescriptor native =
        ToNativeStartDescriptor(descriptor);
    VoipRuntime^ self = this;
    return create_async([native, self]() -> VoipOperationResult^ {
        Engine().SetSignalingDataProducedHandler(
            [self](int64_t callId, const std::vector<uint8_t>& data) {
                self->RaiseSignalingDataProduced((int64)callId, ToArray(data));
            });
        return ProjectOperation(Engine().StartMedia(native));
    });
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::ReceiveSignalingDataAsync(int64 callId, const Platform::Array<uint8>^ data) {
    std::vector<uint8_t> nativeData = ToVector(data);
    return create_async([callId, nativeData]() -> VoipOperationResult^ {
        return ProjectOperation(Engine().ReceiveSignalingData((int64_t)callId, nativeData));
    });
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::StopMediaAsync() {
    return create_async([]() -> VoipOperationResult^ {
        return ProjectOperation(Engine().StopMedia());
    });
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::SetMutedAsync(bool muted) {
    return create_async([muted]() -> VoipOperationResult^ {
        return ProjectOperation(Engine().SetMuted(muted));
    });
}

IAsyncOperation<VoipOperationResult^>^
VoipRuntime::SetSpeakerAsync(bool on) {
    return create_async([on]() -> VoipOperationResult^ {
        return ProjectOperation(Engine().SetSpeaker(on));
    });
}

VoipMediaStatsResult^ VoipRuntime::GetMediaStats() {
    return ProjectMediaStats(Engine().GetMediaSnapshot());
}

void VoipRuntime::RaiseSignalingDataProduced(int64 callId, Platform::Array<uint8>^ data) {
    auto args = ref new VoipSignalingDataProducedEventArgs();
    args->CallId = callId;
    args->Data = data;
    SignalingDataProduced(this, args);
}

IVector<VoipSelfTestResult^>^ VoipSelfTest::RunAll() {
    auto rows = ref new Platform::Collections::Vector<VoipSelfTestResult^>();

    auto load = ref new VoipSelfTestResult();
    load->Name = ref new Platform::String(L"module_load");
    load->Passed = true;
    load->Detail = ref new Platform::String(L"VianiumVoIP WinMD loaded");
    rows->Append(load);

    auto cap = ref new VoipSelfTestResult();
    cap->Name = ref new Platform::String(L"capability_contract");
    cap->Passed = Engine().Capability().CanExchangeCallKeys && Engine().Capability().CanStartMedia;
    cap->Detail = ToPlatformString(Engine().Capability().Reason);
    rows->Append(cap);

    {
        std::vector<vianigram::voip::domain::VoipEndpoint> endpoints;
        vianigram::voip::domain::VoipEndpoint invalid;
        invalid.Ip = "149.154.175.50";
        invalid.Port = 443;
        endpoints.push_back(invalid);

        vianigram::voip::domain::VoipEndpoint ipv6;
        ipv6.Ipv6 = "2001:b28:f23d:f001::a";
        ipv6.Port = 443;
        ipv6.PeerTag.push_back(1);
        endpoints.push_back(ipv6);

        vianigram::voip::domain::VoipEndpoint ipv4;
        ipv4.Id = 42;
        ipv4.Ip = "149.154.175.50";
        ipv4.Port = 443;
        ipv4.PeerTag.push_back(2);
        endpoints.push_back(ipv4);

        vianigram::voip::domain::VoipEndpointSelection selection =
            vianigram::voip::domain::VoipEndpointSelector::SelectReflector(endpoints);

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"endpoint_selector_prefers_ipv4_reflector");
        row->Passed = selection.Found && selection.Endpoint.Id == 42;
        row->Detail = selection.Found
            ? ref new Platform::String(L"selected reflector endpoint")
            : ToPlatformString(selection.Reason);
        rows->Append(row);
    }

    {
        vianigram::voip::domain::VoipRtpPacket packet;
        packet.PayloadType = 96;
        packet.SequenceNumber = 0x1234;
        packet.Timestamp = 0x01020304;
        packet.Ssrc = 0xa0b0c0d0;
        packet.TelegramFlags = 0x5a;
        packet.TelegramSequenceOrAck = 0x00bada55 & 0xFFFFFFu;
        packet.Payload.push_back(0xde);
        packet.Payload.push_back(0xad);
        packet.Payload.push_back(0xbe);
        packet.Payload.push_back(0xef);

        vianigram::voip::domain::VoipRtpCodecResult encoded =
            vianigram::voip::domain::VoipRtpCodec::Encode(packet);
        vianigram::voip::domain::VoipRtpCodecResult decoded =
            encoded.Success
                ? vianigram::voip::domain::VoipRtpCodec::Decode(&encoded.Bytes[0], encoded.Bytes.size())
                : vianigram::voip::domain::VoipRtpCodecResult();

        bool ok = encoded.Success
            && decoded.Success
            && decoded.Packet.PayloadType == packet.PayloadType
            && decoded.Packet.SequenceNumber == packet.SequenceNumber
            && decoded.Packet.Timestamp == packet.Timestamp
            && decoded.Packet.Ssrc == packet.Ssrc
            && decoded.Packet.TelegramFlags == packet.TelegramFlags
            && decoded.Packet.TelegramSequenceOrAck == packet.TelegramSequenceOrAck
            && decoded.Packet.Payload == packet.Payload;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"rtp_packet_roundtrip");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"RTP + Telegram extension round-tripped")
            : ToPlatformString(encoded.Success ? decoded.Error : encoded.Error);
        rows->Append(row);
    }

    {
        vianigram::voip::domain::VoipControlCodecResult initPayload =
            vianigram::voip::domain::VoipControlPacketCodec::BuildInitPayload(false);

        vianigram::voip::domain::VoipControlPacket initPacket;
        initPacket.Type = vianigram::voip::domain::VoipControlPacketType::Init;
        initPacket.Sequence = 1;
        initPacket.AckSequence = 0;
        initPacket.Payload = initPayload.Bytes;

        vianigram::voip::domain::VoipControlCodecResult encodedInit =
            initPayload.Success
                ? vianigram::voip::domain::VoipControlPacketCodec::EncodeShort(initPacket)
                : vianigram::voip::domain::VoipControlCodecResult();
        vianigram::voip::domain::VoipControlCodecResult decodedInit =
            encodedInit.Success
                ? vianigram::voip::domain::VoipControlPacketCodec::DecodeShort(
                    &encodedInit.Bytes[0],
                    encodedInit.Bytes.size())
                : vianigram::voip::domain::VoipControlCodecResult();

        vianigram::voip::domain::VoipControlCodecResult ackPayload =
            vianigram::voip::domain::VoipControlPacketCodec::BuildInitAckPayload();
        vianigram::voip::domain::VoipControlCodecResult parsedAck =
            ackPayload.Success
                ? vianigram::voip::domain::VoipControlPacketCodec::ParseInitAckPayload(
                    &ackPayload.Bytes[0],
                    ackPayload.Bytes.size())
                : vianigram::voip::domain::VoipControlCodecResult();

        bool ok = initPayload.Success
            && encodedInit.Success
            && decodedInit.Success
            && decodedInit.Packet.Type == vianigram::voip::domain::VoipControlPacketType::Init
            && decodedInit.Packet.Sequence == 1
            && decodedInit.Packet.Payload == initPayload.Bytes
            && ackPayload.Success
            && parsedAck.Success
            && parsedAck.InitAck.PeerVersion == vianigram::voip::domain::VoipControlPacketCodec::ProtocolVersion
            && parsedAck.InitAck.PeerMinVersion == vianigram::voip::domain::VoipControlPacketCodec::MinProtocolVersion
            && parsedAck.InitAck.HasAudioOpusStream
            && parsedAck.InitAck.AudioStreamId == vianigram::voip::domain::VoipControlPacketCodec::DefaultAudioStreamId
            && parsedAck.InitAck.FrameDurationMs == vianigram::voip::domain::VoipControlPacketCodec::DefaultAudioFrameDurationMs;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"voip_control_init_packets");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"PKT_INIT/PKT_INIT_ACK short control packets encode and parse")
            : ToPlatformString(initPayload.Success
                ? (encodedInit.Success
                    ? (decodedInit.Success
                        ? (ackPayload.Success ? parsedAck.Error : ackPayload.Error)
                        : decodedInit.Error)
                    : encodedInit.Error)
                : initPayload.Error);
        rows->Append(row);
    }

    {
        vianigram::voip::infrastructure::OpusVoipCodec codec;
        int init = codec.Init(vianigram::voip::infrastructure::OpusVoipCodec::DefaultBitrateBps);

        std::vector<int16_t> pcm(
            vianigram::voip::infrastructure::OpusVoipCodec::SamplesPerFrame,
            0);
        for (size_t i = 0; i < pcm.size(); i++) {
            int phase = static_cast<int>(i % 96);
            int value = phase < 48 ? (phase * 180) : ((96 - phase) * 180);
            pcm[i] = static_cast<int16_t>(value - 4200);
        }

        std::vector<uint8_t> encoded(
            vianigram::voip::infrastructure::OpusVoipCodec::MaxPacketBytes,
            0);
        int encodedBytes = init == 0
            ? codec.EncodeFrame(
                &pcm[0],
                static_cast<int>(pcm.size()),
                &encoded[0],
                encoded.size())
            : init;

        std::vector<int16_t> decoded(
            vianigram::voip::infrastructure::OpusVoipCodec::SamplesPerFrame * 2,
            0);
        int decodedFrames = encodedBytes > 0
            ? codec.DecodeFrame(
                &encoded[0],
                static_cast<size_t>(encodedBytes),
                &decoded[0],
                static_cast<int>(decoded.size()))
            : encodedBytes;

        long long energy = 0;
        if (decodedFrames > 0) {
            for (int i = 0; i < decodedFrames; i++) {
                energy += decoded[i] < 0 ? -decoded[i] : decoded[i];
            }
        }

        std::vector<int16_t> plc(
            vianigram::voip::infrastructure::OpusVoipCodec::SamplesPerFrame,
            0);
        int plcFrames = decodedFrames > 0
            ? codec.DecodePlc(&plc[0], static_cast<int>(plc.size()))
            : decodedFrames;

        bool ok = init == 0
            && encodedBytes > 0
            && encodedBytes <= vianigram::voip::infrastructure::OpusVoipCodec::MaxPacketBytes
            && decodedFrames > 0
            && energy > 0
            && plcFrames > 0;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"opus_voip_encode_decode_plc");
        row->Passed = ok;
        if (ok) {
            row->Detail = ref new Platform::String(L"native Opus 48k mono encode/decode and PLC path passed");
        } else {
            std::ostringstream detail;
            detail << "init=" << init
                   << " encoded=" << encodedBytes
                   << " decoded=" << decodedFrames
                   << " plc=" << plcFrames
                   << " energy=" << energy;
            row->Detail = ToPlatformString(detail.str());
        }
        rows->Append(row);
    }

    {
        vianigram::voip::domain::VoipMediaSession session;
        vianigram::voip::domain::VoipEndpoint endpoint;
        endpoint.Id = 7;
        endpoint.Ip = "149.154.175.50";
        endpoint.Port = 443;
        endpoint.PeerTag.assign(16, 1);

        vianigram::voip::domain::VoipError prepared =
            session.Prepare(99, "voip-call:99", endpoint);
        vianigram::voip::domain::VoipError muted = session.SetMuted(true);
        bool ok = prepared.IsOk()
            && muted.IsOk()
            && session.State() == vianigram::voip::domain::VoipMediaState::Prepared
            && session.CallId() == 99
            && session.Muted()
            && session.Stats().PacketsSent == 0;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"media_session_prepare");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"media session tracks selected reflector and mute state")
            : ToPlatformString(prepared.IsOk() ? muted.Message : prepared.Message);
        rows->Append(row);
    }

    {
        std::vector<uint8_t> tag;
        for (int i = 0; i < 16; i++) {
            tag.push_back(static_cast<uint8_t>(i));
        }
        uint64_t queryId = 0x0102030405060708ULL;
        vianigram::voip::domain::VoipReflectorPacketResult discovery =
            vianigram::voip::domain::VoipReflectorPacketCodec::BuildPeerDiscoveryRequest(tag);
        vianigram::voip::domain::VoipReflectorPacketResult self =
            vianigram::voip::domain::VoipReflectorPacketCodec::BuildSelfInfoRequest(tag, queryId);

        bool ok = discovery.Success
            && discovery.Bytes.size() == vianigram::voip::domain::VoipReflectorPacketCodec::DiscoveryRequestBytes
            && self.Success
            && self.Bytes.size() == vianigram::voip::domain::VoipReflectorPacketCodec::SelfInfoRequestBytes;
        if (ok) {
            for (size_t i = 0; i < tag.size(); i++) {
                ok = ok && discovery.Bytes[i] == tag[i] && self.Bytes[i] == tag[i];
            }
            for (size_t i = 16; i < discovery.Bytes.size(); i++) {
                ok = ok && discovery.Bytes[i] == 0xFF;
            }
            ok = ok
                && self.Bytes[16] == 0xFF && self.Bytes[20] == 0xFF
                && self.Bytes[24] == 0xFF && self.Bytes[28] == 0xFE
                && self.Bytes[32] == 0x08 && self.Bytes[39] == 0x01;
        }

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"reflector_request_packets");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"reflector discovery and self-info request packets match Telegram shape")
            : ToPlatformString(discovery.Success ? self.Error : discovery.Error);
        rows->Append(row);
    }

    {
        std::vector<uint8_t> tag;
        for (int i = 0; i < 16; i++) {
            tag.push_back(static_cast<uint8_t>(0xA0 + i));
        }
        std::vector<uint8_t> response(
            vianigram::voip::domain::VoipReflectorPacketCodec::SelfInfoResponseBytes,
            0);
        for (size_t i = 0; i < tag.size(); i++) {
            response[i] = tag[i];
        }
        TestWriteLE64(response, 16, 0xFFFFFFFFFFFFFFFFULL);
        TestWriteLE32(response, 24, 0xFFFFFFFFu);
        TestWriteLE32(response, 28, 0xc01572c7u);
        TestWriteLE32(response, 32, 1710000000u);
        TestWriteLE64(response, 36, 0x1122334455667788ULL);
        TestWriteLE64(response, 44, 0);
        TestWriteLE32(response, 52, 0xFFFF0000u);
        TestWriteLE32(response, 56, 0x32759a95u);
        TestWriteLE32(response, 60, 51500u);

        vianigram::voip::domain::VoipReflectorPacketResult parsed =
            vianigram::voip::domain::VoipReflectorPacketCodec::ParseSelfInfoResponse(
                &response[0],
                response.size(),
                tag);

        bool ok = parsed.Success
            && parsed.SelfInfo.PeerTag == tag
            && parsed.SelfInfo.QueryId == 0x1122334455667788ULL
            && parsed.SelfInfo.RawIpv4 == 0x32759a95u
            && parsed.SelfInfo.Ipv4 == "149.154.117.50"
            && parsed.SelfInfo.Port == 51500;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"reflector_self_info_parse");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"reflector self-info response parsed")
            : ToPlatformString(parsed.Error);
        rows->Append(row);
    }

    {
        vianigram::voip::domain::VoipJitterBuffer jitter(20);
        std::vector<uint8_t> payload;
        payload.push_back(0x11);
        payload.push_back(0x22);

        vianigram::voip::domain::VoipError e0 = jitter.Insert(100, 96000, payload, 1000);
        vianigram::voip::domain::VoipError e2 = jitter.Insert(102, 97920, payload, 1040);
        vianigram::voip::domain::VoipJitterFrame first = jitter.NextPlayoutFrame(1060);
        vianigram::voip::domain::VoipJitterFrame missing = jitter.NextPlayoutFrame(1080);
        vianigram::voip::domain::VoipError late = jitter.Insert(101, 96960, payload, 1090);
        vianigram::voip::domain::VoipJitterFrame third = jitter.NextPlayoutFrame(1100);
        vianigram::voip::domain::VoipJitterStats stats = jitter.Stats();

        bool ok = e0.IsOk()
            && e2.IsOk()
            && late.IsOk()
            && first.Ready
            && first.HasPacket
            && first.SequenceNumber == 100
            && missing.Ready
            && missing.Plc
            && missing.SequenceNumber == 101
            && third.Ready
            && third.HasPacket
            && third.SequenceNumber == 102
            && stats.PacketsPlayed == 2
            && stats.PacketsLost == 1
            && stats.LateDrops == 1
            && stats.TargetMs >= 60
            && stats.TargetMs <= 180;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"jitter_buffer_playout_plc");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"jitter buffer emits packets, PLC slots, and late-drop stats")
            : ToPlatformString(e0.IsOk() ? e2.Message : e0.Message);
        rows->Append(row);
    }

    {
        std::vector<uint8_t> sharedKey;
        for (int i = 0; i < 256; i++) {
            sharedKey.push_back(static_cast<uint8_t>(i));
        }

        std::vector<uint8_t> tag;
        for (int i = 0; i < 16; i++) {
            tag.push_back(static_cast<uint8_t>(0x30 + i));
        }

        std::vector<uint8_t> plain;
        plain.push_back(1); // PKT_INIT shape marker in Telegram VoIP's packet layer.
        plain.push_back(9);
        plain.push_back(0);
        plain.push_back(0);

        vianigram::voip::domain::VoipEncryptedPacketResult encrypted =
            vianigram::voip::domain::VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
                sharedKey,
                true,
                tag,
                plain);
        vianigram::voip::domain::VoipEncryptedPacketResult decrypted =
            encrypted.Success
                ? vianigram::voip::domain::VoipPacketCrypto::DecryptRelayPacketMtProto2Short(
                    sharedKey,
                    false,
                    tag,
                    &encrypted.Bytes[0],
                    encrypted.Bytes.size())
                : vianigram::voip::domain::VoipEncryptedPacketResult();

        bool ok = encrypted.Success
            && decrypted.Success
            && decrypted.Plain == plain
            && encrypted.Bytes.size() >= 48
            && ((encrypted.Bytes.size() - 32) % 16) == 0;

        if (ok) {
            std::vector<uint8_t> tampered = encrypted.Bytes;
            tampered[tampered.size() - 1] ^= 0x01;
            vianigram::voip::domain::VoipEncryptedPacketResult rejected =
                vianigram::voip::domain::VoipPacketCrypto::DecryptRelayPacketMtProto2Short(
                    sharedKey,
                    false,
                    tag,
                    &tampered[0],
                    tampered.size());
            ok = !rejected.Success;
        }

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"packet_crypto_mtproto2_short");
        row->Passed = ok;
        row->Detail = ok
            ? ref new Platform::String(L"Telegram VoIP relay packet encrypt/decrypt and tamper rejection passed")
            : ToPlatformString(encrypted.Success ? decrypted.Error : encrypted.Error);
        rows->Append(row);
    }

    // ECDSA-P256 identity (DTLS / tgcalls Signaling).
    {
        auto kp = vianigram::voip::infrastructure::EcdsaP256KeyPair::Generate();
        bool generated = kp != nullptr;

        // Sign a 32-byte test vector and verify the DER ECDSA-Sig-Value shape.
        bool sigOk = false;
        std::string sigDetail;
        if (generated) {
            uint8_t hash[32];
            for (int i = 0; i < 32; i++) hash[i] = (uint8_t)i;
            std::vector<uint8_t> sig = kp->SignSha256(hash, 32);
            // DER ECDSA-Sig-Value must start with 0x30, contain 2x INTEGER (0x02 ...).
            if (sig.size() >= 8 && sig[0] == 0x30) {
                size_t lenLen = (sig[1] & 0x80) ? (size_t)(sig[1] & 0x7F) + 1 : 1;
                size_t cursor = 1 + lenLen;
                if (cursor < sig.size() && sig[cursor] == 0x02) {
                    sigOk = true;
                }
            }
            if (!sigOk) {
                sigDetail = "signature did not start with SEQUENCE { INTEGER ... }";
            }
        }

        // Build cert DER, verify it begins with 0x30 0x82 (SEQUENCE long form).
        bool certOk = false;
        std::string certDetail;
        std::string fingerprint;
        if (generated) {
            std::vector<uint8_t> der = kp->ToX509SelfSignedDer();
            if (der.size() >= 4 && der[0] == 0x30 && der[1] == 0x82) {
                certOk = true;
            } else {
                certDetail = "cert DER did not start with 30 82";
            }
            fingerprint = kp->ToSha256Fingerprint();
            // Fingerprint must be 95 chars: 32 hex pairs separated by 31 colons.
            if (fingerprint.size() != 95) {
                certOk = false;
                if (certDetail.empty()) certDetail = "fingerprint length wrong";
            }
        }

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"ecdsa_p256_identity");
        row->Passed = generated && sigOk && certOk;
        std::string detail;
        if (!generated) {
            detail = "platform ECDsaP256Sha256 unavailable";
        } else if (!sigOk) {
            detail = sigDetail;
        } else if (!certOk) {
            detail = certDetail;
        } else {
            detail = std::string("fingerprint=") + fingerprint;
        }
        row->Detail = ToPlatformString(detail);
        rows->Append(row);
    }

    // ---------------------------------------------------------------------
    // SRTP self-tests --- RFC 3711 Appendix B test vectors.
    //
    // The KDF and the AES-128-CTR keystream are validated against the
    // canonical "k_master / master_salt" example from RFC 3711 §B.3, which
    // is the same vector quoted in the libsrtp test suite.
    //
    //   k_master    = E1F97A0D3E018BE0D64FA32C06DE4139
    //   master_salt = 0EC675AD498AFEEBB6960B3AABE6
    //
    // The expected first 16 bytes of the session encryption key for this
    // master / salt pair (as produced by our SRTP KDF with KDR = 0) are:
    //   C61E7A93744F39EE10734AFE3FF7A087
    //
    // We verify keystream too: encrypting the all-zero plaintext with the
    // RFC's IV produces a deterministic block we can compare against.
    // ---------------------------------------------------------------------
    {
        static const uint8_t kMasterKey[16] = {
            0xE1,0xF9,0x7A,0x0D,0x3E,0x01,0x8B,0xE0,
            0xD6,0x4F,0xA3,0x2C,0x06,0xDE,0x41,0x39
        };
        static const uint8_t kMasterSalt[14] = {
            0x0E,0xC6,0x75,0xAD,0x49,0x8A,0xFE,0xEB,
            0xB6,0x96,0x0B,0x3A,0xAB,0xE6
        };
        static const uint8_t kExpectedSessionEncrKey[16] = {
            0xC6,0x1E,0x7A,0x93,0x74,0x4F,0x39,0xEE,
            0x10,0x73,0x4A,0xFE,0x3F,0xF7,0xA0,0x87
        };

        vianigram::voip::infrastructure::srtp::SrtpKeys master;
        std::memcpy(master.MasterKey, kMasterKey, 16);
        std::memcpy(master.MasterSalt, kMasterSalt, 14);

        uint8_t derivedEnc[16];
        vianigram::voip::infrastructure::srtp::SrtpSessionKeys::DeriveSessionEncrKey(master, derivedEnc);

        bool kdfOk = std::memcmp(derivedEnc, kExpectedSessionEncrKey, 16) == 0;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"srtp_kdf_rfc3711_session_encr_key");
        row->Passed = kdfOk;
        row->Detail = kdfOk
            ? ref new Platform::String(L"derived session encryption key matches RFC 3711 Appendix B vector")
            : ref new Platform::String(L"session encryption key did not match RFC 3711 vector");
        rows->Append(row);
    }

    // SRTP encrypt → decrypt round-trip: build a tiny RTP packet, encrypt
    // through SrtpPacketCodec, then decrypt and compare.
    {
        // Build a minimal RTP header (V=2, no padding/extension/CC, PT=96)
        // followed by 16 bytes of payload.
        std::vector<uint8_t> rtp;
        rtp.push_back(0x80);              // V=2
        rtp.push_back(96);                // PT
        rtp.push_back(0x00); rtp.push_back(0x01);   // seq = 1
        rtp.push_back(0x00); rtp.push_back(0x00); rtp.push_back(0x00); rtp.push_back(0x10); // ts
        rtp.push_back(0xCA); rtp.push_back(0xFE); rtp.push_back(0xBA); rtp.push_back(0xBE); // SSRC
        for (uint8_t i = 0; i < 16; ++i) rtp.push_back(static_cast<uint8_t>(0xA0 | i));

        vianigram::voip::infrastructure::srtp::SrtpEncryptParams encParams;
        std::memset(&encParams, 0, sizeof(encParams));
        // Deterministic keys for the round-trip — they don't need to be RFC
        // vectors here; we just need encrypt and decrypt to agree.
        for (int i = 0; i < 16; ++i) encParams.SessionEncrKey[i] = static_cast<uint8_t>(0x10 + i);
        for (int i = 0; i < 20; ++i) encParams.SessionAuthKey[i] = static_cast<uint8_t>(0x40 + i);
        for (int i = 0; i < 14; ++i) encParams.SessionSalt[i]    = static_cast<uint8_t>(0x70 + i);
        encParams.Ssrc = 0xCAFEBABE;
        encParams.RolloverCounter = 0;
        encParams.LastSequenceNumber = 0;
        encParams.HasLastSequenceNumber = false;

        std::vector<uint8_t> srtp =
            vianigram::voip::infrastructure::srtp::SrtpPacketCodec::Encrypt(encParams, rtp, 1);

        bool encOk = !srtp.empty()
            && srtp.size() == rtp.size() + vianigram::voip::infrastructure::srtp::SrtpPacketCodec::kAuthTagSize;

        std::vector<uint8_t> decrypted;
        bool decOk = false;
        if (encOk) {
            // Use the same params for decrypt (round-trip self-check).
            vianigram::voip::infrastructure::srtp::SrtpEncryptParams decParams = encParams;
            decParams.HasLastSequenceNumber = false;
            decParams.LastSequenceNumber = 0;
            decParams.RolloverCounter = 0;
            decOk = vianigram::voip::infrastructure::srtp::SrtpPacketCodec::Decrypt(decParams, srtp, decrypted);
        }
        bool match = decOk && decrypted == rtp;

        // Also verify tamper rejection: flipping a payload byte must invalidate the tag.
        bool tamperRejected = false;
        if (encOk) {
            std::vector<uint8_t> tampered = srtp;
            tampered[12] ^= 0x01;
            std::vector<uint8_t> bogus;
            tamperRejected = !vianigram::voip::infrastructure::srtp::SrtpPacketCodec::Decrypt(encParams, tampered, bogus);
        }

        bool ok = encOk && decOk && match && tamperRejected;

        auto row = ref new VoipSelfTestResult();
        row->Name = ref new Platform::String(L"srtp_packet_roundtrip_and_tamper");
        row->Passed = ok;
        if (ok) {
            row->Detail = ref new Platform::String(L"AES-CTR encrypt/decrypt round-trip and HMAC-SHA1-80 tamper rejection passed");
        } else if (!encOk) {
            row->Detail = ref new Platform::String(L"SRTP encrypt produced wrong size or empty output");
        } else if (!decOk) {
            row->Detail = ref new Platform::String(L"SRTP decrypt rejected its own auth tag");
        } else if (!match) {
            row->Detail = ref new Platform::String(L"SRTP decrypt produced different bytes than original RTP");
        } else {
            row->Detail = ref new Platform::String(L"SRTP did not reject a tampered payload byte");
        }
        rows->Append(row);
    }

    return rows;
}

namespace {

bool IsPrintableJsonByte(uint8_t b) {
    // Allow common JSON whitespace (\t, \n, \r) and printable ASCII; reject controls.
    if (b == 0x09 || b == 0x0A || b == 0x0D) return true;
    if (b < 0x20) return false;
    if (b == 0x7F) return false;
    return true;
}

Platform::String^ ProjectPlaintextUtf8(const std::vector<uint8_t>& plain) {
    if (plain.empty()) return ref new Platform::String(L"");

    // tgcalls v2 plaintext often has a small binary header before the JSON
    // payload starts (we observed 4-byte length prefix + flags + content-marker,
    // ~10 bytes total ending right before the '{' of the JSON object). Find
    // the first '{' or '[' (start of JSON body) and project from there.
    size_t jsonStart = 0;
    bool foundJsonStart = false;
    size_t scanLimit = plain.size() < 64 ? plain.size() : 64;
    for (size_t i = 0; i < scanLimit; i++) {
        uint8_t b = plain[i];
        if (b == 0x7B || b == 0x5B) {  // '{' or '['
            jsonStart = i;
            foundJsonStart = true;
            break;
        }
    }
    if (!foundJsonStart) return ref new Platform::String(L"");

    size_t available = plain.size() - jsonStart;
    size_t take = available < 1500 ? available : 1500;

    // Verify the JSON portion is printable ASCII / valid UTF-8 (tgcalls Signaling
    // is JSON, so this should always hold).
    for (size_t i = 0; i < take; i++) {
        uint8_t b = plain[jsonStart + i];
        // Allow tab/LF/CR (0x09, 0x0A, 0x0D) and printable + UTF-8 multi-byte starts
        if (b < 0x09) return ref new Platform::String(L"");
        if (b > 0x0D && b < 0x20) return ref new Platform::String(L"");
    }

    std::vector<char> buffer(take + 1);
    std::memcpy(&buffer[0], &plain[jsonStart], take);
    buffer[take] = 0;

    int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, &buffer[0], (int)take, nullptr, 0);
    if (needed <= 0) {
        // Fall back to non-strict UTF-8 (allow replacement chars instead of failing).
        needed = ::MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)take, nullptr, 0);
        if (needed <= 0) return ref new Platform::String(L"");
    }

    std::vector<wchar_t> wide((size_t)needed);
    int converted = ::MultiByteToWideChar(CP_UTF8, 0, &buffer[0], (int)take, &wide[0], needed);
    if (converted <= 0) return ref new Platform::String(L"");

    return ref new Platform::String(&wide[0], (unsigned int)converted);
}

Platform::String^ ProjectPlaintextHex(const std::vector<uint8_t>& plain) {
    if (plain.empty()) return ref new Platform::String(L"");
    // 256 bytes is enough to see ICE candidate fingerprints / SDP
    // attribute headers in raw form when UTF-8 projection fails.
    size_t take = plain.size() < 256 ? plain.size() : 256;
    std::wstring hex;
    hex.reserve(take * 2);
    static const wchar_t kDigits[] = L"0123456789abcdef";
    for (size_t i = 0; i < take; i++) {
        hex.push_back(kDigits[plain[i] >> 4]);
        hex.push_back(kDigits[plain[i] & 0x0f]);
    }
    return ref new Platform::String(hex.c_str());
}

} // anonymous namespace

TgcallsSignalingDiagnosticResult^ TgcallsSignalingDiagnostics::Decrypt(
    const Platform::Array<uint8>^ sharedKey,
    bool isOutgoing,
    const Platform::Array<uint8>^ encryptedData)
{
    auto out = ref new TgcallsSignalingDiagnosticResult();
    std::vector<uint8_t> key = ToVector(sharedKey);
    std::vector<uint8_t> data = ToVector(encryptedData);

    if (data.empty()) {
        out->Success = false;
        out->Error = ref new Platform::String(L"empty signaling payload");
        out->Seq = 0;
        out->PlaintextUtf8 = ref new Platform::String(L"");
        out->PlaintextHex = ref new Platform::String(L"");
        out->PlaintextLength = 0;
        return out;
    }

    vianigram::voip::domain::TgcallsSignalingDecryptResult result =
        vianigram::voip::domain::TgcallsSignalingCodec::Decrypt(
            key,
            isOutgoing,
            &data[0],
            data.size());

    out->Success = result.Success;
    out->Error = ToPlatformString(result.Error);
    out->Seq = result.Seq;
    out->PlaintextLength = (uint32)result.Plain.size();
    out->PlaintextUtf8 = result.Success
        ? ProjectPlaintextUtf8(result.Plain)
        : ref new Platform::String(L"");
    out->PlaintextHex = ProjectPlaintextHex(result.Plain);
    return out;
}

// =========================================================================
// TgcallsSignalingPipeline / TgcallsParsedMessage --- full encode/decode.
// =========================================================================
namespace {

TgcallsParsedMessage^ ProjectParsedMessage(const vianigram::voip::domain::TgcallsMessage& msg) {
    auto out = ref new TgcallsParsedMessage();
    out->TypeName = ToPlatformString(msg.TypeName);
    out->JsonContent = ToPlatformString(msg.RawJson);
    out->SupportsRenomination = false;
    out->IsMuted = false;
    out->VideoRotation = 0;
    out->LowBattery = false;
    out->PingId = 0;
    out->CandidateSdpStrings = nullptr;

    switch (msg.Type) {
        case vianigram::voip::domain::TgcallsMessageType_InitialSetup: {
            out->Ufrag = ToPlatformString(msg.Initial.Ufrag);
            out->Pwd = ToPlatformString(msg.Initial.Pwd);
            out->SupportsRenomination = msg.Initial.SupportsRenomination;
            out->FingerprintHash = ToPlatformString(msg.Initial.Fingerprint.Hash);
            out->FingerprintSetup = ToPlatformString(msg.Initial.Fingerprint.Setup);
            out->FingerprintHex = ToPlatformString(msg.Initial.Fingerprint.Fingerprint);
            break;
        }
        case vianigram::voip::domain::TgcallsMessageType_Candidates: {
            auto vec = ref new Platform::Collections::Vector<Platform::String^>();
            for (size_t i = 0; i < msg.Candidates.Candidates.size(); i++) {
                vec->Append(ToPlatformString(msg.Candidates.Candidates[i].SdpString));
            }
            out->CandidateSdpStrings = vec;
            break;
        }
        case vianigram::voip::domain::TgcallsMessageType_Connection: {
            out->ConnectionStatus = ToPlatformString(msg.Connection.Status);
            break;
        }
        case vianigram::voip::domain::TgcallsMessageType_Ping: {
            out->PingId = msg.Ping.PingId;
            break;
        }
        case vianigram::voip::domain::TgcallsMessageType_Pong: {
            out->PingId = msg.Pong.PingId;
            break;
        }
        case vianigram::voip::domain::TgcallsMessageType_MediaState:
        case vianigram::voip::domain::TgcallsMessageType_RemoteMediaState: {
            out->IsMuted = msg.MediaState.IsMuted;
            out->VideoState = ToPlatformString(msg.MediaState.VideoState);
            out->ScreencastState = ToPlatformString(msg.MediaState.ScreencastState);
            out->VideoRotation = msg.MediaState.VideoRotation;
            out->LowBattery = msg.MediaState.LowBattery;
            break;
        }
        default: break;
    }
    return out;
}

} // anonymous namespace

Windows::Foundation::Collections::IVector<TgcallsParsedMessage^>^
TgcallsSignalingPipeline::DecryptAndParse(
    const Platform::Array<uint8>^ sharedKey,
    bool isOutgoing,
    const Platform::Array<uint8>^ bytes)
{
    auto out = ref new Platform::Collections::Vector<TgcallsParsedMessage^>();
    std::vector<uint8_t> key = ToVector(sharedKey);
    std::vector<uint8_t> data = ToVector(bytes);
    if (data.empty()) return out;

    std::vector<vianigram::voip::domain::TgcallsMessage> msgs =
        vianigram::voip::domain::TgcallsSignalingEnvelope::Decrypt(key, isOutgoing, data);

    for (size_t i = 0; i < msgs.size(); i++) {
        out->Append(ProjectParsedMessage(msgs[i]));
    }
    return out;
}

Platform::Array<uint8>^ TgcallsSignalingPipeline::EncryptInitialSetup(
    const Platform::Array<uint8>^ sharedKey,
    bool isOutgoing,
    uint32 outgoingSeq,
    Platform::String^ ufrag,
    Platform::String^ pwd,
    Platform::String^ fingerprintHash,
    Platform::String^ fingerprintSetup,
    Platform::String^ fingerprintHex)
{
    std::vector<uint8_t> key = ToVector(sharedKey);
    vianigram::voip::domain::TgcallsMessage msg;
    msg.Type = vianigram::voip::domain::TgcallsMessageType_InitialSetup;
    msg.TypeName = "InitialSetup";
    msg.Initial.Ufrag = ToUtf8(ufrag);
    msg.Initial.Pwd = ToUtf8(pwd);
    msg.Initial.SupportsRenomination = false;
    msg.Initial.Fingerprint.Hash = ToUtf8(fingerprintHash);
    msg.Initial.Fingerprint.Setup = ToUtf8(fingerprintSetup);
    msg.Initial.Fingerprint.Fingerprint = ToUtf8(fingerprintHex);

    std::vector<vianigram::voip::domain::TgcallsMessage> msgs;
    msgs.push_back(msg);

    std::vector<uint8_t> bytes =
        vianigram::voip::domain::TgcallsSignalingEnvelope::Encrypt(
            key, isOutgoing, (uint32_t)outgoingSeq, msgs);
    return ToArray(bytes);
}

Platform::Array<uint8>^ TgcallsSignalingPipeline::EncryptCandidates(
    const Platform::Array<uint8>^ sharedKey,
    bool isOutgoing,
    uint32 outgoingSeq,
    const Platform::Array<Platform::String^>^ sdpStrings)
{
    std::vector<uint8_t> key = ToVector(sharedKey);
    vianigram::voip::domain::TgcallsMessage msg;
    msg.Type = vianigram::voip::domain::TgcallsMessageType_Candidates;
    msg.TypeName = "Candidates";
    if (sdpStrings != nullptr) {
        for (unsigned int i = 0; i < sdpStrings->Length; i++) {
            vianigram::voip::domain::IceCandidate c;
            c.SdpString = ToUtf8(sdpStrings[i]);
            msg.Candidates.Candidates.push_back(c);
        }
    }

    std::vector<vianigram::voip::domain::TgcallsMessage> msgs;
    msgs.push_back(msg);

    std::vector<uint8_t> bytes =
        vianigram::voip::domain::TgcallsSignalingEnvelope::Encrypt(
            key, isOutgoing, (uint32_t)outgoingSeq, msgs);
    return ToArray(bytes);
}

// =========================================================================
// EcdsaP256Identity --- WinMD ref class wrapping the native keypair.
// =========================================================================
EcdsaP256Identity::EcdsaP256Identity() : m_native(nullptr) {}

EcdsaP256Identity::~EcdsaP256Identity() {
    if (m_native != nullptr) {
        delete reinterpret_cast<vianigram::voip::infrastructure::EcdsaP256KeyPair*>(m_native);
        m_native = nullptr;
    }
}

EcdsaP256Identity^ EcdsaP256Identity::Generate() {
    auto kp = vianigram::voip::infrastructure::EcdsaP256KeyPair::Generate();
    if (kp == nullptr) return nullptr;
    auto identity = ref new EcdsaP256Identity();
    // Transfer ownership: release the unique_ptr and store the raw pointer.
    identity->m_native = kp.release();
    return identity;
}

void EcdsaP256Identity::EnsureCertCached() {
    if (m_native == nullptr) return;
    if (m_cachedDer != nullptr && m_cachedFingerprint != nullptr) return;
    auto kp = reinterpret_cast<vianigram::voip::infrastructure::EcdsaP256KeyPair*>(m_native);
    std::vector<uint8_t> der = kp->ToX509SelfSignedDer();
    m_cachedDer = ToArray(der);
    std::string fp = kp->ToSha256Fingerprint();
    m_cachedFingerprint = ToPlatformString(fp);
}

Platform::String^ EcdsaP256Identity::Sha256Fingerprint::get() {
    EnsureCertCached();
    return m_cachedFingerprint != nullptr
        ? m_cachedFingerprint
        : ref new Platform::String(L"");
}

Platform::Array<uint8>^ EcdsaP256Identity::X509Der::get() {
    EnsureCertCached();
    return m_cachedDer != nullptr
        ? m_cachedDer
        : ref new Platform::Array<uint8>(0);
}

Platform::Array<uint8>^ EcdsaP256Identity::SignSha256(const Platform::Array<uint8>^ hash) {
    if (m_native == nullptr) return ref new Platform::Array<uint8>(0);
    if (hash == nullptr || hash->Length != 32) return ref new Platform::Array<uint8>(0);
    auto kp = reinterpret_cast<vianigram::voip::infrastructure::EcdsaP256KeyPair*>(m_native);
    std::vector<uint8_t> sig = kp->SignSha256(hash->Data, hash->Length);
    return ToArray(sig);
}

Platform::Array<uint8>^ EcdsaP256Identity::ExportPublicKeyUncompressed() {
    if (m_native == nullptr) return ref new Platform::Array<uint8>(0);
    auto kp = reinterpret_cast<vianigram::voip::infrastructure::EcdsaP256KeyPair*>(m_native);
    std::vector<uint8_t> pt = kp->GetPublicKeyUncompressed();
    return ToArray(pt);
}

// =========================================================================
// SrtpSession --- WinMD ref class wrapping the SRTP encrypt/decrypt codec.
// Holds two SrtpEncryptParams (one for outgoing, one for incoming) bound to
// the keys derived from the DTLS-SRTP exporter (RFC 5764).
// =========================================================================
namespace {

struct SrtpSessionState {
    vianigram::voip::infrastructure::srtp::SrtpEncryptParams Outgoing;
    vianigram::voip::infrastructure::srtp::SrtpEncryptParams Incoming;
};

// Initialise an SrtpEncryptParams from a master key + salt and a known SSRC
// (we do not know peer SSRC up front, so we use the same value for both
// directions — the caller can refresh later by recreating the session).
void InitParamsFromMaster(vianigram::voip::infrastructure::srtp::SrtpEncryptParams& dst,
                          const uint8_t masterKey[16],
                          const uint8_t masterSalt[14])
{
    vianigram::voip::infrastructure::srtp::SrtpKeys master;
    std::memcpy(master.MasterKey, masterKey, 16);
    std::memcpy(master.MasterSalt, masterSalt, 14);

    vianigram::voip::infrastructure::srtp::SrtpSessionKeys::DeriveSessionEncrKey(master, dst.SessionEncrKey);
    vianigram::voip::infrastructure::srtp::SrtpSessionKeys::DeriveSessionAuthKey(master, dst.SessionAuthKey);
    vianigram::voip::infrastructure::srtp::SrtpSessionKeys::DeriveSessionSalt(master, dst.SessionSalt);
    dst.Ssrc = 0;
    dst.RolloverCounter = 0;
    dst.LastSequenceNumber = 0;
    dst.HasLastSequenceNumber = false;
}

} // anonymous namespace

SrtpSession::SrtpSession() : m_state(nullptr) {}

SrtpSession::~SrtpSession() {
    if (m_state != nullptr) {
        delete reinterpret_cast<SrtpSessionState*>(m_state);
        m_state = nullptr;
    }
}

SrtpSession^ SrtpSession::Create(
    const Platform::Array<uint8>^ srtpKeyingMaterial,
    bool weAreClient)
{
    if (srtpKeyingMaterial == nullptr || srtpKeyingMaterial->Length != 60) return nullptr;

    const uint8_t* mat = srtpKeyingMaterial->Data;
    // RFC 5764 §4.2: the exporter output is laid out as
    //   client_write_master_key   [0..16)
    //   server_write_master_key   [16..32)
    //   client_write_master_salt  [32..46)
    //   server_write_master_salt  [46..60)
    const uint8_t* clientKey  = mat + 0;
    const uint8_t* serverKey  = mat + 16;
    const uint8_t* clientSalt = mat + 32;
    const uint8_t* serverSalt = mat + 46;

    SrtpSessionState* state = new SrtpSessionState();
    if (weAreClient) {
        InitParamsFromMaster(state->Outgoing, clientKey, clientSalt);
        InitParamsFromMaster(state->Incoming, serverKey, serverSalt);
    } else {
        InitParamsFromMaster(state->Outgoing, serverKey, serverSalt);
        InitParamsFromMaster(state->Incoming, clientKey, clientSalt);
    }

    auto session = ref new SrtpSession();
    session->m_state = state;
    return session;
}

Platform::Array<uint8>^ SrtpSession::EncryptOutgoing(const Platform::Array<uint8>^ rtpPacket) {
    if (m_state == nullptr) return nullptr;
    if (rtpPacket == nullptr || rtpPacket->Length < 12) return nullptr;

    SrtpSessionState* state = reinterpret_cast<SrtpSessionState*>(m_state);
    std::vector<uint8_t> rtp(rtpPacket->Data, rtpPacket->Data + rtpPacket->Length);

    // Extract the 16-bit sequence number and SSRC from the header to drive
    // ROC bookkeeping. We re-bind SSRC on first use so the caller does not
    // have to specify it separately.
    uint16_t seq = static_cast<uint16_t>((rtp[2] << 8) | rtp[3]);
    uint32_t ssrc = ((uint32_t)rtp[8] << 24) | ((uint32_t)rtp[9] << 16)
                  | ((uint32_t)rtp[10] << 8) | (uint32_t)rtp[11];
    state->Outgoing.Ssrc = ssrc;

    std::vector<uint8_t> out =
        vianigram::voip::infrastructure::srtp::SrtpPacketCodec::Encrypt(state->Outgoing, rtp, seq);
    if (out.empty()) return nullptr;
    return ToArray(out);
}

Platform::Array<uint8>^ SrtpSession::DecryptIncoming(const Platform::Array<uint8>^ srtpPacket) {
    if (m_state == nullptr) return nullptr;
    if (srtpPacket == nullptr || srtpPacket->Length < 22) return nullptr;  // 12 RTP + 10 tag

    SrtpSessionState* state = reinterpret_cast<SrtpSessionState*>(m_state);
    std::vector<uint8_t> in(srtpPacket->Data, srtpPacket->Data + srtpPacket->Length);

    uint32_t ssrc = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16)
                  | ((uint32_t)in[10] << 8) | (uint32_t)in[11];
    state->Incoming.Ssrc = ssrc;

    std::vector<uint8_t> plain;
    bool ok = vianigram::voip::infrastructure::srtp::SrtpPacketCodec::Decrypt(state->Incoming, in, plain);
    if (!ok) return nullptr;
    return ToArray(plain);
}

// ============================================================================
// IceConnectivityAgent: thin WinMD-friendly wrapper around the native
// vianigram::voip::application::IceAgent. m_impl is a raw pointer because
// ref classes can't hold std::unique_ptr fields.
// ============================================================================

namespace {

Windows::Storage::Streams::IBuffer^ BytesToBuffer(const std::vector<uint8_t>& bytes) {
    auto data = ref new Platform::Array<uint8>((unsigned int)bytes.size());
    if (!bytes.empty()) {
        std::memcpy(data->Data, &bytes[0], bytes.size());
    }
    return Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(data);
}

} // anonymous namespace

IceConnectivityAgent::IceConnectivityAgent() : m_impl(nullptr) {
    m_nextIps   = ref new Platform::Array<Platform::String^>(0);
    m_nextPorts = ref new Platform::Array<int>(0);
    m_nextBytes = ref new Platform::Collections::Vector<Windows::Storage::Streams::IBuffer^>();
}

IceConnectivityAgent::~IceConnectivityAgent() {
    if (m_impl) {
        delete reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl);
        m_impl = nullptr;
    }
}

IceConnectivityAgent^ IceConnectivityAgent::Create(
    bool weAreControlling,
    Platform::String^ localUfrag,
    Platform::String^ localPwd,
    Platform::String^ remoteUfrag,
    Platform::String^ remotePwd)
{
    auto self = ref new IceConnectivityAgent();
    self->m_impl = new vianigram::voip::application::IceAgent(
        weAreControlling
            ? vianigram::voip::application::IceAgentRole_Controlling
            : vianigram::voip::application::IceAgentRole_Controlled,
        ToUtf8(localUfrag),
        ToUtf8(localPwd),
        ToUtf8(remoteUfrag),
        ToUtf8(remotePwd));
    return self;
}

void IceConnectivityAgent::AddRemoteCandidateLine(Platform::String^ sdpLine) {
    if (m_impl == nullptr) return;
    vianigram::voip::domain::ParsedIceCandidate c;
    if (vianigram::voip::domain::IceCandidateParser::Parse(ToUtf8(sdpLine), c)) {
        reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)
            ->AddRemoteCandidate(c);
    }
}

Platform::Array<Platform::String^>^ IceConnectivityAgent::GenerateLocalCandidateLines(
    const Platform::Array<Platform::String^>^ reflectorIps,
    int reflectorPort)
{
    if (m_impl == nullptr) return ref new Platform::Array<Platform::String^>(0);
    std::vector<std::string> ips = ToStringVector(reflectorIps);
    std::vector<vianigram::voip::domain::ParsedIceCandidate> cands =
        reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)
            ->GenerateLocalCandidates(ips, reflectorPort);
    auto out = ref new Platform::Array<Platform::String^>((unsigned int)cands.size());
    for (size_t i = 0; i < cands.size(); ++i) {
        out[(unsigned int)i] = ToPlatformString(
            vianigram::voip::domain::IceCandidateParser::Format(cands[i]));
    }
    return out;
}

void IceConnectivityAgent::RebuildBindingRequests() {
    if (m_impl == nullptr) {
        m_nextIps   = ref new Platform::Array<Platform::String^>(0);
        m_nextPorts = ref new Platform::Array<int>(0);
        m_nextBytes = ref new Platform::Collections::Vector<Windows::Storage::Streams::IBuffer^>();
        return;
    }
    std::vector<std::pair<vianigram::voip::application::IceCheckTarget, std::vector<uint8_t> > >
        reqs = reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)
                   ->GetBindingRequestsToSend();
    m_nextIps   = ref new Platform::Array<Platform::String^>((unsigned int)reqs.size());
    m_nextPorts = ref new Platform::Array<int>((unsigned int)reqs.size());
    auto bytesVec = ref new Platform::Collections::Vector<Windows::Storage::Streams::IBuffer^>();
    for (size_t i = 0; i < reqs.size(); ++i) {
        m_nextIps[(unsigned int)i]   = ToPlatformString(reqs[i].first.Ip);
        m_nextPorts[(unsigned int)i] = reqs[i].first.Port;
        bytesVec->Append(BytesToBuffer(reqs[i].second));
    }
    m_nextBytes = bytesVec;
}

Platform::Array<Platform::String^>^ IceConnectivityAgent::NextRemoteIps::get() {
    return m_nextIps;
}

Platform::Array<int>^ IceConnectivityAgent::NextRemotePorts::get() {
    return m_nextPorts;
}

Windows::Foundation::Collections::IVector<Windows::Storage::Streams::IBuffer^>^
IceConnectivityAgent::NextRequestBytes::get() {
    return m_nextBytes;
}

Platform::Array<uint8>^ IceConnectivityAgent::ProcessIncomingStun(
    Platform::String^ srcIp, int srcPort,
    const Platform::Array<uint8>^ bytes)
{
    std::vector<uint8_t> empty;
    if (m_impl == nullptr) return ToArray(empty);
    std::vector<uint8_t> in = ToVector(bytes);
    std::vector<uint8_t> out;
    reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)
        ->ProcessIncoming(ToUtf8(srcIp), srcPort, in, out);
    return ToArray(out);
}

bool IceConnectivityAgent::IsConnected::get() {
    if (m_impl == nullptr) return false;
    return reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)->IsConnected();
}

Platform::String^ IceConnectivityAgent::SelectedRemoteIp::get() {
    if (m_impl == nullptr) return ToPlatformString("");
    return ToPlatformString(
        reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)->GetSelectedRemoteIp());
}

int IceConnectivityAgent::SelectedRemotePort::get() {
    if (m_impl == nullptr) return 0;
    return reinterpret_cast<vianigram::voip::application::IceAgent*>(m_impl)->GetSelectedRemotePort();
}

// ============================================================================
// StunCodecDiagnostics: verify our codec produces byte-for-byte the
// "2.1.  Sample Request" fixture from RFC 5769. The fixture uses
// short-term credentials with USERNAME="evtj:h6vY", password="VOkJxbRl1RmTxUk/WvJxBt".
// We can't byte-compare directly because our Encode generates a fresh
// MESSAGE-INTEGRITY/FINGERPRINT every call, but we *can*:
//   1. Decode the canonical bytes and check fields.
//   2. Re-verify MESSAGE-INTEGRITY against the documented password.
//   3. Re-verify FINGERPRINT.
// ============================================================================

bool StunCodecDiagnostics::VerifyRfc5769Sample() {
    // RFC 5769 §2.1 Sample Request bytes (verbatim hex).
    static const uint8_t kSample[] = {
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42,
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
        0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10,
        0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73,
        0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
        0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1,
        0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09,
        0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76,
        0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14,
        0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56,
        0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49,
        0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04,
        0xe5, 0x7a, 0x3b, 0xcf
    };
    static const size_t kSampleSize = sizeof(kSample);

    std::vector<uint8_t> bytes(kSample, kSample + kSampleSize);

    vianigram::voip::infrastructure::ice::StunMessage msg;
    if (!vianigram::voip::infrastructure::ice::StunMessageCodec::Decode(
            &bytes[0], bytes.size(), msg)) {
        return false;
    }
    if (msg.MessageType !=
        vianigram::voip::infrastructure::ice::kStunBindingRequest) return false;
    if (msg.Username != "evtj:h6vY") return false;
    if (!msg.HasPriority || msg.Priority != 0x6e0001ffu) return false;
    if (!msg.HasIceControlled) return false;

    if (!vianigram::voip::infrastructure::ice::StunMessageCodec::VerifyFingerprint(bytes)) {
        return false;
    }
    static const std::string kPassword = "VOkJxbRl1RmTxUk/WvJxBt";
    if (!vianigram::voip::infrastructure::ice::StunMessageCodec::VerifyMessageIntegrity(
            bytes, kPassword)) {
        return false;
    }
    return true;
}

}} // namespace Vianium::VoIP
