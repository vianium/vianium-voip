// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "dynamic_tgcalls_media_graph.h"

#include <windows.h>

#include <sstream>
#include <string>

namespace vianigram { namespace voip { namespace infrastructure {

namespace {

struct ScopedLock {
    concurrency::critical_section::scoped_lock Lock;
    explicit ScopedLock(concurrency::critical_section* cs) : Lock(*cs) {}
};

VianiumTgcallsStringSpan StringSpan(const std::string& value) {
    VianiumTgcallsStringSpan span;
    span.Data = value.empty() ? nullptr : value.c_str();
    span.Size = static_cast<uint32_t>(value.size());
    return span;
}

VianiumTgcallsByteSpan ByteSpan(const std::vector<uint8_t>& value) {
    VianiumTgcallsByteSpan span;
    span.Data = value.empty() ? nullptr : &value[0];
    span.Size = static_cast<uint32_t>(value.size());
    return span;
}

std::string LastWin32ErrorMessage(const char* prefix, DWORD code) {
    std::ostringstream s;
    s << prefix << " win32=" << code;
    return s.str();
}

domain::VoipErrorKind MapResultCode(int32_t code) {
    switch (code) {
        case VianiumTgcallsResultUnavailable:
            return domain::VoipErrorKind::Unavailable;
        case VianiumTgcallsResultInvalidArgument:
            return domain::VoipErrorKind::InvalidArgument;
        case VianiumTgcallsResultCryptoUnavailable:
            return domain::VoipErrorKind::CryptoUnavailable;
        case VianiumTgcallsResultTransportFailed:
            return domain::VoipErrorKind::TransportFailed;
        case VianiumTgcallsResultCodecFailed:
            return domain::VoipErrorKind::CodecFailed;
        case VianiumTgcallsResultAudioDeviceFailed:
            return domain::VoipErrorKind::AudioDeviceFailed;
        case VianiumTgcallsResultInternalError:
        default:
            return domain::VoipErrorKind::InternalError;
    }
}

} // anonymous namespace

DynamicTgcallsMediaGraph::DynamicTgcallsMediaGraph()
    : m_module(nullptr),
      m_handle(nullptr),
      m_loadAttempted(false),
      m_activeCallId(0),
      m_getAbiVersion(nullptr),
      m_create(nullptr),
      m_destroy(nullptr),
      m_start(nullptr),
      m_receiveSignalingData(nullptr),
      m_stop(nullptr),
      m_setMuted(nullptr),
      m_setSpeaker(nullptr),
      m_getSnapshot(nullptr) {
}

DynamicTgcallsMediaGraph::~DynamicTgcallsMediaGraph() {
    if (m_handle != nullptr && m_destroy != nullptr) {
        m_destroy(m_handle);
        m_handle = nullptr;
    }
    if (m_module != nullptr) {
        ::FreeLibrary(static_cast<HMODULE>(m_module));
        m_module = nullptr;
    }
}

domain::VoipError DynamicTgcallsMediaGraph::EnsureLoaded() {
    ScopedLock lock(&m_lock);
    if (m_module != nullptr) return domain::VoipError::Ok();
    if (m_loadAttempted) {
        return domain::VoipError::Unavailable(
            "Vianium.Tgcalls.dll is not loaded; package a modern tgcalls/WebRTC backend implementing VianiumTgcalls ABI v1");
    }
    m_loadAttempted = true;

    HMODULE module = ::LoadPackagedLibrary(L"Vianium.Tgcalls.dll", 0);
    if (module == nullptr) {
        std::string message = LastWin32ErrorMessage(
            "Vianium.Tgcalls.dll was not found or could not be loaded; "
            "build and bundle the modern tgcalls/WebRTC backend DLL",
            ::GetLastError());
        return domain::VoipError::Unavailable(message.c_str());
    }

    m_getAbiVersion = reinterpret_cast<VianiumTgcallsGetAbiVersionFn>(
        ::GetProcAddress(module, "VianiumTgcallsGetAbiVersion"));
    m_create = reinterpret_cast<VianiumTgcallsCreateFn>(
        ::GetProcAddress(module, "VianiumTgcallsCreate"));
    m_destroy = reinterpret_cast<VianiumTgcallsDestroyFn>(
        ::GetProcAddress(module, "VianiumTgcallsDestroy"));
    m_start = reinterpret_cast<VianiumTgcallsStartFn>(
        ::GetProcAddress(module, "VianiumTgcallsStart"));
    m_receiveSignalingData = reinterpret_cast<VianiumTgcallsReceiveSignalingDataFn>(
        ::GetProcAddress(module, "VianiumTgcallsReceiveSignalingData"));
    m_stop = reinterpret_cast<VianiumTgcallsStopFn>(
        ::GetProcAddress(module, "VianiumTgcallsStop"));
    m_setMuted = reinterpret_cast<VianiumTgcallsSetMutedFn>(
        ::GetProcAddress(module, "VianiumTgcallsSetMuted"));
    m_setSpeaker = reinterpret_cast<VianiumTgcallsSetSpeakerFn>(
        ::GetProcAddress(module, "VianiumTgcallsSetSpeaker"));
    m_getSnapshot = reinterpret_cast<VianiumTgcallsGetSnapshotFn>(
        ::GetProcAddress(module, "VianiumTgcallsGetSnapshot"));

    if (m_getAbiVersion == nullptr
        || m_create == nullptr
        || m_destroy == nullptr
        || m_start == nullptr
        || m_receiveSignalingData == nullptr
        || m_stop == nullptr) {
        ::FreeLibrary(module);
        return domain::VoipError::Unavailable(
            "Vianium.Tgcalls.dll does not export the required VianiumTgcalls ABI v1 entrypoints");
    }

    int32_t abiVersion = m_getAbiVersion();
    if (abiVersion != VIANIUM_TGCALLS_ABI_VERSION) {
        ::FreeLibrary(module);
        std::ostringstream s;
        s << "Vianium.Tgcalls.dll ABI mismatch; expected "
          << VIANIUM_TGCALLS_ABI_VERSION
          << " got "
          << abiVersion;
        return domain::VoipError::Unavailable(s.str().c_str());
    }

    m_module = module;
    return domain::VoipError::Ok();
}

domain::VoipError DynamicTgcallsMediaGraph::EnsureHandle() {
    domain::VoipError loaded = EnsureLoaded();
    if (!loaded.IsOk()) return loaded;

    ScopedLock lock(&m_lock);
    if (m_handle != nullptr) return domain::VoipError::Ok();

    VianiumTgcallsResult result = {};
    int32_t rc = m_create(&m_handle, &result);
    return ToVoipError(rc, result, "VianiumTgcallsCreate");
}

domain::VoipError DynamicTgcallsMediaGraph::ToVoipError(
    int32_t returnCode,
    const VianiumTgcallsResult& result,
    const char* operation) const
{
    if (returnCode == VianiumTgcallsResultOk && result.Code == VianiumTgcallsResultOk) {
        return domain::VoipError::Ok();
    }

    int32_t code = result.Code == VianiumTgcallsResultOk ? returnCode : result.Code;
    std::ostringstream s;
    s << (operation == nullptr ? "VianiumTgcalls" : operation) << " failed";
    if (result.Message[0] != '\0') {
        s << ": " << result.Message;
    }
    return domain::VoipError::Of(
        MapResultCode(code),
        result.NativeCode == 0 ? returnCode : result.NativeCode,
        s.str().c_str());
}

domain::VoipError DynamicTgcallsMediaGraph::Start(
    const ports::outbound::TgcallsMediaGraphStartContext& context)
{
    domain::VoipError handle = EnsureHandle();
    if (!handle.IsOk()) return handle;

    std::vector<std::string> versions = context.Descriptor.LibraryVersions;
    std::vector<VianiumTgcallsStringSpan> abiVersions;
    abiVersions.reserve(versions.size());
    for (size_t i = 0; i < versions.size(); i++) {
        abiVersions.push_back(StringSpan(versions[i]));
    }

    const std::vector<domain::VoipEndpoint>& endpoints = context.Descriptor.Endpoints;
    std::vector<std::string> ips;
    std::vector<std::string> ipv6s;
    std::vector<std::string> usernames;
    std::vector<std::string> passwords;
    ips.reserve(endpoints.size());
    ipv6s.reserve(endpoints.size());
    usernames.reserve(endpoints.size());
    passwords.reserve(endpoints.size());

    std::vector<VianiumTgcallsEndpoint> abiEndpoints;
    abiEndpoints.reserve(endpoints.size());
    for (size_t i = 0; i < endpoints.size(); i++) {
        ips.push_back(endpoints[i].Ip);
        ipv6s.push_back(endpoints[i].Ipv6);
        usernames.push_back(endpoints[i].Username);
        passwords.push_back(endpoints[i].Password);

        VianiumTgcallsEndpoint endpoint = {};
        endpoint.Id = endpoints[i].Id;
        endpoint.Ip = StringSpan(ips.back());
        endpoint.Ipv6 = StringSpan(ipv6s.back());
        endpoint.Port = endpoints[i].Port;
        endpoint.PeerTag = ByteSpan(endpoints[i].PeerTag);
        endpoint.IsWebRtc = endpoints[i].IsWebRtc ? 1 : 0;
        endpoint.Tcp = endpoints[i].Tcp ? 1 : 0;
        endpoint.Stun = endpoints[i].Stun ? 1 : 0;
        endpoint.Turn = endpoints[i].Turn ? 1 : 0;
        endpoint.Username = StringSpan(usernames.back());
        endpoint.Password = StringSpan(passwords.back());
        endpoint.ReflectorId = endpoints[i].ReflectorId;
        abiEndpoints.push_back(endpoint);
    }

    VianiumTgcallsStartDescriptor descriptor = {};
    descriptor.AbiVersion = VIANIUM_TGCALLS_ABI_VERSION;
    descriptor.CallId = context.Descriptor.CallId;
    descriptor.AccessHash = context.Descriptor.AccessHash;
    descriptor.IsInitiator = context.Descriptor.IsInitiator ? 1 : 0;
    descriptor.IsVideo = context.Descriptor.IsVideo ? 1 : 0;
    descriptor.UdpP2p = context.Descriptor.UdpP2p ? 1 : 0;
    descriptor.UdpReflector = context.Descriptor.UdpReflector ? 1 : 0;
    descriptor.MinLayer = context.Descriptor.MinLayer;
    descriptor.MaxLayer = context.Descriptor.MaxLayer;
    descriptor.KeyFingerprint = context.Descriptor.KeyFingerprint;
    descriptor.LibraryVersions = abiVersions.empty() ? nullptr : &abiVersions[0];
    descriptor.LibraryVersionCount = static_cast<uint32_t>(abiVersions.size());
    descriptor.Endpoints = abiEndpoints.empty() ? nullptr : &abiEndpoints[0];
    descriptor.EndpointCount = static_cast<uint32_t>(abiEndpoints.size());
    descriptor.SharedKey = ByteSpan(context.SharedKey);
    descriptor.CallConfigJson = StringSpan(context.Descriptor.CallConfigJson);
    descriptor.SignalingDataProduced = &DynamicTgcallsMediaGraph::OnSignalingDataProduced;
    descriptor.UserData = this;

    {
        ScopedLock lock(&m_lock);
        m_activeCallId = context.Descriptor.CallId;
        m_signalingDataProduced = context.SignalingDataProduced;
    }

    VianiumTgcallsResult result = {};
    int32_t rc = m_start(m_handle, &descriptor, &result);
    domain::VoipError start = ToVoipError(rc, result, "VianiumTgcallsStart");
    if (!start.IsOk()) {
        ScopedLock lock(&m_lock);
        if (m_activeCallId == context.Descriptor.CallId) {
            m_activeCallId = 0;
            m_signalingDataProduced = ports::outbound::TgcallsSignalingDataProducedHandler();
        }
    }
    return start;
}

domain::VoipError DynamicTgcallsMediaGraph::ReceiveSignalingData(
    int64_t callId,
    const std::vector<uint8_t>& data)
{
    domain::VoipError handle = EnsureHandle();
    if (!handle.IsOk()) return handle;

    VianiumTgcallsResult result = {};
    int32_t rc = m_receiveSignalingData(
        m_handle,
        callId,
        data.empty() ? nullptr : &data[0],
        static_cast<uint32_t>(data.size()),
        &result);
    return ToVoipError(rc, result, "VianiumTgcallsReceiveSignalingData");
}

domain::VoipError DynamicTgcallsMediaGraph::Stop(int64_t callId) {
    domain::VoipError loaded = EnsureLoaded();
    if (!loaded.IsOk()) {
        ScopedLock lock(&m_lock);
        if (m_activeCallId == callId) {
            m_activeCallId = 0;
            m_signalingDataProduced = ports::outbound::TgcallsSignalingDataProducedHandler();
        }
        return domain::VoipError::Ok();
    }

    VianiumTgcallsResult result = {};
    int32_t rc = m_handle == nullptr
        ? VianiumTgcallsResultOk
        : m_stop(m_handle, callId, &result);

    {
        ScopedLock lock(&m_lock);
        if (m_activeCallId == callId) {
            m_activeCallId = 0;
            m_signalingDataProduced = ports::outbound::TgcallsSignalingDataProducedHandler();
        }
    }

    return ToVoipError(rc, result, "VianiumTgcallsStop");
}

domain::VoipError DynamicTgcallsMediaGraph::SetMuted(int64_t callId, bool muted) {
    domain::VoipError handle = EnsureHandle();
    if (!handle.IsOk()) return handle;
    if (m_setMuted == nullptr) return domain::VoipError::Ok();

    VianiumTgcallsResult result = {};
    int32_t rc = m_setMuted(m_handle, callId, muted ? 1 : 0, &result);
    return ToVoipError(rc, result, "VianiumTgcallsSetMuted");
}

domain::VoipError DynamicTgcallsMediaGraph::SetSpeaker(int64_t callId, bool on) {
    domain::VoipError handle = EnsureHandle();
    if (!handle.IsOk()) return handle;
    if (m_setSpeaker == nullptr) return domain::VoipError::Ok();

    VianiumTgcallsResult result = {};
    int32_t rc = m_setSpeaker(m_handle, callId, on ? 1 : 0, &result);
    return ToVoipError(rc, result, "VianiumTgcallsSetSpeaker");
}

domain::VoipMediaSnapshot DynamicTgcallsMediaGraph::Snapshot(int64_t callId) const {
    domain::VoipMediaSnapshot snapshot;
    snapshot.CallId = callId;
    snapshot.State = domain::VoipMediaState::Connecting;

    if (m_handle == nullptr || m_getSnapshot == nullptr) return snapshot;

    VianiumTgcallsSnapshot native = {};
    VianiumTgcallsResult result = {};
    int32_t rc = m_getSnapshot(m_handle, callId, &native, &result);
    if (rc != VianiumTgcallsResultOk || result.Code != VianiumTgcallsResultOk) {
        return snapshot;
    }

    snapshot.State = static_cast<domain::VoipMediaState>(native.State);
    snapshot.CallId = native.CallId;
    snapshot.Muted = native.Muted != 0;
    snapshot.SpeakerOn = native.SpeakerOn != 0;
    snapshot.Stats.OutboundLevel = native.Stats.OutboundLevel;
    snapshot.Stats.InboundLevel = native.Stats.InboundLevel;
    snapshot.Stats.PacketLossPercent = native.Stats.PacketLossPercent;
    snapshot.Stats.RttMs = native.Stats.RttMs;
    snapshot.Stats.BitrateBps = native.Stats.BitrateBps;
    snapshot.Stats.Underruns = native.Stats.Underruns;
    snapshot.Stats.PacketsSent = native.Stats.PacketsSent;
    snapshot.Stats.PacketsReceived = native.Stats.PacketsReceived;
    snapshot.Stats.PacketsLost = native.Stats.PacketsLost;
    snapshot.Stats.BytesSent = native.Stats.BytesSent;
    snapshot.Stats.BytesReceived = native.Stats.BytesReceived;
    return snapshot;
}

void __stdcall DynamicTgcallsMediaGraph::OnSignalingDataProduced(
    int64_t callId,
    const uint8_t* data,
    uint32_t size,
    void* userData)
{
    if (userData == nullptr || data == nullptr || size == 0) return;

    DynamicTgcallsMediaGraph* self =
        static_cast<DynamicTgcallsMediaGraph*>(userData);
    ports::outbound::TgcallsSignalingDataProducedHandler handler;
    {
        ScopedLock lock(&self->m_lock);
        if (self->m_activeCallId != callId) return;
        handler = self->m_signalingDataProduced;
    }
    if (!handler) return;

    std::vector<uint8_t> payload(data, data + size);
    handler(callId, payload);
}

}}} // namespace vianigram::voip::infrastructure
