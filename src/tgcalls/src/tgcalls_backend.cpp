// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_backend.h"

#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include <sstream>
#include <string>

namespace {

// Layer 92 (tgvoip 2.4.4) is the classic UDP+Opus profile that VianiumVoIP's
// VoipEngine fully implements via DatagramSocketReflectorTransport,
// WinrtVoipAudioRuntimeFactory and OpusVoipCodec on the in-process side.
// When the negotiated descriptor advertises *any* other library (3.0+ /
// "modern tgcalls"), VianiumVoIP routes media start through the
// ITgcallsMediaGraph outbound port, which loads this DLL and calls into
// TgcallsBackend::Start via the C ABI.
//
// The placeholder DLL therefore receives a fully-resolved
// VianiumTgcallsStartDescriptor (CallId, SharedKey, ordered Endpoints,
// AccessHash, IsInitiator, layer caps, library versions, signaling
// callback). It does NOT have access to VoipEngine's DH session map and
// it cannot statically link VianiumVoIP because VianiumVoIP already has
// a build-order ProjectReference pointing here (Vianium.Tgcalls.vcxproj
// must finish before VianiumVoIP.vcxproj starts) - adding the reverse
// link would form a project cycle MSBuild rejects.
//
// Until a non-cyclic media path lands (either a static "voip-media-core"
// lib both DLLs link, or a VoipEngine entrypoint that accepts a
// pre-shared key without DH), this Start() must surface the descriptor
// it received so the upstream device log lines from VianiumVoIP's
// DynamicTgcallsMediaGraph::ToVoipError carry actionable context instead
// of a generic placeholder string.

const char* const kPlaceholderBackendMessage =
    "Vianium.Tgcalls.dll loaded and ABI v1 matched, but TgcallsBackend::Start "
    "cannot bring up media without a non-cyclic link path to VianiumVoIP's "
    "VoipEngine::StartMedia (layer 92 reflector pipeline already implemented "
    "in Core\\VianiumVoIP\\src\\application\\voip_engine.cpp). Next step: "
    "extract VianiumVoIP domain+infrastructure into a static lib both "
    "Vianium.Tgcalls.dll and VianiumVoIP.dll can link, or expose a "
    "VoipEngine entrypoint that accepts the pre-shared key from the "
    "VianiumTgcallsStartDescriptor without redoing DH";

void TraceA(const char* line) {
    if (line == nullptr) return;
    ::OutputDebugStringA(line);
}

void Trace(const std::string& line) {
    TraceA(line.c_str());
}

std::string FormatTimestampPrefix() {
    SYSTEMTIME local;
    ::GetLocalTime(&local);
    char buf[24];
    int n = ::sprintf_s(
        buf,
        sizeof(buf),
        "[%02u:%02u:%02u.%03u Tgcalls.Backend] ",
        local.wHour,
        local.wMinute,
        local.wSecond,
        local.wMilliseconds);
    if (n <= 0) return std::string("[Tgcalls.Backend] ");
    return std::string(buf);
}

void Step(const char* message) {
    if (message == nullptr) return;
    std::string line = FormatTimestampPrefix();
    line += message;
    line += '\n';
    Trace(line);
}

void StepStream(std::ostringstream& body) {
    std::string line = FormatTimestampPrefix();
    line += body.str();
    line += '\n';
    Trace(line);
}

std::string ToString(const VianiumTgcallsStringSpan& span) {
    if (span.Data == nullptr || span.Size == 0) return std::string();
    return std::string(span.Data, span.Data + span.Size);
}

std::string SummarizeLibraries(
    const VianiumTgcallsStringSpan* versions,
    uint32_t count)
{
    if (versions == nullptr || count == 0) return std::string("<empty>");
    std::ostringstream s;
    for (uint32_t i = 0; i < count; i++) {
        if (i > 0) s << ",";
        s << ToString(versions[i]);
    }
    return s.str();
}

bool LooksLikeLayer92(
    const VianiumTgcallsStringSpan* versions,
    uint32_t count)
{
    if (versions == nullptr || count == 0) return true;
    if (count != 1) return false;
    std::string only = ToString(versions[0]);
    return only == "2.4.4";
}

uint32_t CountReflectorEndpoints(
    const VianiumTgcallsEndpoint* endpoints,
    uint32_t count)
{
    if (endpoints == nullptr || count == 0) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (endpoints[i].IsWebRtc) continue;
        if (endpoints[i].Tcp) continue;
        if (endpoints[i].Stun || endpoints[i].Turn) continue;
        if (endpoints[i].Port <= 0) continue;
        total++;
    }
    return total;
}

uint32_t CountWebRtcEndpoints(
    const VianiumTgcallsEndpoint* endpoints,
    uint32_t count)
{
    if (endpoints == nullptr || count == 0) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (endpoints[i].IsWebRtc) total++;
    }
    return total;
}

} // anonymous namespace

void VianiumTgcallsSetResult(
    VianiumTgcallsResult* result,
    int32_t code,
    int32_t nativeCode,
    const char* message)
{
    if (result == nullptr) return;
    memset(result, 0, sizeof(VianiumTgcallsResult));
    result->Code = code;
    result->NativeCode = nativeCode;
    if (message == nullptr) return;

    size_t i = 0;
    for (; i + 1 < sizeof(result->Message) && message[i] != '\0'; i++) {
        result->Message[i] = message[i];
    }
    result->Message[i] = '\0';
}

TgcallsBackend::TgcallsBackend()
    : m_activeCallId(0),
      m_muted(0),
      m_speakerOn(0)
{
    Step("ctor backend instance created");
}

int32_t TgcallsBackend::Start(
    const VianiumTgcallsStartDescriptor* descriptor,
    VianiumTgcallsResult* outResult)
{
    Step("Start invoked");

    if (descriptor == nullptr) {
        Step("Start rejected descriptor=null");
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultInvalidArgument,
            0,
            "descriptor is null");
        return VianiumTgcallsResultInvalidArgument;
    }
    if (descriptor->AbiVersion != VIANIUM_TGCALLS_ABI_VERSION) {
        std::ostringstream s;
        s << "Start rejected unsupported ABI version=" << descriptor->AbiVersion
          << " expected=" << VIANIUM_TGCALLS_ABI_VERSION;
        StepStream(s);
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultInvalidArgument,
            0,
            "unsupported VianiumTgcalls ABI version");
        return VianiumTgcallsResultInvalidArgument;
    }
    if (descriptor->CallId <= 0) {
        Step("Start rejected callId<=0");
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultInvalidArgument,
            0,
            "descriptor.CallId must be positive");
        return VianiumTgcallsResultInvalidArgument;
    }
    if (descriptor->SharedKey.Data == nullptr || descriptor->SharedKey.Size != 256) {
        std::ostringstream s;
        s << "Start rejected SharedKey size="
          << (descriptor->SharedKey.Data == nullptr ? 0 : descriptor->SharedKey.Size)
          << " expected=256";
        StepStream(s);
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultCryptoUnavailable,
            0,
            "descriptor.SharedKey must be the 256-byte tgvoip layer 92 auth_key");
        return VianiumTgcallsResultCryptoUnavailable;
    }
    if (descriptor->EndpointCount == 0 || descriptor->Endpoints == nullptr) {
        Step("Start rejected endpoints=empty");
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultTransportFailed,
            0,
            "descriptor.Endpoints is empty - no reflector or webrtc endpoint to dial");
        return VianiumTgcallsResultTransportFailed;
    }

    const uint32_t reflectorCount = CountReflectorEndpoints(
        descriptor->Endpoints,
        descriptor->EndpointCount);
    const uint32_t webrtcCount = CountWebRtcEndpoints(
        descriptor->Endpoints,
        descriptor->EndpointCount);
    const bool isLayer92 = LooksLikeLayer92(
        descriptor->LibraryVersions,
        descriptor->LibraryVersionCount);
    const std::string libs = SummarizeLibraries(
        descriptor->LibraryVersions,
        descriptor->LibraryVersionCount);

    {
        std::ostringstream s;
        s << "Start descriptor"
          << " callId=" << static_cast<long long>(descriptor->CallId)
          << " accessHash=" << static_cast<long long>(descriptor->AccessHash)
          << " initiator=" << static_cast<int>(descriptor->IsInitiator)
          << " video=" << static_cast<int>(descriptor->IsVideo)
          << " udpP2p=" << static_cast<int>(descriptor->UdpP2p)
          << " udpReflector=" << static_cast<int>(descriptor->UdpReflector)
          << " minLayer=" << descriptor->MinLayer
          << " maxLayer=" << descriptor->MaxLayer
          << " keyFp=" << static_cast<long long>(descriptor->KeyFingerprint)
          << " libraries=[" << libs << "]"
          << " endpoints=" << descriptor->EndpointCount
          << " reflector=" << reflectorCount
          << " webrtc=" << webrtcCount
          << " sharedKey=" << descriptor->SharedKey.Size << "B"
          << " callConfig=" << descriptor->CallConfigJson.Size << "B";
        StepStream(s);
    }

    m_activeCallId = descriptor->CallId;

    // The descriptor is internally consistent and matches the layer 92
    // shape VianiumVoIP knows how to drive. The remaining gap is the
    // architectural one described at the top of this file: reaching
    // VoipEngine::StartMedia from inside this DLL without forming a
    // project cycle. Surface a result that captures the negotiation
    // context so the operator can spot whether the descriptor itself is
    // healthy when reading device logs.
    std::ostringstream message;
    message << kPlaceholderBackendMessage
            << "; descriptor: callId=" << static_cast<long long>(descriptor->CallId)
            << " libs=[" << libs << "]"
            << " (layer92=" << (isLayer92 ? "yes" : "no") << ")"
            << " reflector=" << reflectorCount << "/"
            << descriptor->EndpointCount
            << " webrtc=" << webrtcCount
            << " key=" << descriptor->SharedKey.Size << "B"
            << " fp=" << static_cast<long long>(descriptor->KeyFingerprint);

    Step("Start returning Unavailable with descriptor diagnostics");

    VianiumTgcallsSetResult(
        outResult,
        VianiumTgcallsResultUnavailable,
        0,
        message.str().c_str());
    return VianiumTgcallsResultUnavailable;
}

int32_t TgcallsBackend::ReceiveSignalingData(
    int64_t callId,
    const uint8_t* data,
    uint32_t size,
    VianiumTgcallsResult* outResult)
{
    if (callId <= 0 || data == nullptr || size == 0) {
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultInvalidArgument,
            0,
            "invalid signaling packet");
        return VianiumTgcallsResultInvalidArgument;
    }

    {
        std::ostringstream s;
        s << "ReceiveSignalingData callId=" << static_cast<long long>(callId)
          << " size=" << size << "B (no graph; dropping)";
        StepStream(s);
    }

    VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
    return VianiumTgcallsResultOk;
}

int32_t TgcallsBackend::Stop(
    int64_t callId,
    VianiumTgcallsResult* outResult)
{
    {
        std::ostringstream s;
        s << "Stop callId=" << static_cast<long long>(callId)
          << " (active=" << static_cast<long long>(m_activeCallId) << ")";
        StepStream(s);
    }

    if (m_activeCallId == callId) {
        m_activeCallId = 0;
    }

    VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
    return VianiumTgcallsResultOk;
}

int32_t TgcallsBackend::SetMuted(
    int64_t callId,
    uint8_t muted,
    VianiumTgcallsResult* outResult)
{
    (void)callId;
    m_muted = muted ? 1 : 0;

    {
        std::ostringstream s;
        s << "SetMuted callId=" << static_cast<long long>(callId)
          << " muted=" << static_cast<int>(m_muted);
        StepStream(s);
    }

    VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
    return VianiumTgcallsResultOk;
}

int32_t TgcallsBackend::SetSpeaker(
    int64_t callId,
    uint8_t on,
    VianiumTgcallsResult* outResult)
{
    (void)callId;
    m_speakerOn = on ? 1 : 0;

    {
        std::ostringstream s;
        s << "SetSpeaker callId=" << static_cast<long long>(callId)
          << " on=" << static_cast<int>(m_speakerOn);
        StepStream(s);
    }

    VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
    return VianiumTgcallsResultOk;
}

int32_t TgcallsBackend::GetSnapshot(
    int64_t callId,
    VianiumTgcallsSnapshot* outSnapshot,
    VianiumTgcallsResult* outResult)
{
    if (outSnapshot == nullptr) {
        VianiumTgcallsSetResult(
            outResult,
            VianiumTgcallsResultInvalidArgument,
            0,
            "outSnapshot is null");
        return VianiumTgcallsResultInvalidArgument;
    }

    memset(outSnapshot, 0, sizeof(VianiumTgcallsSnapshot));
    // VoipMediaState mapping: Idle=0, Prepared=1, Connecting=2, Active=3, Stopped=4.
    // No real media graph is running; report Stopped when no callId is
    // active and Connecting otherwise so the host UI does not display a
    // misleading "Active" state.
    outSnapshot->State = (m_activeCallId == 0) ? 4 : 2;
    outSnapshot->CallId = callId;
    outSnapshot->Muted = m_muted;
    outSnapshot->SpeakerOn = m_speakerOn;

    VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
    return VianiumTgcallsResultOk;
}
