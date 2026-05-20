// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <stdint.h>

#define VIANIUM_TGCALLS_ABI_VERSION 1

typedef void* VianiumTgcallsHandle;

enum VianiumTgcallsResultCode {
    VianiumTgcallsResultOk = 0,
    VianiumTgcallsResultUnavailable = 1,
    VianiumTgcallsResultInvalidArgument = 2,
    VianiumTgcallsResultCryptoUnavailable = 3,
    VianiumTgcallsResultTransportFailed = 4,
    VianiumTgcallsResultCodecFailed = 5,
    VianiumTgcallsResultAudioDeviceFailed = 6,
    VianiumTgcallsResultInternalError = 7
};

struct VianiumTgcallsResult {
    int32_t Code;
    int32_t NativeCode;
    char Message[768];
};

struct VianiumTgcallsByteSpan {
    const uint8_t* Data;
    uint32_t Size;
};

struct VianiumTgcallsStringSpan {
    const char* Data;
    uint32_t Size;
};

struct VianiumTgcallsEndpoint {
    int64_t Id;
    VianiumTgcallsStringSpan Ip;
    VianiumTgcallsStringSpan Ipv6;
    int32_t Port;
    VianiumTgcallsByteSpan PeerTag;
    uint8_t IsWebRtc;
    uint8_t Tcp;
    uint8_t Stun;
    uint8_t Turn;
    VianiumTgcallsStringSpan Username;
    VianiumTgcallsStringSpan Password;
    int64_t ReflectorId;
};

struct VianiumTgcallsStats {
    float OutboundLevel;
    float InboundLevel;
    float PacketLossPercent;
    int32_t RttMs;
    int32_t BitrateBps;
    int32_t Underruns;
    uint32_t PacketsSent;
    uint32_t PacketsReceived;
    uint32_t PacketsLost;
    uint32_t BytesSent;
    uint32_t BytesReceived;
};

struct VianiumTgcallsSnapshot {
    int32_t State;
    int64_t CallId;
    uint8_t Muted;
    uint8_t SpeakerOn;
    VianiumTgcallsStats Stats;
};

typedef void (__stdcall *VianiumTgcallsSignalingDataProducedCallback)(
    int64_t callId,
    const uint8_t* data,
    uint32_t size,
    void* userData);

struct VianiumTgcallsStartDescriptor {
    uint32_t AbiVersion;
    int64_t CallId;
    int64_t AccessHash;
    uint8_t IsInitiator;
    uint8_t IsVideo;
    uint8_t UdpP2p;
    uint8_t UdpReflector;
    int32_t MinLayer;
    int32_t MaxLayer;
    int64_t KeyFingerprint;
    const VianiumTgcallsStringSpan* LibraryVersions;
    uint32_t LibraryVersionCount;
    const VianiumTgcallsEndpoint* Endpoints;
    uint32_t EndpointCount;
    VianiumTgcallsByteSpan SharedKey;
    VianiumTgcallsStringSpan CallConfigJson;
    VianiumTgcallsSignalingDataProducedCallback SignalingDataProduced;
    void* UserData;
};

extern "C" {
typedef int32_t (__stdcall *VianiumTgcallsGetAbiVersionFn)();
typedef int32_t (__stdcall *VianiumTgcallsCreateFn)(
    VianiumTgcallsHandle* outHandle,
    VianiumTgcallsResult* outResult);
typedef void (__stdcall *VianiumTgcallsDestroyFn)(
    VianiumTgcallsHandle handle);
typedef int32_t (__stdcall *VianiumTgcallsStartFn)(
    VianiumTgcallsHandle handle,
    const VianiumTgcallsStartDescriptor* descriptor,
    VianiumTgcallsResult* outResult);
typedef int32_t (__stdcall *VianiumTgcallsReceiveSignalingDataFn)(
    VianiumTgcallsHandle handle,
    int64_t callId,
    const uint8_t* data,
    uint32_t size,
    VianiumTgcallsResult* outResult);
typedef int32_t (__stdcall *VianiumTgcallsStopFn)(
    VianiumTgcallsHandle handle,
    int64_t callId,
    VianiumTgcallsResult* outResult);
typedef int32_t (__stdcall *VianiumTgcallsSetMutedFn)(
    VianiumTgcallsHandle handle,
    int64_t callId,
    uint8_t muted,
    VianiumTgcallsResult* outResult);
typedef int32_t (__stdcall *VianiumTgcallsSetSpeakerFn)(
    VianiumTgcallsHandle handle,
    int64_t callId,
    uint8_t on,
    VianiumTgcallsResult* outResult);
typedef int32_t (__stdcall *VianiumTgcallsGetSnapshotFn)(
    VianiumTgcallsHandle handle,
    int64_t callId,
    VianiumTgcallsSnapshot* outSnapshot,
    VianiumTgcallsResult* outResult);
}
