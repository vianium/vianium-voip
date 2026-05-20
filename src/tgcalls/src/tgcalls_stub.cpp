// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_backend.h"

#include <stdint.h>

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsGetAbiVersion() {
    return VIANIUM_TGCALLS_ABI_VERSION;
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsCreate(
    VianiumTgcallsHandle* outHandle,
    VianiumTgcallsResult* outResult)
{
    if (outHandle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultInvalidArgument, 0, "outHandle is null");
        return VianiumTgcallsResultInvalidArgument;
    }

    TgcallsBackend* backend = new TgcallsBackend();
    *outHandle = backend;
    VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
    return VianiumTgcallsResultOk;
}

extern "C" __declspec(dllexport)
void __stdcall VianiumTgcallsDestroy(VianiumTgcallsHandle handle) {
    delete static_cast<TgcallsBackend*>(handle);
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsStart(
    VianiumTgcallsHandle handle,
    const VianiumTgcallsStartDescriptor* descriptor,
    VianiumTgcallsResult* outResult)
{
    if (handle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultInvalidArgument, 0, "handle is null");
        return VianiumTgcallsResultInvalidArgument;
    }
    return static_cast<TgcallsBackend*>(handle)->Start(descriptor, outResult);
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsReceiveSignalingData(
    VianiumTgcallsHandle handle,
    int64_t callId,
    const uint8_t* data,
    uint32_t size,
    VianiumTgcallsResult* outResult)
{
    if (handle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultInvalidArgument, 0, "handle is null");
        return VianiumTgcallsResultInvalidArgument;
    }
    return static_cast<TgcallsBackend*>(handle)->ReceiveSignalingData(
        callId,
        data,
        size,
        outResult);
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsStop(
    VianiumTgcallsHandle handle,
    int64_t callId,
    VianiumTgcallsResult* outResult)
{
    if (handle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
        return VianiumTgcallsResultOk;
    }
    return static_cast<TgcallsBackend*>(handle)->Stop(callId, outResult);
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsSetMuted(
    VianiumTgcallsHandle handle,
    int64_t callId,
    uint8_t muted,
    VianiumTgcallsResult* outResult)
{
    if (handle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
        return VianiumTgcallsResultOk;
    }
    return static_cast<TgcallsBackend*>(handle)->SetMuted(callId, muted, outResult);
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsSetSpeaker(
    VianiumTgcallsHandle handle,
    int64_t callId,
    uint8_t on,
    VianiumTgcallsResult* outResult)
{
    if (handle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultOk, 0, "");
        return VianiumTgcallsResultOk;
    }
    return static_cast<TgcallsBackend*>(handle)->SetSpeaker(callId, on, outResult);
}

extern "C" __declspec(dllexport)
int32_t __stdcall VianiumTgcallsGetSnapshot(
    VianiumTgcallsHandle handle,
    int64_t callId,
    VianiumTgcallsSnapshot* outSnapshot,
    VianiumTgcallsResult* outResult)
{
    if (handle == nullptr) {
        VianiumTgcallsSetResult(outResult, VianiumTgcallsResultInvalidArgument, 0, "handle is null");
        return VianiumTgcallsResultInvalidArgument;
    }
    return static_cast<TgcallsBackend*>(handle)->GetSnapshot(
        callId,
        outSnapshot,
        outResult);
}
