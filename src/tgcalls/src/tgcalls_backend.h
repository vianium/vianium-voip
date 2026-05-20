// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "ports/outbound/tgcalls_native_abi.h"

class TgcallsBackend {
public:
    TgcallsBackend();

    int32_t Start(
        const VianiumTgcallsStartDescriptor* descriptor,
        VianiumTgcallsResult* outResult);

    int32_t ReceiveSignalingData(
        int64_t callId,
        const uint8_t* data,
        uint32_t size,
        VianiumTgcallsResult* outResult);

    int32_t Stop(
        int64_t callId,
        VianiumTgcallsResult* outResult);

    int32_t SetMuted(
        int64_t callId,
        uint8_t muted,
        VianiumTgcallsResult* outResult);

    int32_t SetSpeaker(
        int64_t callId,
        uint8_t on,
        VianiumTgcallsResult* outResult);

    int32_t GetSnapshot(
        int64_t callId,
        VianiumTgcallsSnapshot* outSnapshot,
        VianiumTgcallsResult* outResult);

private:
    int64_t m_activeCallId;
    uint8_t m_muted;
    uint8_t m_speakerOn;
};

void VianiumTgcallsSetResult(
    VianiumTgcallsResult* result,
    int32_t code,
    int32_t nativeCode,
    const char* message);
