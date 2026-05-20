// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../ports/outbound/i_tgcalls_media_graph.h"
#include "../ports/outbound/tgcalls_native_abi.h"

#include <ppl.h>

namespace vianigram { namespace voip { namespace infrastructure {

class DynamicTgcallsMediaGraph : public ports::outbound::ITgcallsMediaGraph {
public:
    DynamicTgcallsMediaGraph();
    virtual ~DynamicTgcallsMediaGraph();

    virtual domain::VoipError Start(
        const ports::outbound::TgcallsMediaGraphStartContext& context);

    virtual domain::VoipError ReceiveSignalingData(
        int64_t callId,
        const std::vector<uint8_t>& data);

    virtual domain::VoipError Stop(int64_t callId);

    virtual domain::VoipError SetMuted(int64_t callId, bool muted);
    virtual domain::VoipError SetSpeaker(int64_t callId, bool on);

    virtual domain::VoipMediaSnapshot Snapshot(int64_t callId) const;

private:
    void* m_module;
    VianiumTgcallsHandle m_handle;
    bool m_loadAttempted;
    int64_t m_activeCallId;
    ports::outbound::TgcallsSignalingDataProducedHandler m_signalingDataProduced;
    mutable concurrency::critical_section m_lock;

    VianiumTgcallsGetAbiVersionFn m_getAbiVersion;
    VianiumTgcallsCreateFn m_create;
    VianiumTgcallsDestroyFn m_destroy;
    VianiumTgcallsStartFn m_start;
    VianiumTgcallsReceiveSignalingDataFn m_receiveSignalingData;
    VianiumTgcallsStopFn m_stop;
    VianiumTgcallsSetMutedFn m_setMuted;
    VianiumTgcallsSetSpeakerFn m_setSpeaker;
    VianiumTgcallsGetSnapshotFn m_getSnapshot;

    domain::VoipError EnsureLoaded();
    domain::VoipError EnsureHandle();
    domain::VoipError ToVoipError(
        int32_t returnCode,
        const VianiumTgcallsResult& result,
        const char* operation) const;

    static void __stdcall OnSignalingDataProduced(
        int64_t callId,
        const uint8_t* data,
        uint32_t size,
        void* userData);

    DynamicTgcallsMediaGraph(const DynamicTgcallsMediaGraph&);
    DynamicTgcallsMediaGraph& operator=(const DynamicTgcallsMediaGraph&);
};

}}} // namespace vianigram::voip::infrastructure
