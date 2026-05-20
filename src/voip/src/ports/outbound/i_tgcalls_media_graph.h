// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../../domain/voip_call_start_descriptor.h"
#include "../../domain/voip_error.h"
#include "../../domain/voip_media_session.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace ports { namespace outbound {

typedef std::function<void(int64_t, const std::vector<uint8_t>&)> TgcallsSignalingDataProducedHandler;

struct TgcallsMediaGraphStartContext {
    domain::VoipCallStartDescriptor Descriptor;
    std::vector<uint8_t> SharedKey;
    TgcallsSignalingDataProducedHandler SignalingDataProduced;
};

class ITgcallsMediaGraph {
public:
    virtual ~ITgcallsMediaGraph() {}

    virtual domain::VoipError Start(const TgcallsMediaGraphStartContext& context) = 0;

    virtual domain::VoipError ReceiveSignalingData(
        int64_t callId,
        const std::vector<uint8_t>& data) = 0;

    virtual domain::VoipError Stop(int64_t callId) = 0;

    virtual domain::VoipError SetMuted(int64_t callId, bool muted) = 0;
    virtual domain::VoipError SetSpeaker(int64_t callId, bool on) = 0;

    virtual domain::VoipMediaSnapshot Snapshot(int64_t callId) const = 0;
};

}}}} // namespace vianigram::voip::ports::outbound
