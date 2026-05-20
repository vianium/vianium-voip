// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../../domain/voip_capability.h"
#include "../../domain/voip_call_start_descriptor.h"
#include "../../domain/voip_dh_material.h"
#include "../../domain/voip_endpoint.h"
#include "../../domain/voip_error.h"
#include "../../domain/voip_media_session.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace ports { namespace inbound {

class IVoipEngine {
public:
    virtual ~IVoipEngine() {}

    virtual domain::VoipCapability Capability() const = 0;

    virtual domain::VoipDhMaterial CreateOutgoingDh(
        int32_t randomId,
        int32_t g,
        const std::vector<uint8_t>& p) = 0;

    virtual domain::VoipError BindOutgoingCall(int32_t randomId, int64_t callId) = 0;

    virtual domain::VoipError RegisterIncomingGAHash(
        int64_t callId,
        const std::vector<uint8_t>& gAHash) = 0;

    virtual domain::VoipDhMaterial CreateIncomingDh(
        int64_t callId,
        int32_t g,
        const std::vector<uint8_t>& p) = 0;

    virtual domain::VoipDhMaterial AcceptPeerGB(
        int64_t callId,
        const std::vector<uint8_t>& gB) = 0;

    virtual domain::VoipError ConfirmPeerGAOrB(
        int64_t callId,
        const std::vector<uint8_t>& gAOrB,
        int64_t expectedFingerprint) = 0;

    virtual int64_t GetLocalFingerprint(int64_t callId) = 0;
    virtual std::string GetKeyHandle(int64_t callId) = 0;
    virtual void DropCall(int64_t callId) = 0;

    virtual domain::VoipError StartMedia(
        int64_t callId,
        const std::string& keyHandle,
        const std::vector<domain::VoipEndpoint>& endpoints) = 0;

    virtual domain::VoipError StartMedia(
        const domain::VoipCallStartDescriptor& descriptor) = 0;

    virtual domain::VoipError ReceiveSignalingData(
        int64_t callId,
        const std::vector<uint8_t>& data) = 0;

    virtual domain::VoipError StopMedia() = 0;
    virtual domain::VoipError SetMuted(bool muted) = 0;
    virtual domain::VoipError SetSpeaker(bool on) = 0;
    virtual domain::VoipMediaSnapshot GetMediaSnapshot() const = 0;
};

}}}} // namespace vianigram::voip::ports::inbound
