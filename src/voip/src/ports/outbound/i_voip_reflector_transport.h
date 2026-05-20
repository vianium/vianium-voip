// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "../../domain/voip_endpoint.h"
#include "../../domain/voip_reflector_packet.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace ports { namespace outbound {

struct VoipReflectorProbeResult {
    bool Success;
    std::string Error;
    int RttMs;
    domain::VoipReflectorSelfInfo SelfInfo;

    VoipReflectorProbeResult()
        : Success(false),
          RttMs(0) {}

    static VoipReflectorProbeResult Fail(const std::string& error) {
        VoipReflectorProbeResult r;
        r.Success = false;
        r.Error = error;
        return r;
    }

    static VoipReflectorProbeResult Ok(
        const domain::VoipReflectorSelfInfo& selfInfo,
        int rttMs)
    {
        VoipReflectorProbeResult r;
        r.Success = true;
        r.SelfInfo = selfInfo;
        r.RttMs = rttMs;
        return r;
    }
};

struct VoipReflectorDatagramResult {
    bool Success;
    std::string Error;
    int RttMs;
    std::vector<uint8_t> Bytes;

    VoipReflectorDatagramResult()
        : Success(false),
          RttMs(0) {}

    static VoipReflectorDatagramResult Fail(const std::string& error) {
        VoipReflectorDatagramResult r;
        r.Success = false;
        r.Error = error;
        return r;
    }

    static VoipReflectorDatagramResult Ok(const std::vector<uint8_t>& bytes, int rttMs) {
        VoipReflectorDatagramResult r;
        r.Success = true;
        r.Bytes = bytes;
        r.RttMs = rttMs;
        return r;
    }
};

class IVoipReflectorDatagramSession {
public:
    virtual ~IVoipReflectorDatagramSession() {}

    virtual VoipReflectorDatagramResult Open(const domain::VoipEndpoint& endpoint) = 0;
    virtual VoipReflectorDatagramResult Send(const std::vector<uint8_t>& bytes) = 0;
    virtual VoipReflectorDatagramResult Receive(
        const std::vector<uint8_t>& expectedPeerTag,
        int timeoutMs) = 0;
    virtual void Close() = 0;
};

class IVoipReflectorTransport {
public:
    virtual ~IVoipReflectorTransport() {}

    virtual VoipReflectorProbeResult ProbeSelfInfo(
        const domain::VoipEndpoint& endpoint,
        uint64_t queryId,
        int timeoutMs) = 0;

    virtual std::unique_ptr<IVoipReflectorDatagramSession> CreateDatagramSession() = 0;
};

}}}} // namespace vianigram::voip::ports::outbound
