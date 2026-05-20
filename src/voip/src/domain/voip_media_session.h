// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "voip_endpoint.h"
#include "voip_error.h"

#include <cstdint>
#include <string>

namespace vianigram { namespace voip { namespace domain {

enum class VoipMediaState : uint8_t {
    Idle = 0,
    Prepared = 1,
    Connecting = 2,
    Active = 3,
    Stopped = 4
};

struct VoipMediaStats {
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

    VoipMediaStats()
        : OutboundLevel(0.0f),
          InboundLevel(0.0f),
          PacketLossPercent(0.0f),
          RttMs(0),
          BitrateBps(0),
          Underruns(0),
          PacketsSent(0),
          PacketsReceived(0),
          PacketsLost(0),
          BytesSent(0),
          BytesReceived(0) {}
};

struct VoipMediaSnapshot {
    VoipMediaState State;
    int64_t CallId;
    VoipEndpoint Endpoint;
    bool Muted;
    bool SpeakerOn;
    VoipMediaStats Stats;

    VoipMediaSnapshot()
        : State(VoipMediaState::Idle),
          CallId(0),
          Muted(false),
          SpeakerOn(false) {}
};

class VoipMediaSession {
public:
    VoipMediaSession();

    VoipError Prepare(
        int64_t callId,
        const std::string& keyHandle,
        const VoipEndpoint& endpoint);

    VoipError MarkConnecting();
    VoipError MarkActive();
    VoipError SetMuted(bool muted);
    VoipError SetSpeaker(bool on);
    void RecordProbeSuccess(uint32_t bytesSent, uint32_t bytesReceived, int rttMs);
    void RecordHandshake(
        uint32_t packetsSent,
        uint32_t packetsReceived,
        uint32_t bytesSent,
        uint32_t bytesReceived,
        int rttMs);
    void Stop();

    VoipMediaState State() const;
    int64_t CallId() const;
    const std::string& KeyHandle() const;
    const VoipEndpoint& Endpoint() const;
    bool Muted() const;
    VoipMediaStats Stats() const;
    VoipMediaSnapshot Snapshot() const;

private:
    VoipMediaState m_state;
    int64_t m_callId;
    std::string m_keyHandle;
    VoipEndpoint m_endpoint;
    bool m_muted;
    bool m_speakerOn;
    VoipMediaStats m_stats;
};

}}} // namespace vianigram::voip::domain
