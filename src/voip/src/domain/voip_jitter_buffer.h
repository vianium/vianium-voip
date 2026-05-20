// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "voip_error.h"

#include <cstdint>
#include <map>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipJitterFrame {
    bool Ready;
    bool HasPacket;
    bool Plc;
    uint16_t SequenceNumber;
    uint32_t Timestamp;
    std::vector<uint8_t> Payload;

    VoipJitterFrame()
        : Ready(false),
          HasPacket(false),
          Plc(false),
          SequenceNumber(0),
          Timestamp(0) {}
};

struct VoipJitterStats {
    uint32_t PacketsInserted;
    uint32_t PacketsPlayed;
    uint32_t PacketsLost;
    uint32_t LateDrops;
    int TargetMs;
    int DepthPackets;

    VoipJitterStats()
        : PacketsInserted(0),
          PacketsPlayed(0),
          PacketsLost(0),
          LateDrops(0),
          TargetMs(60),
          DepthPackets(0) {}
};

class VoipJitterBuffer {
public:
    explicit VoipJitterBuffer(int frameMs = 20);

    void Reset();

    VoipError Insert(
        uint16_t sequenceNumber,
        uint32_t timestamp,
        const std::vector<uint8_t>& payload,
        int64_t arrivalMonotonicMs);

    VoipJitterFrame NextPlayoutFrame(int64_t nowMonotonicMs);

    int CurrentTargetMs() const;
    VoipJitterStats Stats() const;

private:
    struct Slot {
        uint16_t SequenceNumber;
        uint32_t Timestamp;
        std::vector<uint8_t> Payload;

        Slot() : SequenceNumber(0), Timestamp(0) {}
    };

    int m_frameMs;
    bool m_started;
    uint16_t m_nextSequence;
    uint32_t m_nextTimestamp;
    int64_t m_firstPlayoutMs;
    int64_t m_playoutIndex;
    int64_t m_lastArrivalMs;
    double m_smoothedJitterMs;
    int m_targetMs;
    std::map<uint16_t, Slot> m_slots;
    VoipJitterStats m_stats;

    bool IsLate(uint16_t sequenceNumber) const;
    void RecalculateTarget(int64_t arrivalMonotonicMs);
    void TrimOverflow();
};

}}} // namespace vianigram::voip::domain
