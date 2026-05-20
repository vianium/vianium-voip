// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_jitter_buffer.h"

#include <cmath>
#include <cstdlib>

namespace vianigram { namespace voip { namespace domain {

namespace {

const int kMinTargetMs = 60;
const int kMaxTargetMs = 180;
const size_t kMaxBufferedPackets = 64;

VoipError Invalid(const char* message) {
    return VoipError::Of(VoipErrorKind::InvalidArgument, 0, message);
}

int ClampInt(int value, int lo, int hi) {
    if (value < lo) return lo;
    if (value > hi) return hi;
    return value;
}

bool SequenceBefore(uint16_t a, uint16_t b) {
    return static_cast<int16_t>(a - b) < 0;
}

} // namespace

VoipJitterBuffer::VoipJitterBuffer(int frameMs)
    : m_frameMs(frameMs <= 0 ? 20 : frameMs) {
    Reset();
}

void VoipJitterBuffer::Reset() {
    m_started = false;
    m_nextSequence = 0;
    m_nextTimestamp = 0;
    m_firstPlayoutMs = 0;
    m_playoutIndex = 0;
    m_lastArrivalMs = -1;
    m_smoothedJitterMs = 0.0;
    m_targetMs = kMinTargetMs;
    m_slots.clear();
    m_stats = VoipJitterStats();
}

VoipError VoipJitterBuffer::Insert(
    uint16_t sequenceNumber,
    uint32_t timestamp,
    const std::vector<uint8_t>& payload,
    int64_t arrivalMonotonicMs)
{
    if (payload.empty()) {
        return Invalid("jitter buffer payload is empty");
    }

    if (m_started && IsLate(sequenceNumber)) {
        m_stats.LateDrops++;
        m_stats.DepthPackets = static_cast<int>(m_slots.size());
        return VoipError::Ok();
    }

    RecalculateTarget(arrivalMonotonicMs);

    Slot slot;
    slot.SequenceNumber = sequenceNumber;
    slot.Timestamp = timestamp;
    slot.Payload = payload;
    m_slots[sequenceNumber] = slot;

    if (!m_started) {
        m_started = true;
        m_nextSequence = sequenceNumber;
        m_nextTimestamp = timestamp;
        m_firstPlayoutMs = arrivalMonotonicMs + m_targetMs;
        m_playoutIndex = 0;
    }

    m_stats.PacketsInserted++;
    TrimOverflow();
    m_stats.TargetMs = m_targetMs;
    m_stats.DepthPackets = static_cast<int>(m_slots.size());
    return VoipError::Ok();
}

VoipJitterFrame VoipJitterBuffer::NextPlayoutFrame(int64_t nowMonotonicMs) {
    VoipJitterFrame frame;
    if (!m_started) {
        return frame;
    }

    int64_t due = m_firstPlayoutMs + (m_playoutIndex * m_frameMs);
    if (nowMonotonicMs < due) {
        return frame;
    }

    frame.Ready = true;
    frame.SequenceNumber = m_nextSequence;
    frame.Timestamp = m_nextTimestamp;

    std::map<uint16_t, Slot>::iterator it = m_slots.find(m_nextSequence);
    if (it != m_slots.end()) {
        frame.HasPacket = true;
        frame.Plc = false;
        frame.Timestamp = it->second.Timestamp;
        frame.Payload = it->second.Payload;
        m_slots.erase(it);
        m_stats.PacketsPlayed++;
    } else {
        frame.HasPacket = false;
        frame.Plc = true;
        m_stats.PacketsLost++;
    }

    m_nextSequence = static_cast<uint16_t>(m_nextSequence + 1);
    m_nextTimestamp += static_cast<uint32_t>(m_frameMs);
    m_playoutIndex++;
    m_stats.TargetMs = m_targetMs;
    m_stats.DepthPackets = static_cast<int>(m_slots.size());
    return frame;
}

int VoipJitterBuffer::CurrentTargetMs() const {
    return m_targetMs;
}

VoipJitterStats VoipJitterBuffer::Stats() const {
    VoipJitterStats copy = m_stats;
    copy.TargetMs = m_targetMs;
    copy.DepthPackets = static_cast<int>(m_slots.size());
    return copy;
}

bool VoipJitterBuffer::IsLate(uint16_t sequenceNumber) const {
    return SequenceBefore(sequenceNumber, m_nextSequence);
}

void VoipJitterBuffer::RecalculateTarget(int64_t arrivalMonotonicMs) {
    if (m_lastArrivalMs >= 0) {
        int64_t delta = arrivalMonotonicMs - m_lastArrivalMs;
        if (delta < 0) delta = 0;
        double jitter = std::fabs(static_cast<double>(delta - m_frameMs));
        if (m_smoothedJitterMs == 0.0) {
            m_smoothedJitterMs = jitter;
        } else {
            m_smoothedJitterMs = (m_smoothedJitterMs * 0.95) + (jitter * 0.05);
        }
        m_targetMs = ClampInt(
            kMinTargetMs + static_cast<int>(m_smoothedJitterMs * 4.0),
            kMinTargetMs,
            kMaxTargetMs);
    }
    m_lastArrivalMs = arrivalMonotonicMs;
}

void VoipJitterBuffer::TrimOverflow() {
    while (m_slots.size() > kMaxBufferedPackets) {
        m_slots.erase(m_slots.begin());
        m_stats.LateDrops++;
    }
}

}}} // namespace vianigram::voip::domain
