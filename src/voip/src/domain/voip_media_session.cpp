// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_media_session.h"

namespace vianigram { namespace voip { namespace domain {

namespace {

VoipError Invalid(const char* message) {
    return VoipError::Of(VoipErrorKind::InvalidArgument, 0, message);
}

bool HasAddress(const VoipEndpoint& endpoint) {
    return !endpoint.Ip.empty() || !endpoint.Ipv6.empty();
}

} // namespace

VoipMediaSession::VoipMediaSession()
    : m_state(VoipMediaState::Idle),
      m_callId(0),
      m_muted(false),
      m_speakerOn(false) {
}

VoipError VoipMediaSession::Prepare(
    int64_t callId,
    const std::string& keyHandle,
    const VoipEndpoint& endpoint)
{
    if (callId <= 0) return Invalid("media session callId must be positive");
    if (keyHandle.empty()) return Invalid("media session key handle is missing");
    if (endpoint.Port <= 0 || endpoint.Port > 65535) {
        return Invalid("media session endpoint port is invalid");
    }
    if (!HasAddress(endpoint)) {
        return Invalid("media session endpoint address is missing");
    }
    if (endpoint.PeerTag.empty()) {
        return Invalid("media session reflector peer_tag is missing");
    }
    if (m_state != VoipMediaState::Idle
        && m_state != VoipMediaState::Stopped
        && m_callId != callId) {
        return Invalid("another media session is already prepared");
    }

    m_state = VoipMediaState::Prepared;
    m_callId = callId;
    m_keyHandle = keyHandle;
    m_endpoint = endpoint;
    m_muted = false;
    m_speakerOn = false;
    m_stats = VoipMediaStats();
    return VoipError::Ok();
}

VoipError VoipMediaSession::MarkConnecting() {
    if (m_state != VoipMediaState::Prepared) {
        return Invalid("media session must be prepared before connecting");
    }
    m_state = VoipMediaState::Connecting;
    return VoipError::Ok();
}

VoipError VoipMediaSession::MarkActive() {
    if (m_state != VoipMediaState::Connecting && m_state != VoipMediaState::Prepared) {
        return Invalid("media session must be prepared or connecting before active");
    }
    m_state = VoipMediaState::Active;
    return VoipError::Ok();
}

VoipError VoipMediaSession::SetMuted(bool muted) {
    if (m_state == VoipMediaState::Idle || m_state == VoipMediaState::Stopped) {
        return Invalid("media session is not started");
    }
    m_muted = muted;
    return VoipError::Ok();
}

VoipError VoipMediaSession::SetSpeaker(bool on) {
    if (m_state == VoipMediaState::Idle || m_state == VoipMediaState::Stopped) {
        return Invalid("media session is not started");
    }
    m_speakerOn = on;
    return VoipError::Ok();
}

void VoipMediaSession::RecordProbeSuccess(uint32_t bytesSent, uint32_t bytesReceived, int rttMs) {
    m_stats.PacketsSent += 1;
    m_stats.PacketsReceived += 1;
    m_stats.BytesSent += bytesSent;
    m_stats.BytesReceived += bytesReceived;
    if (rttMs > 0) {
        m_stats.RttMs = rttMs;
    }
    m_stats.PacketLossPercent = 0.0f;
}

void VoipMediaSession::RecordHandshake(
    uint32_t packetsSent,
    uint32_t packetsReceived,
    uint32_t bytesSent,
    uint32_t bytesReceived,
    int rttMs)
{
    m_stats.PacketsSent += packetsSent;
    m_stats.PacketsReceived += packetsReceived;
    m_stats.BytesSent += bytesSent;
    m_stats.BytesReceived += bytesReceived;
    if (rttMs > 0) {
        m_stats.RttMs = rttMs;
    }
    m_stats.PacketLossPercent = 0.0f;
}

void VoipMediaSession::Stop() {
    m_state = VoipMediaState::Stopped;
    m_callId = 0;
    m_keyHandle.clear();
    m_endpoint = VoipEndpoint();
    m_muted = false;
    m_speakerOn = false;
    m_stats = VoipMediaStats();
}

VoipMediaState VoipMediaSession::State() const {
    return m_state;
}

int64_t VoipMediaSession::CallId() const {
    return m_callId;
}

const std::string& VoipMediaSession::KeyHandle() const {
    return m_keyHandle;
}

const VoipEndpoint& VoipMediaSession::Endpoint() const {
    return m_endpoint;
}

bool VoipMediaSession::Muted() const {
    return m_muted;
}

VoipMediaStats VoipMediaSession::Stats() const {
    return m_stats;
}

VoipMediaSnapshot VoipMediaSession::Snapshot() const {
    VoipMediaSnapshot out;
    out.State = m_state;
    out.CallId = m_callId;
    out.Endpoint = m_endpoint;
    out.Muted = m_muted;
    out.SpeakerOn = m_speakerOn;
    out.Stats = m_stats;
    return out;
}

}}} // namespace vianigram::voip::domain
