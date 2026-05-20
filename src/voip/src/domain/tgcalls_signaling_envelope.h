// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

// Top-level wrapper around the AES-CTR layer (tgcalls_signaling_codec) and
// the channel-frame + JSON layers (tgcalls_signaling_frames +
// tgcalls_signaling_messages). Use this to go between
// {one or more TgcallsMessage values} and {raw bytes for sendSignalingData}.

#include <cstdint>
#include <vector>

#include "tgcalls_signaling_messages.h"

namespace vianigram { namespace voip { namespace domain {

class TgcallsSignalingEnvelope {
public:
    /// Encrypt a TgcallsMessage list into signaling bytes ready for
    /// phone.sendSignalingData. Returns an empty vector on failure.
    static std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& sharedKey, // 256 bytes
        bool isOutgoing,
        uint32_t outgoingSeq,                  // monotonic per-direction counter
        const std::vector<TgcallsMessage>& messages);

    /// Decrypt + parse signaling bytes from peer. Returns an empty vector if
    /// AES-CTR fails; otherwise returns one TgcallsMessage per channel frame
    /// recovered.
    static std::vector<TgcallsMessage> Decrypt(
        const std::vector<uint8_t>& sharedKey,
        bool isOutgoing,
        const std::vector<uint8_t>& bytes);
};

}}} // namespace vianigram::voip::domain
