// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_signaling_envelope.h"

#include "tgcalls_signaling_codec.h"
#include "tgcalls_signaling_frames.h"

namespace vianigram { namespace voip { namespace domain {

std::vector<uint8_t> TgcallsSignalingEnvelope::Encrypt(
    const std::vector<uint8_t>& sharedKey,
    bool isOutgoing,
    uint32_t outgoingSeq,
    const std::vector<TgcallsMessage>& messages)
{
    if (messages.empty()) return std::vector<uint8_t>();

    std::vector<ChannelFrame> frames;
    frames.reserve(messages.size());

    // First frame uses outerSeq (single+requiresAck). Subsequent frames each
    // get their own monotonic counter, with the standard requires-ack flag.
    bool single = (messages.size() == 1);
    uint32_t outerSeq = outgoingSeq
        | (single ? ChannelFrameCodec::kSeqBitSinglePacket : 0u)
        | ChannelFrameCodec::kSeqBitRequiresAck;

    for (size_t i = 0; i < messages.size(); i++) {
        std::string json = TgcallsSignalingMessages::Serialize(messages[i]);
        ChannelFrame f;
        if (i == 0) {
            f.Seq = outerSeq;
        } else {
            f.Seq = (outgoingSeq + (uint32_t)i) | ChannelFrameCodec::kSeqBitRequiresAck;
        }
        f.ContentTag = ChannelFrameCodec::kContentTagCustom;
        f.Counter = f.Seq & ~(ChannelFrameCodec::kSeqBitSinglePacket | ChannelFrameCodec::kSeqBitRequiresAck);
        f.SingleMessagePacket = (f.Seq & ChannelFrameCodec::kSeqBitSinglePacket) != 0;
        f.RequiresAck = true;
        f.Payload.assign(json.begin(), json.end());
        frames.push_back(f);
    }

    std::vector<uint8_t> body = ChannelFrameCodec::JoinFrames(frames);
    return TgcallsSignalingCodec::Encrypt(sharedKey, isOutgoing, outerSeq, body);
}

std::vector<TgcallsMessage> TgcallsSignalingEnvelope::Decrypt(
    const std::vector<uint8_t>& sharedKey,
    bool isOutgoing,
    const std::vector<uint8_t>& bytes)
{
    std::vector<TgcallsMessage> out;
    if (bytes.empty()) return out;

    TgcallsSignalingDecryptResult dec = TgcallsSignalingCodec::Decrypt(
        sharedKey, isOutgoing, &bytes[0], bytes.size());
    if (!dec.Success) return out;

    std::vector<ChannelFrame> frames = ChannelFrameCodec::SplitFrames(dec.Seq, dec.Plain);
    for (size_t i = 0; i < frames.size(); i++) {
        const ChannelFrame& f = frames[i];
        if (f.ContentTag != ChannelFrameCodec::kContentTagCustom) continue;
        if (f.Payload.empty()) continue;
        std::string json(f.Payload.begin(), f.Payload.end());
        TgcallsMessage msg = TgcallsSignalingMessages::Parse(json);
        out.push_back(msg);
    }
    return out;
}

}}} // namespace vianigram::voip::domain
