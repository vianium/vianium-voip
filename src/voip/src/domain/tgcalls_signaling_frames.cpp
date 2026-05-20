// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_signaling_frames.h"

#include <cstring>

namespace vianigram { namespace voip { namespace domain {

namespace {

uint32_t ReadBE32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         |  (uint32_t)p[3];
}

void WriteBE32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

void FillSeqFlags(ChannelFrame& f) {
    f.SingleMessagePacket = (f.Seq & ChannelFrameCodec::kSeqBitSinglePacket) != 0;
    f.RequiresAck = (f.Seq & ChannelFrameCodec::kSeqBitRequiresAck) != 0;
    f.Counter = f.Seq & ~(ChannelFrameCodec::kSeqBitSinglePacket | ChannelFrameCodec::kSeqBitRequiresAck);
}

} // namespace

std::vector<ChannelFrame> ChannelFrameCodec::SplitFrames(uint32_t outerSeq,
                                                         const std::vector<uint8_t>& body) {
    std::vector<ChannelFrame> out;
    size_t pos = 0;
    const size_t n = body.size();
    uint32_t currentSeq = outerSeq;
    bool first = true;

    while (pos < n) {
        if (!first) {
            if (pos + 4 > n) break;
            currentSeq = ReadBE32(&body[pos]);
            pos += 4;
        }
        first = false;

        if (pos + 1 > n) break;
        uint8_t type = body[pos];
        pos += 1;

        if (type == kContentTagAck) {
            // ACK marker — no length prefix, no payload bytes for this entry.
            // (Upstream consumes only the type byte; the seq it ACKs is the
            // currentSeq we already read.)
            ChannelFrame f;
            f.Seq = currentSeq;
            f.ContentTag = type;
            FillSeqFlags(f);
            out.push_back(f);
            continue;
        }

        if (type == kContentTagEmpty) {
            ChannelFrame f;
            f.Seq = currentSeq;
            f.ContentTag = type;
            FillSeqFlags(f);
            out.push_back(f);
            continue;
        }

        if (type != kContentTagCustom) {
            // Unknown content tag — surface it but stop scanning; we don't
            // know how big the body is.
            ChannelFrame f;
            f.Seq = currentSeq;
            f.ContentTag = type;
            FillSeqFlags(f);
            out.push_back(f);
            break;
        }

        // kCustomId: read the BE uint32 length and copy that many bytes.
        if (pos + 4 > n) break;
        uint32_t len = ReadBE32(&body[pos]);
        pos += 4;
        if (len > 1024 * 1024) break;             // sanity cap (matches upstream)
        if (pos + len > n) break;                  // truncated

        ChannelFrame f;
        f.Seq = currentSeq;
        f.ContentTag = type;
        FillSeqFlags(f);
        f.Payload.assign(body.begin() + pos, body.begin() + (pos + len));
        out.push_back(f);
        pos += len;
    }

    return out;
}

std::vector<uint8_t> ChannelFrameCodec::JoinFrames(const std::vector<ChannelFrame>& frames) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < frames.size(); i++) {
        const ChannelFrame& f = frames[i];

        // The first frame omits its seq (outer seq is prepended by the
        // envelope layer); subsequent frames carry their own seq.
        if (i != 0) {
            size_t base = out.size();
            out.resize(base + 4);
            WriteBE32(&out[base], f.Seq);
        }

        if (f.ContentTag == kContentTagEmpty || f.ContentTag == kContentTagAck) {
            out.push_back(f.ContentTag);
            continue;
        }

        // Default: kCustomId-shaped frame (type + len32 + payload).
        size_t headerBase = out.size();
        out.resize(headerBase + 1 + 4 + f.Payload.size());
        out[headerBase] = f.ContentTag;
        WriteBE32(&out[headerBase + 1], (uint32_t)f.Payload.size());
        if (!f.Payload.empty()) {
            std::memcpy(&out[headerBase + 1 + 4], &f.Payload[0], f.Payload.size());
        }
    }
    return out;
}

ChannelFrame ChannelFrameCodec::BuildJsonFrame(uint32_t counter, const std::string& jsonPayload) {
    ChannelFrame f;
    f.Counter = counter;
    f.SingleMessagePacket = true;
    f.RequiresAck = true;
    f.Seq = counter | kSeqBitSinglePacket | kSeqBitRequiresAck;
    f.ContentTag = kContentTagCustom;
    f.Payload.assign(jsonPayload.begin(), jsonPayload.end());
    return f;
}

}}} // namespace vianigram::voip::domain
