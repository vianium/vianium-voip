// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

// Channel-frame codec for tgcalls v2 Signaling.
//
// After the AES-CTR layer (tgcalls_signaling_codec.cpp) decrypts an
// updatePhoneCallSignalingData blob, the resulting plaintext starts with a
// 4-byte big-endian *outer* packet seq. tgcalls_signaling_codec already
// strips that seq for us and returns it separately as `result.Seq`. What
// we get into SplitFrames here is the body that *follows* the outer seq —
// i.e. starting at the first frame's type byte.
//
// Frame layout (matches EncryptedConnection::processRawPacket and
// SerializeRawMessageWithSeq in
// _references/.../tgcalls/EncryptedConnection.cpp):
//
//   first frame in packet (no per-frame seq prefix — uses outer seq):
//       [type:uint8 = 0x7F  (kCustomId == 127)]
//       [length:uint32 BE]
//       [payload bytes]            -- usually JSON for Signaling
//
//   each subsequent frame in the same packet:
//       [seq:uint32 BE]            -- per-frame seq (>=5 remaining bytes)
//       [type:uint8 = 0x7F]
//       [length:uint32 BE]
//       [payload bytes]
//
// Notes on the seq word:
//   * bit 31 (0x80000000) = singleMessagePacket — set on the outer seq when
//     the packet only carries a single frame (no concatenation).
//   * bit 30 (0x40000000) = messageRequiresAck — set when a frame body is
//     ack-required. Most JSON payloads (InitialSetup / Candidates /
//     NegotiateChannels / MediaState) are sent with this bit on.
//   * bits 29..0 = the monotonic per-direction packet counter.
//
// Other type bytes that may appear instead of 0x7F:
//   * 0xFE = kEmptyId (an empty/keep-alive frame, no length, no payload).
//   * 0xFF = kAckId   (per-frame seq is the seq of the previously-sent
//                      outgoing message being acked; no length prefix).
//
// Hex example from a real device capture (post-AES-CTR plaintext, *with*
// the outer seq still attached, as we receive on the wire):
//
//   FE 40 00 01            outer seq = 0xFE400001
//                           = singleMessage|requiresAck|0x3E400001
//   7F                     kCustomId (0x7F = 127)  -- first frame type
//   00 00 00 B0            length = 0xB0 = 176 bytes JSON
//   { ... 176 bytes ... }  payload
//
// (The codec strips the FE 40 00 01 and returns it as Seq, then we Split
// the rest starting at the 7F.)

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct ChannelFrame {
    uint32_t Seq;            // 4-byte big-endian, includes high control bits.
                             // For the first frame this is the *outer* seq
                             // passed in to SplitFrames; for later frames
                             // this is read from the wire.
    uint8_t  ContentTag;     // 0x7F (kCustomId) for JSON Signaling messages
    bool     SingleMessagePacket; // derived from Seq bit 31
    bool     RequiresAck;    // derived from Seq bit 30
    uint32_t Counter;        // Seq with high bits stripped
    std::vector<uint8_t> Payload;

    ChannelFrame() : Seq(0), ContentTag(0), SingleMessagePacket(false), RequiresAck(false), Counter(0) {}
};

class ChannelFrameCodec {
public:
    // Splits a plaintext body into its individual frames. `outerSeq` is the
    // 4-byte big-endian word that prefixed the encrypted packet (already
    // stripped by tgcalls_signaling_codec); it is used as the seq for the
    // first frame. Truncated / malformed input returns the frames recovered
    // up to the failure point.
    static std::vector<ChannelFrame> SplitFrames(uint32_t outerSeq,
                                                 const std::vector<uint8_t>& body);

    // Joins a list of frames back into a wire-format packet body. The first
    // frame's seq is *omitted* (it is the outer seq), every subsequent frame
    // includes its own 4-byte seq prefix. The outer seq must be reapplied by
    // the caller (the envelope layer prepends it before AES-CTR encryption).
    // Returns the body bytes that go *after* the outer seq word.
    static std::vector<uint8_t> JoinFrames(const std::vector<ChannelFrame>& frames);

    // Convenience: build a ChannelFrame for a JSON outgoing payload using
    // kCustomId/0x7F content tag, with the standard "single-msg + requires-ack"
    // bits set on the seq. counter is the per-direction monotonic counter.
    static ChannelFrame BuildJsonFrame(uint32_t counter, const std::string& jsonPayload);

    // Constants exposed for tests and the envelope layer.
    static const uint8_t kContentTagCustom = 0x7F; // kCustomId
    static const uint8_t kContentTagEmpty  = 0xFE; // kEmptyId
    static const uint8_t kContentTagAck    = 0xFF; // kAckId
    static const uint32_t kSeqBitSinglePacket = 0x80000000u;
    static const uint32_t kSeqBitRequiresAck = 0x40000000u;
};

}}} // namespace vianigram::voip::domain
