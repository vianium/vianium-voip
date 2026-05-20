// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

// TL-style schema for the tgcalls v2 JSON signaling messages exchanged
// inside encrypted updatePhoneCallSignalingData blobs. These are the
// per-record message bodies once the kCustomId framing has been removed
// (see tgcalls_signaling_frames.h) and the AES-CTR layer has been
// removed (see tgcalls_signaling_codec.h).
//
// Reference: _references/telegram-android/.../v2/Signaling.h and Signaling.cpp.
// On the wire the messages are JSON objects with an "@type" string discriminator.
//
// We keep the C++03/11-compatible discriminated-union shape (no std::variant /
// no absl::variant) because the v120_wp81 toolset does not ship those
// utilities. Each message-type-specific field lives on TgcallsMessage and is
// only meaningful when Type matches.

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

enum TgcallsMessageType {
    TgcallsMessageType_Unknown = 0,
    TgcallsMessageType_InitialSetup = 1,
    TgcallsMessageType_Candidates = 2,
    TgcallsMessageType_NegotiateChannels = 3,
    TgcallsMessageType_Media = 4,
    TgcallsMessageType_MediaState = 5,
    TgcallsMessageType_Connection = 6,
    TgcallsMessageType_Pong = 7,
    TgcallsMessageType_Ping = 8,
    TgcallsMessageType_EmptyAck = 9,
    TgcallsMessageType_RemoteMediaState = 10
};

struct DtlsFingerprint {
    std::string Hash;          // "sha-256" usually
    std::string Setup;          // "active" / "passive" / "actpass"
    std::string Fingerprint;    // hex with colons "AB:CD:..."
};

struct IceCandidate {
    std::string SdpString;      // full SDP candidate line: "candidate:..."
};

struct InitialSetupMsg {
    std::string Ufrag;
    std::string Pwd;
    bool SupportsRenomination;
    DtlsFingerprint Fingerprint; // first fingerprint only (others are rarely used)

    InitialSetupMsg() : SupportsRenomination(false) {}
};

struct CandidatesMsg {
    std::vector<IceCandidate> Candidates;
};

struct ConnectionMsg {
    std::string Status;         // "connected" / "failed" / etc
};

struct PingMsg {
    uint32_t PingId;
    PingMsg() : PingId(0) {}
};

struct PongMsg {
    uint32_t PingId;
    PongMsg() : PingId(0) {}
};

struct MediaStateMsg {
    bool IsMuted;
    std::string VideoState;     // "active" / "inactive" / "suspended"
    std::string ScreencastState;// "active" / "inactive" / "suspended"
    int VideoRotation;          // 0/90/180/270
    bool LowBattery;

    MediaStateMsg() : IsMuted(false), VideoRotation(0), LowBattery(false) {}
};

// Discriminated union — one field is populated based on Type.
struct TgcallsMessage {
    TgcallsMessageType Type;
    std::string TypeName;       // raw "@type" value as observed (handy for logging)
    InitialSetupMsg Initial;
    CandidatesMsg Candidates;
    ConnectionMsg Connection;
    PingMsg Ping;
    PongMsg Pong;
    MediaStateMsg MediaState;
    std::string RawJson;        // for unknown types (Unknown message logged + stored)

    TgcallsMessage() : Type(TgcallsMessageType_Unknown) {}
};

class TgcallsSignalingMessages {
public:
    // Parse decrypted JSON plaintext (post-msg_key+CTR strip + post-binary-frame skip).
    // Returns parsed message; on error returns Type=Unknown with RawJson preserved.
    static TgcallsMessage Parse(const std::string& json);

    // Serialize a TgcallsMessage to JSON bytes ready to be wrapped in a frame
    // and encrypted.
    static std::string Serialize(const TgcallsMessage& msg);
};

}}} // namespace vianigram::voip::domain
