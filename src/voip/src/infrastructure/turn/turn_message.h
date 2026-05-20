// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
//
// turn_message.h --- minimal RFC 5766 TURN client message codec.
//
// tgcalls 2.x WebRtc reflectors at port 1400 act as TURN servers
// (long-term credential auth, RFC 5389 Section 10.2). To get our STUN
// binding requests to reach the actual peer we need to:
//
//   1. Allocate against the WebRtc reflector with the username/password
//      provided in the phoneConnectionWebrtc TL descriptor.
//   2. CreatePermission for each peer relay candidate we want to send to.
//   3. Wrap every outbound STUN/DTLS/SRTP byte in a Send Indication.
//   4. Strip the inbound Data Indication envelope on every received
//      datagram and deliver the inner DATA bytes to the existing
//      OnReflectorDatagram pipeline (RFC 7983 demux).
//
// Only the attribute set actually emitted/consumed by Telegram's TURN
// servers is supported -- this is not a general-purpose TURN library.
//
// Wire format (RFC 5389 Section 6 + RFC 5766 Section 14):
//
//   header  : type(2) length(2) magic(4) txid(12)        = 20 bytes
//   attr    : type(2) length(2) value(length, padded to 4)
//   length  : count of attribute bytes only (header excluded)
//
// MESSAGE-INTEGRITY computation (RFC 5389 Section 15.4): 20-byte HMAC-SHA1
// over the message up to but not including the M-I attribute, with the
// header's `length` field temporarily set to include the M-I attribute
// itself (4-byte header + 20-byte value). The HMAC key for long-term
// credentials is MD5(username || ":" || realm || ":" || password).
//
// We are C++03/11 (v120_wp81 toolset) -- no exceptions across WinMD ABI,
// no std::optional, no <ranges>. Decode populates a "TurnMessage" plain
// struct; encode helpers return std::vector<uint8_t> ready for the wire.
//

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace turn {

const uint32_t kMagicCookie = 0x2112A442U;
const uint8_t  kFamilyIPv4  = 0x01;
const uint8_t  kFamilyIPv6  = 0x02;

// RFC 5766 method numbers (low 12 bits of message-type after class shift).
const uint16_t kMethodBinding         = 0x001;
const uint16_t kMethodAllocate        = 0x003;
const uint16_t kMethodRefresh         = 0x004;
const uint16_t kMethodSend            = 0x006;
const uint16_t kMethodData            = 0x007;
const uint16_t kMethodCreatePermission = 0x008;

// RFC 5389 Section 6 message classes (encoded into bits 4 and 8 of type).
const uint16_t kClassRequest    = 0x000;
const uint16_t kClassIndication = 0x010;
const uint16_t kClassSuccess    = 0x100;
const uint16_t kClassError      = 0x110;

// Compose the 14-bit STUN message type from a method (12-bit) and class
// (2-bit). Per RFC 5389 Section 6 the class bits live at positions 4 and 8;
// the method bits skip those and use {0..3, 5..7, 9..11}.
inline uint16_t TurnMessageType(uint16_t method, uint16_t cls) {
    uint16_t methodBits =
        static_cast<uint16_t>((method & 0x0F) |
                              ((method & 0x70) << 1) |
                              ((method & 0xF80) << 2));
    uint16_t classBits =
        static_cast<uint16_t>((cls & 0x10) | ((cls & 0x100) << 1));
    return static_cast<uint16_t>(methodBits | classBits);
}

inline uint16_t TurnMethodOf(uint16_t type) {
    return static_cast<uint16_t>(((type & 0x000F)      ) |
                                 ((type & 0x00E0) >> 1) |
                                 ((type & 0x3E00) >> 2));
}

inline uint16_t TurnClassOf(uint16_t type) {
    return static_cast<uint16_t>((type & 0x0010) | ((type & 0x0200) >> 1));
}

// RFC 5389 + 5766 attribute identifiers (only those we encode/decode).
const uint16_t kAttrMappedAddress      = 0x0001;
const uint16_t kAttrUsername           = 0x0006;
const uint16_t kAttrMessageIntegrity   = 0x0008;
const uint16_t kAttrErrorCode          = 0x0009;
const uint16_t kAttrUnknownAttributes  = 0x000A;
const uint16_t kAttrLifetime           = 0x000D;
const uint16_t kAttrXorPeerAddress     = 0x0012;
const uint16_t kAttrData               = 0x0013;
const uint16_t kAttrRealm              = 0x0014;
const uint16_t kAttrNonce              = 0x0015;
const uint16_t kAttrXorRelayedAddress  = 0x0016;
const uint16_t kAttrRequestedTransport = 0x0019;
const uint16_t kAttrDontFragment       = 0x001A;
const uint16_t kAttrXorMappedAddress   = 0x0020;
const uint16_t kAttrSoftware           = 0x8022;
const uint16_t kAttrAlternateServer    = 0x8023;
const uint16_t kAttrFingerprint        = 0x8028;

// Address family carrier used for XOR-MAPPED / XOR-RELAYED / XOR-PEER.
struct TurnAddress {
    uint8_t  Family;          // 0x01 or 0x02
    uint16_t Port;
    std::vector<uint8_t> Address; // 4 or 16 bytes (network byte order)

    TurnAddress() : Family(0), Port(0) {}
};

struct TurnMessage {
    uint16_t Type;            // composite method+class
    uint8_t  TransactionId[12];

    // Decoded attributes (encode helpers also populate these where useful):
    bool          HasUsername;        std::string  Username;
    bool          HasRealm;           std::string  Realm;
    bool          HasNonce;           std::vector<uint8_t> Nonce;
    bool          HasErrorCode;       int          ErrorCode;       std::string ErrorReason;
    bool          HasXorMapped;       TurnAddress  XorMapped;
    bool          HasXorRelayed;      TurnAddress  XorRelayed;
    std::vector<TurnAddress> XorPeers;
    bool          HasData;            std::vector<uint8_t> Data;
    bool          HasLifetime;        uint32_t     Lifetime;
    bool          HasRequestedTransport; uint8_t  Protocol; // 17 = UDP
    bool          HasMessageIntegrity;
    std::vector<uint8_t> MessageIntegrity; // 20 bytes when present.
    // Raw outer for HMAC verification or diagnostics.
    std::vector<uint8_t> Raw;

    TurnMessage();
};

// Encode helpers --- return ready-to-send UDP payload. `key` is the
// 16-byte MD5(username:realm:password) used as HMAC-SHA1 key for
// MESSAGE-INTEGRITY. If key.empty(), MESSAGE-INTEGRITY is omitted (used
// for the unauthenticated initial Allocate that gets a 401 back).
std::vector<uint8_t> EncodeAllocate(
    const uint8_t txnId[12], uint32_t lifetimeSeconds,
    const std::string& username, const std::string& realm,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& key);

std::vector<uint8_t> EncodeCreatePermission(
    const uint8_t txnId[12],
    const std::vector<TurnAddress>& peers,
    const std::string& username, const std::string& realm,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& key);

// Send Indication carries arbitrary inner bytes (DATA attribute). RFC 5766
// Section 11.4: indications are NOT authenticated with MESSAGE-INTEGRITY
// in long-term credential mode, so no `key` argument is needed.
std::vector<uint8_t> EncodeSendIndication(
    const uint8_t txnId[12],
    const TurnAddress& peer,
    const std::vector<uint8_t>& data);

std::vector<uint8_t> EncodeRefresh(
    const uint8_t txnId[12], uint32_t lifetimeSeconds,
    const std::string& username, const std::string& realm,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& key);

// Decode any inbound UDP datagram. Returns false if it's not a valid
// STUN/TURN message (first byte must be 0x00..0x03, magic-cookie match,
// declared length fits within `bytes`).
bool DecodeMessage(const std::vector<uint8_t>& bytes, TurnMessage* out);

// Cheap pre-check: a UDP datagram looks like a STUN/TURN message if its
// first byte is in [0x00,0x03] (i.e. no DTLS / RTP collision possible).
inline bool LooksLikeStunOrTurn(const uint8_t* p, size_t n) {
    return n >= 20 && (p[0] <= 0x03);
}

// Long-term credential key derivation per RFC 5389 Section 15.4:
// MD5(username || ":" || realm || ":" || password). Returns 16 raw bytes.
std::vector<uint8_t> DeriveLongTermKey(const std::string& username,
                                       const std::string& realm,
                                       const std::string& password);

// Address helpers. ParseAddress accepts IPv4 dotted ("a.b.c.d") or
// IPv6 colon notation; we only need IPv4 today but the helper handles
// both cases defensively.
TurnAddress MakeAddressIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, int port);
TurnAddress MakeAddress(const std::string& ip, int port);

// Format a TurnAddress as "a.b.c.d:port" / "[v6]:port" for diagnostics.
std::string FormatAddress(const TurnAddress& a);

}}}} // namespace vianigram::voip::infrastructure::turn
