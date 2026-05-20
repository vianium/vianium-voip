// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
//
// Minimal STUN message codec (RFC 5389 + ICE attributes from RFC 5245/8445).
//
// This is *just enough* to drive ordinary ICE connectivity checks against a
// Telegram WebRTC reflector that proxies UDP between the two clients. We
// implement only the attributes the Telegram client actually emits:
//
//   0x0006 USERNAME              (STUN short-term credential, ICE: ufrag:ufrag)
//   0x0008 MESSAGE-INTEGRITY     (HMAC-SHA1 over header+attrs, key = password)
//   0x0020 XOR-MAPPED-ADDRESS    (peer's reflexive address in responses)
//   0x0024 PRIORITY              (ICE)
//   0x0025 USE-CANDIDATE         (ICE, controlling side)
//   0x8028 FINGERPRINT           (CRC-32 with 0x5354554e XOR mask)
//   0x8029 ICE-CONTROLLED        (ICE tie-breaker)
//   0x802A ICE-CONTROLLING       (ICE tie-breaker)
//
// Encoding rules (network byte order / big-endian):
//   header  : type(2) length(2) magic(4) txid(12)        = 20 bytes
//   attr    : type(2) length(2) value(length, padded to 4)
//   length  : count of attribute bytes only (header excluded)
//
// MESSAGE-INTEGRITY is computed over the STUN message *up to* (but not
// including) the MESSAGE-INTEGRITY attribute, with the header's `length`
// field temporarily set to include the 24 bytes that the MESSAGE-INTEGRITY
// TLV will occupy (4 byte TLV header + 20 byte HMAC).
//
// FINGERPRINT is computed over the entire message *up to* (but not
// including) the FINGERPRINT attribute, with the header's `length` field
// temporarily set to include the 8 bytes that the FINGERPRINT TLV occupies
// (4 byte TLV header + 4 byte CRC). The 32-bit CRC value is XORed with
// 0x5354554e before being placed in the attribute value.
//
// We are C++03/11 (v120_wp81 toolset).
//

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace ice {

const uint16_t kStunBindingRequest       = 0x0001;
const uint16_t kStunBindingResponse      = 0x0101;
const uint16_t kStunBindingErrorResponse = 0x0111;

const uint32_t kStunMagicCookie     = 0x2112A442u;
const uint32_t kStunFingerprintMask = 0x5354554Eu;

const uint16_t kStunAttrUsername          = 0x0006;
const uint16_t kStunAttrMessageIntegrity  = 0x0008;
const uint16_t kStunAttrXorMappedAddress  = 0x0020;
const uint16_t kStunAttrPriority          = 0x0024;
const uint16_t kStunAttrUseCandidate      = 0x0025;
const uint16_t kStunAttrFingerprint       = 0x8028;
const uint16_t kStunAttrIceControlled     = 0x8029;
const uint16_t kStunAttrIceControlling    = 0x802A;

struct StunMessage {
    uint16_t MessageType;             // e.g. 0x0001
    uint8_t  TransactionId[12];       // random for requests, copied for responses

    // ICE / short-term credential attributes that we read or write. All are
    // optional; unused slots stay empty / false / zero.
    std::string Username;             // value of USERNAME attribute (UTF-8 ufrag:ufrag)
    bool        HasPriority;
    uint32_t    Priority;
    bool        HasIceControlling;
    uint64_t    IceControllingTieBreak;
    bool        HasIceControlled;
    uint64_t    IceControlledTieBreak;
    bool        UseCandidate;

    // Decoded XOR-MAPPED-ADDRESS (only meaningful in responses we receive).
    bool         HasMappedAddress;
    uint8_t      MappedFamily;        // 0x01 IPv4, 0x02 IPv6
    uint8_t      MappedAddress[16];   // big-endian, IPv4 occupies first 4
    uint16_t     MappedPort;

    // The raw bytes of MESSAGE-INTEGRITY / FINGERPRINT, populated by Decode
    // for diagnostic purposes only. Encode regenerates them.
    std::vector<uint8_t> MessageIntegrity;
    bool        HasFingerprint;
    uint32_t    Fingerprint;

    StunMessage();
};

class StunMessageCodec {
public:
    // Encode a STUN message and append MESSAGE-INTEGRITY (if password
    // non-empty) followed by FINGERPRINT. The returned buffer is what
    // goes on the wire.
    static std::vector<uint8_t> Encode(const StunMessage& msg,
                                       const std::string& password);

    // Decode a STUN message. Returns false on malformed input. Does NOT
    // verify message integrity (call VerifyMessageIntegrity for that).
    static bool Decode(const uint8_t* data, size_t size, StunMessage& out);

    // Re-compute HMAC-SHA1 over (header + attributes_before_MI) using
    // `password` as the key, with the header length field rewritten to
    // include the MI attribute, and compare against the MI attribute that
    // is actually present in `msgBytes`.
    static bool VerifyMessageIntegrity(const std::vector<uint8_t>& msgBytes,
                                       const std::string& password);

    // Verify the FINGERPRINT attribute in `msgBytes` (CRC-32 of bytes
    // before FINGERPRINT XOR 0x5354554e).
    static bool VerifyFingerprint(const std::vector<uint8_t>& msgBytes);
};

}}}} // namespace vianigram::voip::infrastructure::ice
