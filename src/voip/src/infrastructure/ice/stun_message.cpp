// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "stun_message.h"
#include "crc32.h"

#include <vianium/crypto/hmac.h>

#include <cstring>

namespace vianigram { namespace voip { namespace infrastructure { namespace ice {

namespace {

inline void WriteU16(std::vector<uint8_t>& buf, size_t pos, uint16_t v) {
    buf[pos]     = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[pos + 1] = static_cast<uint8_t>(v & 0xFF);
}

inline void WriteU32(std::vector<uint8_t>& buf, size_t pos, uint32_t v) {
    buf[pos]     = static_cast<uint8_t>((v >> 24) & 0xFF);
    buf[pos + 1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[pos + 2] = static_cast<uint8_t>((v >> 8)  & 0xFF);
    buf[pos + 3] = static_cast<uint8_t>(v         & 0xFF);
}

inline uint16_t ReadU16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                 static_cast<uint16_t>(p[1]));
}

inline uint32_t ReadU32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
            static_cast<uint32_t>(p[3]);
}

inline uint64_t ReadU64(const uint8_t* p) {
    return (static_cast<uint64_t>(ReadU32(p))     << 32) |
            static_cast<uint64_t>(ReadU32(p + 4));
}

// Append a STUN attribute TLV. Pads the value out to a 4-byte boundary
// with zeros (padding bytes do NOT count toward the attribute length).
void AppendAttr(std::vector<uint8_t>& buf,
                uint16_t type,
                const uint8_t* value, size_t length) {
    size_t headerPos = buf.size();
    buf.resize(headerPos + 4);
    WriteU16(buf, headerPos,     type);
    WriteU16(buf, headerPos + 2, static_cast<uint16_t>(length));
    if (length) {
        buf.insert(buf.end(), value, value + length);
    }
    while ((buf.size() & 0x3) != 0) {
        buf.push_back(0);
    }
}

void AppendAttrU32(std::vector<uint8_t>& buf, uint16_t type, uint32_t value) {
    uint8_t v[4];
    v[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    v[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    v[2] = static_cast<uint8_t>((value >> 8)  & 0xFF);
    v[3] = static_cast<uint8_t>(value         & 0xFF);
    AppendAttr(buf, type, v, 4);
}

void AppendAttrU64(std::vector<uint8_t>& buf, uint16_t type, uint64_t value) {
    uint8_t v[8];
    v[0] = static_cast<uint8_t>((value >> 56) & 0xFF);
    v[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
    v[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
    v[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
    v[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
    v[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
    v[6] = static_cast<uint8_t>((value >> 8)  & 0xFF);
    v[7] = static_cast<uint8_t>(value         & 0xFF);
    AppendAttr(buf, type, v, 8);
}

} // namespace

StunMessage::StunMessage()
    : MessageType(0)
    , HasPriority(false), Priority(0)
    , HasIceControlling(false), IceControllingTieBreak(0)
    , HasIceControlled(false),  IceControlledTieBreak(0)
    , UseCandidate(false)
    , HasMappedAddress(false), MappedFamily(0), MappedPort(0)
    , HasFingerprint(false), Fingerprint(0)
{
    std::memset(TransactionId, 0, sizeof(TransactionId));
    std::memset(MappedAddress, 0, sizeof(MappedAddress));
}

std::vector<uint8_t> StunMessageCodec::Encode(const StunMessage& msg,
                                              const std::string& password) {
    std::vector<uint8_t> buf;
    buf.reserve(96);

    // Header (length filled in last).
    buf.resize(20);
    WriteU16(buf, 0, msg.MessageType);
    WriteU16(buf, 2, 0);
    WriteU32(buf, 4, kStunMagicCookie);
    std::memcpy(&buf[8], msg.TransactionId, 12);

    // USERNAME (if any) - encode first per common practice.
    if (!msg.Username.empty()) {
        AppendAttr(buf, kStunAttrUsername,
                   reinterpret_cast<const uint8_t*>(msg.Username.data()),
                   msg.Username.size());
    }

    // PRIORITY
    if (msg.HasPriority) {
        AppendAttrU32(buf, kStunAttrPriority, msg.Priority);
    }

    // ICE-CONTROLLING / ICE-CONTROLLED (mutually exclusive in practice)
    if (msg.HasIceControlling) {
        AppendAttrU64(buf, kStunAttrIceControlling, msg.IceControllingTieBreak);
    }
    if (msg.HasIceControlled) {
        AppendAttrU64(buf, kStunAttrIceControlled, msg.IceControlledTieBreak);
    }

    // USE-CANDIDATE (zero-length flag)
    if (msg.UseCandidate) {
        AppendAttr(buf, kStunAttrUseCandidate, NULL, 0);
    }

    // XOR-MAPPED-ADDRESS (responses only)
    if (msg.HasMappedAddress) {
        // family(1) reserved(1) xport(2) xaddr(4 or 16)
        std::vector<uint8_t> v;
        if (msg.MappedFamily == 0x01) {
            v.resize(8);
            v[0] = 0;
            v[1] = 0x01;
            uint16_t xport = static_cast<uint16_t>(msg.MappedPort ^
                                                   ((kStunMagicCookie >> 16) & 0xFFFF));
            v[2] = static_cast<uint8_t>((xport >> 8) & 0xFF);
            v[3] = static_cast<uint8_t>(xport & 0xFF);
            uint32_t a = (static_cast<uint32_t>(msg.MappedAddress[0]) << 24) |
                         (static_cast<uint32_t>(msg.MappedAddress[1]) << 16) |
                         (static_cast<uint32_t>(msg.MappedAddress[2]) << 8)  |
                          static_cast<uint32_t>(msg.MappedAddress[3]);
            uint32_t xa = a ^ kStunMagicCookie;
            v[4] = static_cast<uint8_t>((xa >> 24) & 0xFF);
            v[5] = static_cast<uint8_t>((xa >> 16) & 0xFF);
            v[6] = static_cast<uint8_t>((xa >> 8)  & 0xFF);
            v[7] = static_cast<uint8_t>(xa         & 0xFF);
            AppendAttr(buf, kStunAttrXorMappedAddress, &v[0], v.size());
        }
    }

    // MESSAGE-INTEGRITY: temporarily set length to include the 24-byte
    // MI attribute and HMAC-SHA1 the buffer-so-far.
    if (!password.empty()) {
        uint16_t miLength = static_cast<uint16_t>((buf.size() - 20) + 24);
        WriteU16(buf, 2, miLength);

        uint8_t mac[20];
        vianium::crypto::HmacSha1::Compute(
            reinterpret_cast<const uint8_t*>(password.data()),
            static_cast<int>(password.size()),
            &buf[0], buf.size(),
            mac);
        AppendAttr(buf, kStunAttrMessageIntegrity, mac, 20);
    }

    // FINGERPRINT: temporarily set length to include the 8-byte FP
    // attribute and CRC-32 the buffer-so-far.
    {
        uint16_t fpLength = static_cast<uint16_t>((buf.size() - 20) + 8);
        WriteU16(buf, 2, fpLength);

        uint32_t crc = Crc32::Compute(&buf[0], buf.size());
        AppendAttrU32(buf, kStunAttrFingerprint, crc ^ kStunFingerprintMask);
    }

    return buf;
}

bool StunMessageCodec::Decode(const uint8_t* data, size_t size, StunMessage& out) {
    if (size < 20) return false;
    uint16_t type     = ReadU16(data);
    uint16_t attrLen  = ReadU16(data + 2);
    uint32_t cookie   = ReadU32(data + 4);
    if (cookie != kStunMagicCookie) return false;
    if (20 + static_cast<size_t>(attrLen) > size) return false;

    out = StunMessage();
    out.MessageType = type;
    std::memcpy(out.TransactionId, data + 8, 12);

    const uint8_t* p   = data + 20;
    const uint8_t* end = p + attrLen;
    while (p + 4 <= end) {
        uint16_t aType = ReadU16(p);
        uint16_t aLen  = ReadU16(p + 2);
        const uint8_t* aVal = p + 4;
        if (aVal + aLen > end) return false;

        switch (aType) {
            case kStunAttrUsername:
                out.Username.assign(reinterpret_cast<const char*>(aVal), aLen);
                break;
            case kStunAttrMessageIntegrity:
                if (aLen == 20) {
                    out.MessageIntegrity.assign(aVal, aVal + 20);
                }
                break;
            case kStunAttrFingerprint:
                if (aLen == 4) {
                    out.HasFingerprint = true;
                    out.Fingerprint    = ReadU32(aVal);
                }
                break;
            case kStunAttrPriority:
                if (aLen == 4) {
                    out.HasPriority = true;
                    out.Priority    = ReadU32(aVal);
                }
                break;
            case kStunAttrIceControlling:
                if (aLen == 8) {
                    out.HasIceControlling      = true;
                    out.IceControllingTieBreak = ReadU64(aVal);
                }
                break;
            case kStunAttrIceControlled:
                if (aLen == 8) {
                    out.HasIceControlled      = true;
                    out.IceControlledTieBreak = ReadU64(aVal);
                }
                break;
            case kStunAttrUseCandidate:
                out.UseCandidate = true;
                break;
            case kStunAttrXorMappedAddress:
                if (aLen >= 8) {
                    out.HasMappedAddress = true;
                    out.MappedFamily     = aVal[1];
                    uint16_t xport = ReadU16(aVal + 2);
                    out.MappedPort = static_cast<uint16_t>(xport ^
                                          ((kStunMagicCookie >> 16) & 0xFFFF));
                    if (out.MappedFamily == 0x01 && aLen >= 8) {
                        uint32_t xa = ReadU32(aVal + 4);
                        uint32_t a  = xa ^ kStunMagicCookie;
                        out.MappedAddress[0] = static_cast<uint8_t>((a >> 24) & 0xFF);
                        out.MappedAddress[1] = static_cast<uint8_t>((a >> 16) & 0xFF);
                        out.MappedAddress[2] = static_cast<uint8_t>((a >> 8)  & 0xFF);
                        out.MappedAddress[3] = static_cast<uint8_t>(a         & 0xFF);
                    }
                }
                break;
            default:
                break;
        }

        // Advance past value, padded up to 4-byte alignment.
        size_t advance = 4 + aLen;
        while ((advance & 0x3) != 0) ++advance;
        p += advance;
    }
    return true;
}

bool StunMessageCodec::VerifyMessageIntegrity(const std::vector<uint8_t>& msgBytes,
                                              const std::string& password) {
    // Walk attributes to find the MI offset and capture the value.
    if (msgBytes.size() < 20) return false;
    uint16_t attrLen = ReadU16(&msgBytes[2]);
    if (20 + static_cast<size_t>(attrLen) > msgBytes.size()) return false;

    size_t p = 20;
    size_t end = 20 + attrLen;
    size_t miOffset = 0;
    const uint8_t* miValue = NULL;
    while (p + 4 <= end) {
        uint16_t aType = ReadU16(&msgBytes[p]);
        uint16_t aLen  = ReadU16(&msgBytes[p + 2]);
        if (p + 4 + aLen > end) return false;
        if (aType == kStunAttrMessageIntegrity && aLen == 20) {
            miOffset = p;
            miValue  = &msgBytes[p + 4];
            break;
        }
        size_t advance = 4 + aLen;
        while ((advance & 0x3) != 0) ++advance;
        p += advance;
    }
    if (!miValue) return false;

    // Build a copy of bytes [0..miOffset) with header length rewritten to
    // (miOffset - 20 + 24) and HMAC.
    std::vector<uint8_t> tmp(msgBytes.begin(), msgBytes.begin() + miOffset);
    if (tmp.size() < 20) return false;
    uint16_t synthetic = static_cast<uint16_t>((miOffset - 20) + 24);
    tmp[2] = static_cast<uint8_t>((synthetic >> 8) & 0xFF);
    tmp[3] = static_cast<uint8_t>(synthetic & 0xFF);

    uint8_t mac[20];
    vianium::crypto::HmacSha1::Compute(
        reinterpret_cast<const uint8_t*>(password.data()),
        static_cast<int>(password.size()),
        tmp.empty() ? NULL : &tmp[0], tmp.size(),
        mac);
    for (int i = 0; i < 20; ++i) {
        if (mac[i] != miValue[i]) return false;
    }
    return true;
}

bool StunMessageCodec::VerifyFingerprint(const std::vector<uint8_t>& msgBytes) {
    if (msgBytes.size() < 28) return false;
    // Last 8 bytes must be the FINGERPRINT TLV.
    size_t fpOffset = msgBytes.size() - 8;
    if (ReadU16(&msgBytes[fpOffset]) != kStunAttrFingerprint) return false;
    if (ReadU16(&msgBytes[fpOffset + 2]) != 4) return false;

    std::vector<uint8_t> tmp(msgBytes.begin(), msgBytes.begin() + fpOffset);
    if (tmp.size() < 20) return false;
    uint16_t synthetic = static_cast<uint16_t>((fpOffset - 20) + 8);
    tmp[2] = static_cast<uint8_t>((synthetic >> 8) & 0xFF);
    tmp[3] = static_cast<uint8_t>(synthetic & 0xFF);

    uint32_t expected = Crc32::Compute(&tmp[0], tmp.size()) ^ kStunFingerprintMask;
    uint32_t actual   = ReadU32(&msgBytes[fpOffset + 4]);
    return expected == actual;
}

}}}} // namespace vianigram::voip::infrastructure::ice
