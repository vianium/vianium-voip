// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "turn_message.h"

#include <vianium/crypto/hmac.h>

#include <cstring>
#include <sstream>

namespace vianigram { namespace voip { namespace infrastructure { namespace turn {

// =============================================================================
// MD5 (RFC 1321) inline implementation.
//
// HMAC-SHA1 ships in Vianium.Core.Tls/crypto/hmac.h, but MD5 doesn't, and we
// only need it for the long-term-credential key derivation
// (MD5(username:realm:password)). RFC 1321 + RFC 5389 Section 15.4 spell out
// the exact algorithm; the implementation below is the standard reference
// expansion (~70 LOC). MD5 is used solely for STUN/TURN credential derivation
// here; it is NOT used to authenticate or hash anything else, so its
// well-known weaknesses are not relevant.
// =============================================================================

namespace {

struct Md5Ctx {
    uint32_t state[4];
    uint64_t bitCount;
    uint8_t  buffer[64];
};

inline uint32_t Rotl32(uint32_t x, int s) {
    return (x << s) | (x >> (32 - s));
}

#define MD5_F(x,y,z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x,y,z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x,y,z) ((x) ^ (y) ^ (z))
#define MD5_I(x,y,z) ((y) ^ ((x) | (~z)))

#define MD5_FF(a,b,c,d,x,s,ac) { (a) += MD5_F(b,c,d) + (x) + (uint32_t)(ac); (a) = Rotl32(a,s); (a) += (b); }
#define MD5_GG(a,b,c,d,x,s,ac) { (a) += MD5_G(b,c,d) + (x) + (uint32_t)(ac); (a) = Rotl32(a,s); (a) += (b); }
#define MD5_HH(a,b,c,d,x,s,ac) { (a) += MD5_H(b,c,d) + (x) + (uint32_t)(ac); (a) = Rotl32(a,s); (a) += (b); }
#define MD5_II(a,b,c,d,x,s,ac) { (a) += MD5_I(b,c,d) + (x) + (uint32_t)(ac); (a) = Rotl32(a,s); (a) += (b); }

void Md5Transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] =  static_cast<uint32_t>(block[i * 4 + 0])
             | (static_cast<uint32_t>(block[i * 4 + 1]) << 8)
             | (static_cast<uint32_t>(block[i * 4 + 2]) << 16)
             | (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }

    // Round 1
    MD5_FF(a,b,c,d, x[ 0], 7,  0xd76aa478);
    MD5_FF(d,a,b,c, x[ 1], 12, 0xe8c7b756);
    MD5_FF(c,d,a,b, x[ 2], 17, 0x242070db);
    MD5_FF(b,c,d,a, x[ 3], 22, 0xc1bdceee);
    MD5_FF(a,b,c,d, x[ 4], 7,  0xf57c0faf);
    MD5_FF(d,a,b,c, x[ 5], 12, 0x4787c62a);
    MD5_FF(c,d,a,b, x[ 6], 17, 0xa8304613);
    MD5_FF(b,c,d,a, x[ 7], 22, 0xfd469501);
    MD5_FF(a,b,c,d, x[ 8], 7,  0x698098d8);
    MD5_FF(d,a,b,c, x[ 9], 12, 0x8b44f7af);
    MD5_FF(c,d,a,b, x[10], 17, 0xffff5bb1);
    MD5_FF(b,c,d,a, x[11], 22, 0x895cd7be);
    MD5_FF(a,b,c,d, x[12], 7,  0x6b901122);
    MD5_FF(d,a,b,c, x[13], 12, 0xfd987193);
    MD5_FF(c,d,a,b, x[14], 17, 0xa679438e);
    MD5_FF(b,c,d,a, x[15], 22, 0x49b40821);

    // Round 2
    MD5_GG(a,b,c,d, x[ 1], 5,  0xf61e2562);
    MD5_GG(d,a,b,c, x[ 6], 9,  0xc040b340);
    MD5_GG(c,d,a,b, x[11], 14, 0x265e5a51);
    MD5_GG(b,c,d,a, x[ 0], 20, 0xe9b6c7aa);
    MD5_GG(a,b,c,d, x[ 5], 5,  0xd62f105d);
    MD5_GG(d,a,b,c, x[10], 9,  0x02441453);
    MD5_GG(c,d,a,b, x[15], 14, 0xd8a1e681);
    MD5_GG(b,c,d,a, x[ 4], 20, 0xe7d3fbc8);
    MD5_GG(a,b,c,d, x[ 9], 5,  0x21e1cde6);
    MD5_GG(d,a,b,c, x[14], 9,  0xc33707d6);
    MD5_GG(c,d,a,b, x[ 3], 14, 0xf4d50d87);
    MD5_GG(b,c,d,a, x[ 8], 20, 0x455a14ed);
    MD5_GG(a,b,c,d, x[13], 5,  0xa9e3e905);
    MD5_GG(d,a,b,c, x[ 2], 9,  0xfcefa3f8);
    MD5_GG(c,d,a,b, x[ 7], 14, 0x676f02d9);
    MD5_GG(b,c,d,a, x[12], 20, 0x8d2a4c8a);

    // Round 3
    MD5_HH(a,b,c,d, x[ 5], 4,  0xfffa3942);
    MD5_HH(d,a,b,c, x[ 8], 11, 0x8771f681);
    MD5_HH(c,d,a,b, x[11], 16, 0x6d9d6122);
    MD5_HH(b,c,d,a, x[14], 23, 0xfde5380c);
    MD5_HH(a,b,c,d, x[ 1], 4,  0xa4beea44);
    MD5_HH(d,a,b,c, x[ 4], 11, 0x4bdecfa9);
    MD5_HH(c,d,a,b, x[ 7], 16, 0xf6bb4b60);
    MD5_HH(b,c,d,a, x[10], 23, 0xbebfbc70);
    MD5_HH(a,b,c,d, x[13], 4,  0x289b7ec6);
    MD5_HH(d,a,b,c, x[ 0], 11, 0xeaa127fa);
    MD5_HH(c,d,a,b, x[ 3], 16, 0xd4ef3085);
    MD5_HH(b,c,d,a, x[ 6], 23, 0x04881d05);
    MD5_HH(a,b,c,d, x[ 9], 4,  0xd9d4d039);
    MD5_HH(d,a,b,c, x[12], 11, 0xe6db99e5);
    MD5_HH(c,d,a,b, x[15], 16, 0x1fa27cf8);
    MD5_HH(b,c,d,a, x[ 2], 23, 0xc4ac5665);

    // Round 4
    MD5_II(a,b,c,d, x[ 0], 6,  0xf4292244);
    MD5_II(d,a,b,c, x[ 7], 10, 0x432aff97);
    MD5_II(c,d,a,b, x[14], 15, 0xab9423a7);
    MD5_II(b,c,d,a, x[ 5], 21, 0xfc93a039);
    MD5_II(a,b,c,d, x[12], 6,  0x655b59c3);
    MD5_II(d,a,b,c, x[ 3], 10, 0x8f0ccc92);
    MD5_II(c,d,a,b, x[10], 15, 0xffeff47d);
    MD5_II(b,c,d,a, x[ 1], 21, 0x85845dd1);
    MD5_II(a,b,c,d, x[ 8], 6,  0x6fa87e4f);
    MD5_II(d,a,b,c, x[15], 10, 0xfe2ce6e0);
    MD5_II(c,d,a,b, x[ 6], 15, 0xa3014314);
    MD5_II(b,c,d,a, x[13], 21, 0x4e0811a1);
    MD5_II(a,b,c,d, x[ 4], 6,  0xf7537e82);
    MD5_II(d,a,b,c, x[11], 10, 0xbd3af235);
    MD5_II(c,d,a,b, x[ 2], 15, 0x2ad7d2bb);
    MD5_II(b,c,d,a, x[ 9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void Md5Init(Md5Ctx& ctx) {
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
    ctx.bitCount = 0;
    std::memset(ctx.buffer, 0, sizeof(ctx.buffer));
}

void Md5Update(Md5Ctx& ctx, const uint8_t* data, size_t len) {
    size_t bufferIndex = static_cast<size_t>((ctx.bitCount >> 3) & 0x3F);
    ctx.bitCount += static_cast<uint64_t>(len) << 3;
    size_t partLen = 64 - bufferIndex;
    size_t i = 0;
    if (len >= partLen) {
        std::memcpy(ctx.buffer + bufferIndex, data, partLen);
        Md5Transform(ctx.state, ctx.buffer);
        for (i = partLen; i + 63 < len; i += 64) {
            Md5Transform(ctx.state, data + i);
        }
        bufferIndex = 0;
    }
    if (i < len) {
        std::memcpy(ctx.buffer + bufferIndex, data + i, len - i);
    }
}

void Md5Final(Md5Ctx& ctx, uint8_t out[16]) {
    static const uint8_t kPadding[64] = { 0x80, 0 };
    uint8_t bits[8];
    uint64_t bitCount = ctx.bitCount;
    for (int i = 0; i < 8; i++) {
        bits[i] = static_cast<uint8_t>((bitCount >> (8 * i)) & 0xFF);
    }
    size_t index = static_cast<size_t>((ctx.bitCount >> 3) & 0x3F);
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    Md5Update(ctx, kPadding, padLen);
    Md5Update(ctx, bits, 8);
    for (int i = 0; i < 4; i++) {
        out[i * 4 + 0] = static_cast<uint8_t>(ctx.state[i] & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((ctx.state[i] >> 8)  & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((ctx.state[i] >> 16) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>((ctx.state[i] >> 24) & 0xFF);
    }
}

#undef MD5_F
#undef MD5_G
#undef MD5_H
#undef MD5_I
#undef MD5_FF
#undef MD5_GG
#undef MD5_HH
#undef MD5_II

} // anonymous namespace

// =============================================================================
// Wire helpers.
// =============================================================================

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

void EncodeXorAddress(std::vector<uint8_t>& buf,
                      uint16_t attrType,
                      const TurnAddress& addr,
                      const uint8_t txnId[12]) {
    if (addr.Family != kFamilyIPv4 && addr.Family != kFamilyIPv6) return;
    if (addr.Family == kFamilyIPv4 && addr.Address.size() != 4) return;
    if (addr.Family == kFamilyIPv6 && addr.Address.size() != 16) return;

    std::vector<uint8_t> v;
    v.resize(addr.Family == kFamilyIPv4 ? 8 : 20);
    v[0] = 0;
    v[1] = addr.Family;

    uint16_t xport = static_cast<uint16_t>(
        addr.Port ^ static_cast<uint16_t>((kMagicCookie >> 16) & 0xFFFF));
    v[2] = static_cast<uint8_t>((xport >> 8) & 0xFF);
    v[3] = static_cast<uint8_t>(xport & 0xFF);

    if (addr.Family == kFamilyIPv4) {
        uint32_t a = (static_cast<uint32_t>(addr.Address[0]) << 24) |
                     (static_cast<uint32_t>(addr.Address[1]) << 16) |
                     (static_cast<uint32_t>(addr.Address[2]) << 8)  |
                      static_cast<uint32_t>(addr.Address[3]);
        uint32_t xa = a ^ kMagicCookie;
        v[4] = static_cast<uint8_t>((xa >> 24) & 0xFF);
        v[5] = static_cast<uint8_t>((xa >> 16) & 0xFF);
        v[6] = static_cast<uint8_t>((xa >> 8)  & 0xFF);
        v[7] = static_cast<uint8_t>(xa         & 0xFF);
    } else {
        // Family == IPv6: XOR with magic_cookie || transaction_id.
        uint8_t mask[16];
        WriteU32(*reinterpret_cast<std::vector<uint8_t>*>(&v), 0, 0); // dummy to silence unused-warnings on some compilers
        mask[0] = static_cast<uint8_t>((kMagicCookie >> 24) & 0xFF);
        mask[1] = static_cast<uint8_t>((kMagicCookie >> 16) & 0xFF);
        mask[2] = static_cast<uint8_t>((kMagicCookie >> 8)  & 0xFF);
        mask[3] = static_cast<uint8_t>(kMagicCookie         & 0xFF);
        std::memcpy(mask + 4, txnId, 12);
        for (int i = 0; i < 16; i++) {
            v[4 + i] = static_cast<uint8_t>(addr.Address[i] ^ mask[i]);
        }
    }

    AppendAttr(buf, attrType, &v[0], v.size());
}

bool DecodeXorAddress(uint16_t /*attrType*/,
                      const uint8_t* val, uint16_t len,
                      const uint8_t txnId[12],
                      TurnAddress& out) {
    if (len < 8) return false;
    out.Family = val[1];
    uint16_t xport = ReadU16(val + 2);
    out.Port = static_cast<uint16_t>(
        xport ^ static_cast<uint16_t>((kMagicCookie >> 16) & 0xFFFF));
    if (out.Family == kFamilyIPv4) {
        if (len < 8) return false;
        uint32_t xa = ReadU32(val + 4);
        uint32_t a  = xa ^ kMagicCookie;
        out.Address.resize(4);
        out.Address[0] = static_cast<uint8_t>((a >> 24) & 0xFF);
        out.Address[1] = static_cast<uint8_t>((a >> 16) & 0xFF);
        out.Address[2] = static_cast<uint8_t>((a >> 8)  & 0xFF);
        out.Address[3] = static_cast<uint8_t>(a         & 0xFF);
        return true;
    }
    if (out.Family == kFamilyIPv6) {
        if (len < 20) return false;
        uint8_t mask[16];
        mask[0] = static_cast<uint8_t>((kMagicCookie >> 24) & 0xFF);
        mask[1] = static_cast<uint8_t>((kMagicCookie >> 16) & 0xFF);
        mask[2] = static_cast<uint8_t>((kMagicCookie >> 8)  & 0xFF);
        mask[3] = static_cast<uint8_t>(kMagicCookie         & 0xFF);
        std::memcpy(mask + 4, txnId, 12);
        out.Address.resize(16);
        for (int i = 0; i < 16; i++) {
            out.Address[i] = static_cast<uint8_t>(val[4 + i] ^ mask[i]);
        }
        return true;
    }
    return false;
}

void AppendCommonAuthAttrs(std::vector<uint8_t>& buf,
                           const std::string& username,
                           const std::string& realm,
                           const std::vector<uint8_t>& nonce) {
    if (!username.empty()) {
        AppendAttr(buf, kAttrUsername,
                   reinterpret_cast<const uint8_t*>(username.data()),
                   username.size());
    }
    if (!realm.empty()) {
        AppendAttr(buf, kAttrRealm,
                   reinterpret_cast<const uint8_t*>(realm.data()),
                   realm.size());
    }
    if (!nonce.empty()) {
        AppendAttr(buf, kAttrNonce, &nonce[0], nonce.size());
    }
}

// MESSAGE-INTEGRITY: appends a 24-byte attribute (4-byte header + 20-byte
// HMAC-SHA1) computed over the message-so-far with the header `length` field
// temporarily overwritten so it covers the M-I attribute itself.
void AppendMessageIntegrity(std::vector<uint8_t>& buf,
                            const std::vector<uint8_t>& key) {
    uint16_t miLength = static_cast<uint16_t>((buf.size() - 20) + 24);
    WriteU16(buf, 2, miLength);

    uint8_t mac[20];
    vianium::crypto::HmacSha1::Compute(
        key.empty() ? NULL : &key[0],
        static_cast<int>(key.size()),
        &buf[0], buf.size(),
        mac);
    AppendAttr(buf, kAttrMessageIntegrity, mac, 20);
}

void WriteHeader(std::vector<uint8_t>& buf, uint16_t type, const uint8_t txnId[12]) {
    buf.resize(20);
    WriteU16(buf, 0, type);
    WriteU16(buf, 2, 0);
    WriteU32(buf, 4, kMagicCookie);
    std::memcpy(&buf[8], txnId, 12);
}

void FinalizeLength(std::vector<uint8_t>& buf) {
    WriteU16(buf, 2, static_cast<uint16_t>(buf.size() - 20));
}

} // anonymous namespace

// =============================================================================
// TurnMessage default ctor.
// =============================================================================

TurnMessage::TurnMessage()
    : Type(0)
    , HasUsername(false)
    , HasRealm(false)
    , HasNonce(false)
    , HasErrorCode(false), ErrorCode(0)
    , HasXorMapped(false)
    , HasXorRelayed(false)
    , HasData(false)
    , HasLifetime(false), Lifetime(0)
    , HasRequestedTransport(false), Protocol(0)
    , HasMessageIntegrity(false)
{
    std::memset(TransactionId, 0, sizeof(TransactionId));
}

// =============================================================================
// Encode helpers.
// =============================================================================

std::vector<uint8_t> EncodeAllocate(
    const uint8_t txnId[12], uint32_t lifetimeSeconds,
    const std::string& username, const std::string& realm,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> buf;
    buf.reserve(96);
    WriteHeader(buf, TurnMessageType(kMethodAllocate, kClassRequest), txnId);

    // REQUESTED-TRANSPORT (0x0019) -- protocol = 17 (UDP) << 24
    {
        uint8_t v[4];
        v[0] = 17; v[1] = 0; v[2] = 0; v[3] = 0;
        AppendAttr(buf, kAttrRequestedTransport, v, 4);
    }
    // DONT-FRAGMENT (0x001A) -- zero-length flag.
    AppendAttr(buf, kAttrDontFragment, NULL, 0);
    // LIFETIME (0x000D)
    AppendAttrU32(buf, kAttrLifetime, lifetimeSeconds);

    // Auth attrs (omitted on the very first unauthenticated Allocate).
    AppendCommonAuthAttrs(buf, username, realm, nonce);

    if (!key.empty()) {
        AppendMessageIntegrity(buf, key);
    }
    FinalizeLength(buf);
    return buf;
}

std::vector<uint8_t> EncodeCreatePermission(
    const uint8_t txnId[12],
    const std::vector<TurnAddress>& peers,
    const std::string& username, const std::string& realm,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> buf;
    buf.reserve(96);
    WriteHeader(buf, TurnMessageType(kMethodCreatePermission, kClassRequest), txnId);

    for (size_t i = 0; i < peers.size(); i++) {
        EncodeXorAddress(buf, kAttrXorPeerAddress, peers[i], txnId);
    }
    AppendCommonAuthAttrs(buf, username, realm, nonce);
    if (!key.empty()) {
        AppendMessageIntegrity(buf, key);
    }
    FinalizeLength(buf);
    return buf;
}

std::vector<uint8_t> EncodeSendIndication(
    const uint8_t txnId[12],
    const TurnAddress& peer,
    const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> buf;
    buf.reserve(48 + data.size());
    WriteHeader(buf, TurnMessageType(kMethodSend, kClassIndication), txnId);

    EncodeXorAddress(buf, kAttrXorPeerAddress, peer, txnId);
    if (!data.empty()) {
        AppendAttr(buf, kAttrData, &data[0], data.size());
    } else {
        AppendAttr(buf, kAttrData, NULL, 0);
    }
    // Send Indications carry no MESSAGE-INTEGRITY in long-term-cred mode.
    FinalizeLength(buf);
    return buf;
}

std::vector<uint8_t> EncodeRefresh(
    const uint8_t txnId[12], uint32_t lifetimeSeconds,
    const std::string& username, const std::string& realm,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> buf;
    buf.reserve(80);
    WriteHeader(buf, TurnMessageType(kMethodRefresh, kClassRequest), txnId);

    AppendAttrU32(buf, kAttrLifetime, lifetimeSeconds);
    AppendCommonAuthAttrs(buf, username, realm, nonce);
    if (!key.empty()) {
        AppendMessageIntegrity(buf, key);
    }
    FinalizeLength(buf);
    return buf;
}

// =============================================================================
// Decoder.
// =============================================================================

bool DecodeMessage(const std::vector<uint8_t>& bytes, TurnMessage* out) {
    if (out == NULL) return false;
    if (bytes.size() < 20) return false;
    const uint8_t* data = &bytes[0];
    if (data[0] > 0x03) return false; // Not STUN/TURN

    uint16_t type    = ReadU16(data);
    uint16_t attrLen = ReadU16(data + 2);
    uint32_t cookie  = ReadU32(data + 4);
    if (cookie != kMagicCookie) return false;
    if (20 + static_cast<size_t>(attrLen) > bytes.size()) return false;

    *out = TurnMessage();
    out->Type = type;
    std::memcpy(out->TransactionId, data + 8, 12);
    out->Raw = bytes;

    const uint8_t* p   = data + 20;
    const uint8_t* end = p + attrLen;
    while (p + 4 <= end) {
        uint16_t aType = ReadU16(p);
        uint16_t aLen  = ReadU16(p + 2);
        const uint8_t* aVal = p + 4;
        if (aVal + aLen > end) return false;

        switch (aType) {
            case kAttrUsername:
                out->HasUsername = true;
                out->Username.assign(reinterpret_cast<const char*>(aVal), aLen);
                break;
            case kAttrRealm:
                out->HasRealm = true;
                out->Realm.assign(reinterpret_cast<const char*>(aVal), aLen);
                break;
            case kAttrNonce:
                out->HasNonce = true;
                out->Nonce.assign(aVal, aVal + aLen);
                break;
            case kAttrErrorCode:
                if (aLen >= 4) {
                    out->HasErrorCode = true;
                    int cls    = aVal[2] & 0x07;       // class digit (0..7)
                    int number = aVal[3];              // 0..99
                    out->ErrorCode = cls * 100 + number;
                    if (aLen > 4) {
                        out->ErrorReason.assign(
                            reinterpret_cast<const char*>(aVal + 4),
                            aLen - 4);
                    }
                }
                break;
            case kAttrXorMappedAddress: {
                TurnAddress a;
                if (DecodeXorAddress(aType, aVal, aLen, out->TransactionId, a)) {
                    out->HasXorMapped = true;
                    out->XorMapped = a;
                }
                break;
            }
            case kAttrXorRelayedAddress: {
                TurnAddress a;
                if (DecodeXorAddress(aType, aVal, aLen, out->TransactionId, a)) {
                    out->HasXorRelayed = true;
                    out->XorRelayed = a;
                }
                break;
            }
            case kAttrXorPeerAddress: {
                TurnAddress a;
                if (DecodeXorAddress(aType, aVal, aLen, out->TransactionId, a)) {
                    out->XorPeers.push_back(a);
                }
                break;
            }
            case kAttrData:
                out->HasData = true;
                out->Data.assign(aVal, aVal + aLen);
                break;
            case kAttrLifetime:
                if (aLen == 4) {
                    out->HasLifetime = true;
                    out->Lifetime    = ReadU32(aVal);
                }
                break;
            case kAttrRequestedTransport:
                if (aLen == 4) {
                    out->HasRequestedTransport = true;
                    out->Protocol              = aVal[0];
                }
                break;
            case kAttrMessageIntegrity:
                if (aLen == 20) {
                    out->HasMessageIntegrity = true;
                    out->MessageIntegrity.assign(aVal, aVal + 20);
                }
                break;
            default:
                break;
        }

        size_t advance = 4 + aLen;
        while ((advance & 0x3) != 0) ++advance;
        p += advance;
    }
    return true;
}

// =============================================================================
// Long-term credential key derivation.
// =============================================================================

std::vector<uint8_t> DeriveLongTermKey(const std::string& username,
                                       const std::string& realm,
                                       const std::string& password)
{
    Md5Ctx ctx;
    Md5Init(ctx);
    if (!username.empty()) {
        Md5Update(ctx,
            reinterpret_cast<const uint8_t*>(username.data()),
            username.size());
    }
    {
        const uint8_t colon = ':';
        Md5Update(ctx, &colon, 1);
    }
    if (!realm.empty()) {
        Md5Update(ctx,
            reinterpret_cast<const uint8_t*>(realm.data()),
            realm.size());
    }
    {
        const uint8_t colon = ':';
        Md5Update(ctx, &colon, 1);
    }
    if (!password.empty()) {
        Md5Update(ctx,
            reinterpret_cast<const uint8_t*>(password.data()),
            password.size());
    }
    uint8_t digest[16];
    Md5Final(ctx, digest);
    return std::vector<uint8_t>(digest, digest + 16);
}

// =============================================================================
// Address helpers.
// =============================================================================

TurnAddress MakeAddressIPv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, int port) {
    TurnAddress out;
    out.Family = kFamilyIPv4;
    out.Port   = static_cast<uint16_t>(port & 0xFFFF);
    out.Address.resize(4);
    out.Address[0] = a; out.Address[1] = b; out.Address[2] = c; out.Address[3] = d;
    return out;
}

TurnAddress MakeAddress(const std::string& ip, int port) {
    TurnAddress out;
    out.Port = static_cast<uint16_t>(port & 0xFFFF);
    if (ip.empty()) return out;

    if (ip.find('.') != std::string::npos) {
        // IPv4 dotted quad.
        unsigned int parts[4] = {0, 0, 0, 0};
        int idx = 0;
        unsigned int acc = 0;
        bool inDigit = false;
        for (size_t i = 0; i <= ip.size(); ++i) {
            char ch = (i == ip.size()) ? '.' : ip[i];
            if (ch >= '0' && ch <= '9') {
                acc = acc * 10 + static_cast<unsigned int>(ch - '0');
                inDigit = true;
                if (acc > 255) { out.Address.clear(); return out; }
            } else if (ch == '.') {
                if (!inDigit) { out.Address.clear(); return out; }
                if (idx >= 4)  { out.Address.clear(); return out; }
                parts[idx++] = acc;
                acc = 0;
                inDigit = false;
            } else {
                out.Address.clear();
                return out;
            }
        }
        if (idx != 4) { out.Address.clear(); return out; }
        out.Family = kFamilyIPv4;
        out.Address.resize(4);
        out.Address[0] = static_cast<uint8_t>(parts[0]);
        out.Address[1] = static_cast<uint8_t>(parts[1]);
        out.Address[2] = static_cast<uint8_t>(parts[2]);
        out.Address[3] = static_cast<uint8_t>(parts[3]);
        return out;
    }

    // Else IPv6 -- minimal parsing. We accept canonical "x:x:x:x:x:x:x:x"
    // or "::"-compressed forms. For Telegram's relay candidates we almost
    // always see IPv4 so the IPv6 path here is best-effort and used only
    // as a fallback. If parsing fails we leave Address empty so the caller
    // can detect and skip.
    unsigned int groups[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    int gIdx = 0;
    int dblColon = -1;
    size_t i = 0;
    while (i < ip.size() && gIdx < 8) {
        if (ip[i] == ':') {
            if (i + 1 < ip.size() && ip[i + 1] == ':') {
                if (dblColon != -1) { out.Address.clear(); return out; }
                dblColon = gIdx;
                i += 2;
                continue;
            }
            ++i;
            continue;
        }
        unsigned int g = 0;
        int hexCount = 0;
        while (i < ip.size() && hexCount < 4) {
            char ch = ip[i];
            unsigned int hv = 0;
            if (ch >= '0' && ch <= '9') hv = static_cast<unsigned int>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') hv = 10 + static_cast<unsigned int>(ch - 'a');
            else if (ch >= 'A' && ch <= 'F') hv = 10 + static_cast<unsigned int>(ch - 'A');
            else break;
            g = (g << 4) | hv;
            ++i;
            ++hexCount;
        }
        if (hexCount == 0) break;
        groups[gIdx++] = g;
    }
    if (dblColon != -1) {
        // Expand ::: shift trailing groups.
        int trailing = gIdx - dblColon;
        int zeros = 8 - gIdx;
        if (zeros < 0) { out.Address.clear(); return out; }
        for (int j = trailing - 1; j >= 0; --j) {
            groups[dblColon + zeros + j] = groups[dblColon + j];
        }
        for (int j = 0; j < zeros; ++j) {
            groups[dblColon + j] = 0;
        }
        gIdx = 8;
    }
    if (gIdx != 8) { out.Address.clear(); return out; }

    out.Family = kFamilyIPv6;
    out.Address.resize(16);
    for (int j = 0; j < 8; ++j) {
        out.Address[j * 2 + 0] = static_cast<uint8_t>((groups[j] >> 8) & 0xFF);
        out.Address[j * 2 + 1] = static_cast<uint8_t>(groups[j] & 0xFF);
    }
    return out;
}

std::string FormatAddress(const TurnAddress& a) {
    std::ostringstream s;
    if (a.Family == kFamilyIPv4 && a.Address.size() == 4) {
        s << static_cast<int>(a.Address[0]) << "."
          << static_cast<int>(a.Address[1]) << "."
          << static_cast<int>(a.Address[2]) << "."
          << static_cast<int>(a.Address[3]) << ":"
          << static_cast<int>(a.Port);
    } else if (a.Family == kFamilyIPv6 && a.Address.size() == 16) {
        s << "[";
        for (int i = 0; i < 8; ++i) {
            if (i > 0) s << ":";
            uint16_t g = static_cast<uint16_t>(
                (static_cast<uint16_t>(a.Address[i * 2]) << 8) |
                 static_cast<uint16_t>(a.Address[i * 2 + 1]));
            s << std::hex << g << std::dec;
        }
        s << "]:" << static_cast<int>(a.Port);
    } else {
        s << "(unknown family " << static_cast<int>(a.Family) << ")";
    }
    return s.str();
}

}}}} // namespace vianigram::voip::infrastructure::turn
