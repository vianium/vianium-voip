// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// DTLS 1.2 handshake codecs.
#include "dtls_handshake_messages.h"
#include "dtls_record.h"   // for kDtlsVersion12
#include <cstring>

namespace vianigram { namespace voip { namespace infrastructure { namespace dtls {

// ---- Big-endian helpers ----
static inline void StoreBE16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void StoreBE24(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
}
static inline uint16_t LoadBE16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t LoadBE24(const uint8_t* p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static void AppendU8 (std::vector<uint8_t>& v, uint8_t  x) { v.push_back(x); }
static void AppendU16(std::vector<uint8_t>& v, uint16_t x) { v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x); }
static void AppendU24(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)(x >> 16)); v.push_back((uint8_t)(x >> 8)); v.push_back((uint8_t)x);
}
static void AppendBytes(std::vector<uint8_t>& v, const uint8_t* p, size_t n) {
    if (n) v.insert(v.end(), p, p + n);
}

// =====================================================================
// HandshakeHeader
// =====================================================================
HandshakeHeader::HandshakeHeader()
    : msgType(0), length(0), messageSeq(0), fragmentOffset(0), fragmentLength(0) {}

void HandshakeHeaderCodec::Encode(const HandshakeHeader& h, uint8_t out[kHandshakeHeaderSize]) {
    out[0] = h.msgType;
    StoreBE24(&out[1], h.length);
    StoreBE16(&out[4], h.messageSeq);
    StoreBE24(&out[6], h.fragmentOffset);
    StoreBE24(&out[9], h.fragmentLength);
}

bool HandshakeHeaderCodec::Decode(const uint8_t* data, size_t size, HandshakeHeader& out) {
    if (size < kHandshakeHeaderSize) return false;
    out.msgType        = data[0];
    out.length         = LoadBE24(&data[1]);
    out.messageSeq     = LoadBE16(&data[4]);
    out.fragmentOffset = LoadBE24(&data[6]);
    out.fragmentLength = LoadBE24(&data[9]);
    return true;
}

std::vector<uint8_t> WrapHandshakeUnfragmented(uint8_t msgType,
                                               uint16_t messageSeq,
                                               const std::vector<uint8_t>& body)
{
    std::vector<uint8_t> out;
    out.reserve(kHandshakeHeaderSize + body.size());
    HandshakeHeader h;
    h.msgType        = msgType;
    h.length         = (uint32_t)body.size();
    h.messageSeq     = messageSeq;
    h.fragmentOffset = 0;
    h.fragmentLength = (uint32_t)body.size();

    uint8_t hdr[kHandshakeHeaderSize];
    HandshakeHeaderCodec::Encode(h, hdr);
    out.insert(out.end(), hdr, hdr + kHandshakeHeaderSize);
    if (!body.empty()) out.insert(out.end(), body.begin(), body.end());
    return out;
}

// =====================================================================
// ClientHello
// =====================================================================
ClientHello::ClientHello() : extendedMasterSecret(true) {
    std::memset(random, 0, sizeof(random));
}

std::vector<uint8_t> ClientHelloCodec::Encode(const ClientHello& m) {
    std::vector<uint8_t> body;

    // client_version (DTLS 1.2)
    AppendU16(body, kDtlsVersion12);

    // random (32 bytes)
    AppendBytes(body, m.random, 32);

    // session_id<0..32>
    AppendU8(body, (uint8_t)m.sessionId.size());
    AppendBytes(body, m.sessionId.empty() ? 0 : &m.sessionId[0], m.sessionId.size());

    // cookie<0..255>  (DTLS-only)
    AppendU8(body, (uint8_t)m.cookie.size());
    AppendBytes(body, m.cookie.empty() ? 0 : &m.cookie[0], m.cookie.size());

    // cipher_suites<2..2^16-2>
    {
        uint16_t bytes = (uint16_t)(m.cipherSuites.size() * 2);
        AppendU16(body, bytes);
        for (size_t i = 0; i < m.cipherSuites.size(); ++i) AppendU16(body, m.cipherSuites[i]);
    }

    // compression_methods<1..2^8-1>
    AppendU8(body, (uint8_t)m.compressionMethods.size());
    AppendBytes(body, m.compressionMethods.empty() ? 0 : &m.compressionMethods[0], m.compressionMethods.size());

    // extensions<0..2^16-1>
    std::vector<uint8_t> exts;

    // supported_groups
    if (!m.supportedGroups.empty()) {
        std::vector<uint8_t> body2;
        AppendU16(body2, (uint16_t)(m.supportedGroups.size() * 2));
        for (size_t i = 0; i < m.supportedGroups.size(); ++i) AppendU16(body2, m.supportedGroups[i]);
        AppendU16(exts, kExtSupportedGroups);
        AppendU16(exts, (uint16_t)body2.size());
        AppendBytes(exts, body2.empty() ? 0 : &body2[0], body2.size());
    }

    // ec_point_formats
    if (!m.ecPointFormats.empty()) {
        std::vector<uint8_t> body2;
        AppendU8(body2, (uint8_t)m.ecPointFormats.size());
        AppendBytes(body2, &m.ecPointFormats[0], m.ecPointFormats.size());
        AppendU16(exts, kExtEcPointFormats);
        AppendU16(exts, (uint16_t)body2.size());
        AppendBytes(exts, body2.empty() ? 0 : &body2[0], body2.size());
    }

    // signature_algorithms
    if (!m.signatureAlgorithms.empty()) {
        std::vector<uint8_t> body2;
        AppendU16(body2, (uint16_t)(m.signatureAlgorithms.size() * 2));
        for (size_t i = 0; i < m.signatureAlgorithms.size(); ++i) AppendU16(body2, m.signatureAlgorithms[i]);
        AppendU16(exts, kExtSignatureAlgorithms);
        AppendU16(exts, (uint16_t)body2.size());
        AppendBytes(exts, body2.empty() ? 0 : &body2[0], body2.size());
    }

    // use_srtp (RFC 5764)
    if (!m.srtpProtectionProfiles.empty()) {
        std::vector<uint8_t> body2;
        AppendU16(body2, (uint16_t)(m.srtpProtectionProfiles.size() * 2));
        for (size_t i = 0; i < m.srtpProtectionProfiles.size(); ++i) AppendU16(body2, m.srtpProtectionProfiles[i]);
        AppendU8(body2, (uint8_t)m.srtpMki.size());
        AppendBytes(body2, m.srtpMki.empty() ? 0 : &m.srtpMki[0], m.srtpMki.size());
        AppendU16(exts, kExtUseSrtp);
        AppendU16(exts, (uint16_t)body2.size());
        AppendBytes(exts, body2.empty() ? 0 : &body2[0], body2.size());
    }

    // extended_master_secret
    if (m.extendedMasterSecret) {
        AppendU16(exts, kExtExtendedMasterSecret);
        AppendU16(exts, 0);
    }

    AppendU16(body, (uint16_t)exts.size());
    AppendBytes(body, exts.empty() ? 0 : &exts[0], exts.size());

    return body;
}

// =====================================================================
// HelloVerifyRequest
// =====================================================================
bool HelloVerifyRequestCodec::Decode(const uint8_t* data, size_t size, HelloVerifyRequest& out) {
    if (size < 3) return false;
    out.serverVersion = LoadBE16(data);
    uint8_t cookieLen = data[2];
    if ((size_t)3 + cookieLen > size) return false;
    out.cookie.assign(data + 3, data + 3 + cookieLen);
    return true;
}

// =====================================================================
// ServerHello
// =====================================================================
ServerHello::ServerHello()
    : serverVersion(kDtlsVersion12), cipherSuite(0), compressionMethod(0),
      extendedMasterSecret(false), useSrtpPresent(false), srtpProtectionProfile(0)
{
    std::memset(random, 0, sizeof(random));
}

bool ServerHelloCodec::Decode(const uint8_t* data, size_t size, ServerHello& out) {
    size_t pos = 0;
    if (size < 2 + 32 + 1) return false;

    out.serverVersion = LoadBE16(data + pos); pos += 2;
    std::memcpy(out.random, data + pos, 32);  pos += 32;

    uint8_t sidLen = data[pos++];
    if (pos + sidLen > size) return false;
    out.sessionId.assign(data + pos, data + pos + sidLen); pos += sidLen;

    if (pos + 3 > size) return false;
    out.cipherSuite       = LoadBE16(data + pos); pos += 2;
    out.compressionMethod = data[pos++];

    out.extendedMasterSecret = false;
    out.useSrtpPresent       = false;

    if (pos == size) return true; // no extensions block

    if (pos + 2 > size) return false;
    uint16_t extsLen = LoadBE16(data + pos); pos += 2;
    if (pos + extsLen > size) return false;

    size_t extsEnd = pos + extsLen;
    while (pos + 4 <= extsEnd) {
        uint16_t extType = LoadBE16(data + pos); pos += 2;
        uint16_t extLen  = LoadBE16(data + pos); pos += 2;
        if (pos + extLen > extsEnd) return false;

        if (extType == kExtExtendedMasterSecret) {
            out.extendedMasterSecret = true;
        } else if (extType == kExtUseSrtp) {
            // SRTPProtectionProfiles<2..2^16-1>; opaque mki<0..255>;
            if (extLen >= 2) {
                uint16_t profsLen = LoadBE16(data + pos);
                if (profsLen >= 2 && extLen >= 2 + profsLen) {
                    out.useSrtpPresent       = true;
                    out.srtpProtectionProfile = LoadBE16(data + pos + 2);
                }
            }
        }
        pos += extLen;
    }
    return true;
}

// =====================================================================
// Certificate
//   ASN.1Cert certificate_list<0..2^24-1>
//     opaque certificate<1..2^24-1>  // each cert is uint24 length-prefixed
// =====================================================================
bool CertificateCodec::Decode(const uint8_t* data, size_t size, Certificate& out) {
    out.chain.clear();
    if (size < 3) return false;
    uint32_t listLen = LoadBE24(data);
    if (3 + listLen > size) return false;

    size_t pos = 3;
    size_t end = 3 + listLen;
    while (pos + 3 <= end) {
        uint32_t certLen = LoadBE24(data + pos); pos += 3;
        if (pos + certLen > end) return false;
        std::vector<uint8_t> cert(data + pos, data + pos + certLen);
        out.chain.push_back(cert);
        pos += certLen;
    }
    return true;
}

// =====================================================================
// ServerKeyExchange (ECDHE_ECDSA flavour)
//   curve_type(1)
//   named_curve(2)
//   public_point: uint8 length || octets
//   signature_and_hash_algorithm: uint8+uint8
//   signature: uint16 length || octets
// =====================================================================
bool ServerKeyExchangeCodec::Decode(const uint8_t* data, size_t size, ServerKeyExchange& out) {
    if (size < 4) return false;
    size_t pos = 0;

    uint8_t curveType = data[pos++];
    if (curveType != 0x03) return false; // 3 = named_curve
    out.namedCurve = LoadBE16(data + pos); pos += 2;

    uint8_t pointLen = data[pos++];
    if (pos + pointLen > size) return false;
    out.publicPoint.assign(data + pos, data + pos + pointLen);

    // signedParams = curveType .. publicPoint (the bytes covered by the signature)
    out.signedParams.assign(data, data + pos + pointLen);
    pos += pointLen;

    if (pos + 2 > size) return false;
    out.hashAlgorithm      = data[pos++];
    out.signatureAlgorithm = data[pos++];

    if (pos + 2 > size) return false;
    uint16_t sigLen = LoadBE16(data + pos); pos += 2;
    if (pos + sigLen > size) return false;
    out.signature.assign(data + pos, data + pos + sigLen);
    return true;
}

// =====================================================================
// ClientKeyExchange (ECDHE)
//   opaque ecdh_Yc<1..255>
// =====================================================================
std::vector<uint8_t> ClientKeyExchangeCodec::Encode(const ClientKeyExchange& m) {
    std::vector<uint8_t> body;
    AppendU8(body, (uint8_t)m.publicPoint.size());
    AppendBytes(body, m.publicPoint.empty() ? 0 : &m.publicPoint[0], m.publicPoint.size());
    return body;
}

// =====================================================================
// CertificateVerify
// =====================================================================
std::vector<uint8_t> CertificateVerifyCodec::Encode(const CertificateVerify& m) {
    std::vector<uint8_t> body;
    AppendU8(body, m.hashAlgorithm);
    AppendU8(body, m.signatureAlgorithm);
    AppendU16(body, (uint16_t)m.signature.size());
    AppendBytes(body, m.signature.empty() ? 0 : &m.signature[0], m.signature.size());
    return body;
}

// =====================================================================
// Finished
// =====================================================================
std::vector<uint8_t> FinishedCodec::Encode(const Finished& m) {
    std::vector<uint8_t> body(m.verifyData, m.verifyData + kVerifyDataLength);
    return body;
}

bool FinishedCodec::Decode(const uint8_t* data, size_t size, Finished& out) {
    if (size < kVerifyDataLength) return false;
    std::memcpy(out.verifyData, data, kVerifyDataLength);
    return true;
}

}}}} // namespace vianigram::voip::infrastructure::dtls
