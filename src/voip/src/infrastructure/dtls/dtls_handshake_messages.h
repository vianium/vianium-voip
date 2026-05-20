// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// DTLS 1.2 handshake message framing & per-message codecs.
//
// DTLS adds three fields beyond TLS to every handshake message header so
// that messages can be reassembled out of order across UDP datagrams:
//
//   uint8  msg_type
//   uint24 length              (length of full message body)
//   uint16 message_seq         (per-side, monotonic, starts at 0)
//   uint24 fragment_offset
//   uint24 fragment_length
//
// For our minimal client we always send unfragmented messages, so
// fragment_offset == 0 and fragment_length == length on every send.
// On receive, we only support unfragmented messages too; we fail if the
// peer fragments. This is fine for tgcalls — peer messages never exceed
// the typical 1200-byte safe MTU.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure { namespace dtls {

// Handshake type codes
const uint8_t kHsHelloRequest        = 0;
const uint8_t kHsClientHello         = 1;
const uint8_t kHsServerHello         = 2;
const uint8_t kHsHelloVerifyRequest  = 3;
const uint8_t kHsCertificate         = 11;
const uint8_t kHsServerKeyExchange   = 12;
const uint8_t kHsCertificateRequest  = 13;
const uint8_t kHsServerHelloDone     = 14;
const uint8_t kHsCertificateVerify   = 15;
const uint8_t kHsClientKeyExchange   = 16;
const uint8_t kHsFinished            = 20;

// Cipher suites we know about
const uint16_t kCsEcdheEcdsaAes128GcmSha256 = 0xC02B;

// Named groups (TLS extensions registry)
const uint16_t kNgSecp256r1 = 0x0017;

// EC point formats
const uint8_t kEcPointFormatUncompressed = 0;

// Signature algorithms (TLS 1.2 §7.4.1.4.1)
const uint16_t kSigAlgEcdsaSecp256r1Sha256 = 0x0403;

// Extension types
const uint16_t kExtServerName            = 0x0000;
const uint16_t kExtSupportedGroups       = 0x000A;
const uint16_t kExtEcPointFormats        = 0x000B;
const uint16_t kExtSignatureAlgorithms   = 0x000D;
const uint16_t kExtUseSrtp               = 0x000E; // RFC 5764
const uint16_t kExtExtendedMasterSecret  = 0x0017; // RFC 7627
const uint16_t kExtRenegotiationInfo     = 0xFF01;

// SRTP protection profiles (RFC 5764 §4.1.2)
const uint16_t kSrtpAes128CmHmacSha1_80 = 0x0001;
const uint16_t kSrtpAes128CmHmacSha1_32 = 0x0002;

// Handshake header is 12 bytes
const size_t kHandshakeHeaderSize = 12;

// 48-byte master secret length, 32-byte random length
const size_t kRandomLength       = 32;
const size_t kMasterSecretLength = 48;
const size_t kVerifyDataLength   = 12;

// ---------------------------------------------------------------------------
// Generic handshake header
// ---------------------------------------------------------------------------
struct HandshakeHeader {
    uint8_t  msgType;
    uint32_t length;          // 24-bit on the wire
    uint16_t messageSeq;
    uint32_t fragmentOffset;  // 24-bit on the wire
    uint32_t fragmentLength;  // 24-bit on the wire

    HandshakeHeader();
};

class HandshakeHeaderCodec {
public:
    static void   Encode(const HandshakeHeader& h, uint8_t out[kHandshakeHeaderSize]);
    static bool   Decode(const uint8_t* data, size_t size, HandshakeHeader& out);
};

// Wrap a handshake message body with a DTLS handshake header. Always emits
// an unfragmented message (fragment_offset = 0, fragment_length = length).
std::vector<uint8_t> WrapHandshakeUnfragmented(uint8_t msgType,
                                               uint16_t messageSeq,
                                               const std::vector<uint8_t>& body);

// ---------------------------------------------------------------------------
// ClientHello (with extensions for tgcalls/WebRTC)
// ---------------------------------------------------------------------------
struct ClientHello {
    uint8_t              random[32];
    std::vector<uint8_t> sessionId;
    std::vector<uint8_t> cookie;            // empty on first hello
    std::vector<uint16_t> cipherSuites;     // typically [0xC02B]
    std::vector<uint8_t>  compressionMethods; // [0]

    // Extensions
    std::vector<uint16_t> supportedGroups;        // [0x0017]
    std::vector<uint8_t>  ecPointFormats;          // [0]
    std::vector<uint16_t> signatureAlgorithms;    // [0x0403]
    std::vector<uint16_t> srtpProtectionProfiles; // [0x0001]
    std::vector<uint8_t>  srtpMki;                 // empty
    bool                  extendedMasterSecret;

    ClientHello();
};

class ClientHelloCodec {
public:
    // Body bytes (no DTLS handshake header). Always DTLS 1.2 (0xFEFD).
    static std::vector<uint8_t> Encode(const ClientHello& m);
};

// ---------------------------------------------------------------------------
// HelloVerifyRequest — DTLS-only cookie exchange
// ---------------------------------------------------------------------------
struct HelloVerifyRequest {
    uint16_t             serverVersion; // typically 0xFEFD
    std::vector<uint8_t> cookie;
};

class HelloVerifyRequestCodec {
public:
    static bool Decode(const uint8_t* data, size_t size, HelloVerifyRequest& out);
};

// ---------------------------------------------------------------------------
// ServerHello
// ---------------------------------------------------------------------------
struct ServerHello {
    uint16_t serverVersion;
    uint8_t  random[32];
    std::vector<uint8_t> sessionId;
    uint16_t cipherSuite;
    uint8_t  compressionMethod;
    bool     extendedMasterSecret;
    bool     useSrtpPresent;
    uint16_t srtpProtectionProfile; // valid only when useSrtpPresent

    ServerHello();
};

class ServerHelloCodec {
public:
    static bool Decode(const uint8_t* data, size_t size, ServerHello& out);
};

// ---------------------------------------------------------------------------
// Certificate (we only need the first/leaf cert DER bytes for fingerprinting)
// ---------------------------------------------------------------------------
struct Certificate {
    // Concatenated chain — entry [0] is the leaf cert in DER form.
    std::vector<std::vector<uint8_t> > chain;
};

class CertificateCodec {
public:
    static bool Decode(const uint8_t* data, size_t size, Certificate& out);
};

// ---------------------------------------------------------------------------
// ServerKeyExchange (ECDHE-ECDSA only)
//   ECCurveType  curve_type    = 0x03 (named_curve)
//   NamedCurve   named_curve
//   ECPoint      public         (uncompressed: 0x04 || X || Y)
//   SignatureAndHashAlgorithm  (TLS 1.2)
//   opaque       signature<0..2^16-1>
// ---------------------------------------------------------------------------
struct ServerKeyExchange {
    uint16_t             namedCurve;
    std::vector<uint8_t> publicPoint;       // uncompressed (0x04 || X || Y)
    uint8_t              hashAlgorithm;      // 4 = SHA256
    uint8_t              signatureAlgorithm; // 3 = ECDSA
    std::vector<uint8_t> signature;          // ASN.1 DER-encoded ECDSA signature
    // Raw signed body (curveType..ECPoint) — needed to re-verify the signature.
    std::vector<uint8_t> signedParams;
};

class ServerKeyExchangeCodec {
public:
    static bool Decode(const uint8_t* data, size_t size, ServerKeyExchange& out);
};

// ---------------------------------------------------------------------------
// ClientKeyExchange (ECDHE) — opaque ECPoint (uncompressed) preceded by 1-byte length
// ---------------------------------------------------------------------------
struct ClientKeyExchange {
    std::vector<uint8_t> publicPoint; // uncompressed (0x04 || X || Y)
};

class ClientKeyExchangeCodec {
public:
    static std::vector<uint8_t> Encode(const ClientKeyExchange& m);
};

// ---------------------------------------------------------------------------
// CertificateVerify (TLS 1.2)
//   SignatureAndHashAlgorithm
//   opaque signature<0..2^16-1>
// ---------------------------------------------------------------------------
struct CertificateVerify {
    uint8_t              hashAlgorithm;      // 4 = SHA256
    uint8_t              signatureAlgorithm; // 3 = ECDSA
    std::vector<uint8_t> signature;          // DER-encoded ECDSA signature
};

class CertificateVerifyCodec {
public:
    static std::vector<uint8_t> Encode(const CertificateVerify& m);
};

// ---------------------------------------------------------------------------
// Finished — verify_data only (12 bytes for TLS 1.2 default PRF)
// ---------------------------------------------------------------------------
struct Finished {
    uint8_t verifyData[kVerifyDataLength];
};

class FinishedCodec {
public:
    static std::vector<uint8_t> Encode(const Finished& m);
    static bool Decode(const uint8_t* data, size_t size, Finished& out);
};

}}}} // namespace vianigram::voip::infrastructure::dtls
