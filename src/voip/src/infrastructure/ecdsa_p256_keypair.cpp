// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// ecdsa_p256_keypair --- WP8.1 implementation backed by
// Windows::Security::Cryptography::Core (ECDsaP256Sha256).
//
// The platform exposes ECDSA signing as raw r||s (64 bytes for P-256). For
// X.509 / DTLS we need DER-encoded ECDSA-Sig-Value:
//     SEQUENCE { r INTEGER, s INTEGER }
// This file converts between the two.
//
// X.509 v3 self-signed cert generation is hand-rolled in DER form because
// WP8.1's WinRT API set does not expose certificate building.  The shape:
//
//   Certificate ::= SEQUENCE {
//       tbsCertificate       TBSCertificate,
//       signatureAlgorithm   AlgorithmIdentifier,    -- ecdsa-with-SHA256
//       signatureValue       BIT STRING               -- DER ECDSA-Sig-Value
//   }
//
//   TBSCertificate ::= SEQUENCE {
//       [0] EXPLICIT INTEGER (2)            -- v3
//       INTEGER                              -- serialNumber (random 8 bytes)
//       AlgorithmIdentifier                  -- ecdsa-with-SHA256
//       Name                                 -- issuer = "CN=Vianigram"
//       SEQUENCE { UTCTime, UTCTime }       -- validity (notBefore, notAfter)
//       Name                                 -- subject = "CN=Vianigram"
//       SubjectPublicKeyInfo                 -- ecPublicKey + P-256 + (04|X|Y)
//   }
//
// We DO NOT include a v3 extensions block; minimal cert is sufficient for
// DTLS / tgcalls fingerprinting (the fingerprint just needs to be a stable
// hash over the entire DER blob).

#include "ecdsa_p256_keypair.h"

#include "../internal/voip_log.h"

#include <robuffer.h>
#include <wrl.h>

#include <ctime>
#include <cstring>
#include <string>
#include <vector>

using namespace Microsoft::WRL;
using namespace Windows::Foundation;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Storage::Streams;

namespace vianigram { namespace voip { namespace infrastructure {

// =========================================================================
// IBuffer helpers
// =========================================================================
namespace {

IBuffer^ ToIBuffer(const uint8_t* data, size_t len) {
    auto arr = ref new Platform::Array<uint8>((unsigned int)len);
    if (len > 0 && data != nullptr) {
        std::memcpy(arr->Data, data, len);
    }
    return CryptographicBuffer::CreateFromByteArray(arr);
}

std::vector<uint8_t> FromIBuffer(IBuffer^ buffer) {
    if (buffer == nullptr || buffer->Length == 0) return std::vector<uint8_t>();
    Platform::Array<uint8>^ arr = nullptr;
    CryptographicBuffer::CopyToByteArray(buffer, &arr);
    if (arr == nullptr || arr->Length == 0) return std::vector<uint8_t>();
    std::vector<uint8_t> out(arr->Length);
    std::memcpy(&out[0], arr->Data, arr->Length);
    return out;
}

// =========================================================================
// Minimal SHA-256 (used only for fingerprint and TBS hashing).
// We avoid pulling in the project's own SHA-256 to keep this module
// self-contained; CryptographicEngine handles it for us via HashAlgorithmProvider.
// =========================================================================
std::vector<uint8_t> Sha256Bytes(const std::vector<uint8_t>& data) {
    auto provider = HashAlgorithmProvider::OpenAlgorithm(HashAlgorithmNames::Sha256);
    auto hasher = provider->CreateHash();
    hasher->Append(ToIBuffer(data.empty() ? nullptr : &data[0], data.size()));
    return FromIBuffer(hasher->GetValueAndReset());
}

// =========================================================================
// ASN.1 DER encoder
// =========================================================================
class Asn1Builder {
public:
    Asn1Builder() {}

    void WriteRaw(const uint8_t* data, size_t len) {
        if (len > 0) m_out.insert(m_out.end(), data, data + len);
    }
    void WriteRaw(const std::vector<uint8_t>& v) {
        WriteRaw(v.empty() ? nullptr : &v[0], v.size());
    }

    void WriteBytes(uint8_t tag, const uint8_t* data, size_t len) {
        m_out.push_back(tag);
        WriteLength(len);
        WriteRaw(data, len);
    }
    void WriteBytes(uint8_t tag, const std::vector<uint8_t>& v) {
        WriteBytes(tag, v.empty() ? nullptr : &v[0], v.size());
    }

    void WriteInteger(const uint8_t* data, size_t len) {
        // INTEGER (0x02). DER requires:
        //  * no leading zero bytes EXCEPT a single 0x00 to disambiguate
        //    positive numbers whose high bit is set.
        //  * if value is 0, encode a single 0x00.
        size_t start = 0;
        while (start + 1 < len && data[start] == 0x00 && (data[start + 1] & 0x80) == 0) {
            start++;
        }
        std::vector<uint8_t> body;
        if (len == 0) {
            body.push_back(0x00);
        } else {
            if ((data[start] & 0x80) != 0) {
                body.push_back(0x00);
            }
            body.insert(body.end(), data + start, data + len);
        }
        WriteBytes(0x02, body);
    }
    void WriteInteger(const std::vector<uint8_t>& v) {
        WriteInteger(v.empty() ? nullptr : &v[0], v.size());
    }
    void WriteIntegerSmall(int64_t value) {
        // Big-endian, minimal representation.
        uint8_t buf[8];
        int n = 0;
        bool negative = value < 0;
        uint64_t u = (uint64_t)value;
        // Pull bytes most-significant first.
        for (int i = 7; i >= 0; --i) {
            buf[n++] = (uint8_t)((u >> (i * 8)) & 0xFF);
        }
        // Trim leading 0x00 (positive) or 0xFF (negative) while preserving sign bit.
        size_t start = 0;
        if (negative) {
            while (start + 1 < (size_t)n
                && buf[start] == 0xFF
                && (buf[start + 1] & 0x80) != 0) {
                start++;
            }
        } else {
            while (start + 1 < (size_t)n
                && buf[start] == 0x00
                && (buf[start + 1] & 0x80) == 0) {
                start++;
            }
        }
        WriteInteger(buf + start, (size_t)n - start);
    }

    void WriteOidRaw(const uint8_t* der, size_t len) {
        // Pass-through: caller already provides the OID bytes.
        WriteBytes(0x06, der, len);
    }

    void WriteUtcTime(time_t t) {
        struct tm tmv;
        // gmtime_s on MSVC; threadsafe.
        gmtime_s(&tmv, &t);
        char buf[16];
        // YYMMDDHHMMSSZ -- 13 chars.
        int yy = (tmv.tm_year + 1900) % 100;
        sprintf_s(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ",
            yy,
            tmv.tm_mon + 1,
            tmv.tm_mday,
            tmv.tm_hour,
            tmv.tm_min,
            tmv.tm_sec);
        WriteBytes(0x17, (const uint8_t*)buf, 13);
    }

    void WriteBitString(const uint8_t* data, size_t len, uint8_t unusedBits) {
        // 0x03 LEN UNUSED VALUE
        std::vector<uint8_t> body;
        body.reserve(len + 1);
        body.push_back(unusedBits);
        if (len > 0) body.insert(body.end(), data, data + len);
        WriteBytes(0x03, body);
    }
    void WriteBitString(const std::vector<uint8_t>& v) {
        WriteBitString(v.empty() ? nullptr : &v[0], v.size(), 0);
    }

    void WriteOctetString(const std::vector<uint8_t>& v) {
        WriteBytes(0x04, v);
    }

    // BeginConstructed / EndConstructed: write a SEQUENCE/SET/[n] EXPLICIT tag
    // with computed length around content emitted between the calls.
    size_t BeginConstructed(uint8_t tag) {
        m_out.push_back(tag);
        // Reserve a placeholder for the length -- worst case 5 bytes
        // (0x84 + 4-byte big-endian length).  We'll patch it in End.
        m_pendingLengthOffsets.push_back(m_out.size());
        m_out.push_back(0x00);  // single placeholder; we'll insert more if needed
        return m_pendingLengthOffsets.size();
    }
    void EndConstructed() {
        size_t lengthOffset = m_pendingLengthOffsets.back();
        m_pendingLengthOffsets.pop_back();
        size_t contentLen = m_out.size() - (lengthOffset + 1);

        // Build the proper length encoding.
        std::vector<uint8_t> lenBytes;
        EncodeLength(contentLen, lenBytes);

        // Replace the single placeholder byte at lengthOffset with lenBytes.
        // Insert any extra bytes needed.
        if (lenBytes.size() == 1) {
            m_out[lengthOffset] = lenBytes[0];
        } else {
            // Replace placeholder + insert extra bytes.
            m_out[lengthOffset] = lenBytes[0];
            m_out.insert(m_out.begin() + (lengthOffset + 1),
                lenBytes.begin() + 1, lenBytes.end());
        }
    }

    std::vector<uint8_t> Take() { return m_out; }
    const std::vector<uint8_t>& Bytes() const { return m_out; }

private:
    void WriteLength(size_t len) {
        std::vector<uint8_t> tmp;
        EncodeLength(len, tmp);
        WriteRaw(tmp);
    }
    static void EncodeLength(size_t len, std::vector<uint8_t>& out) {
        if (len < 0x80) {
            out.push_back((uint8_t)len);
            return;
        }
        // long form: 0x80 | N, then N big-endian bytes
        uint8_t bytes[8];
        int n = 0;
        size_t v = len;
        while (v > 0) {
            bytes[n++] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
        out.push_back((uint8_t)(0x80 | n));
        for (int i = n - 1; i >= 0; --i) out.push_back(bytes[i]);
    }

    std::vector<uint8_t> m_out;
    std::vector<size_t> m_pendingLengthOffsets;
};

// =========================================================================
// OID byte sequences (raw value bytes, not including 0x06 + length).
// =========================================================================
//   ecPublicKey      1.2.840.10045.2.1     -> 2A 86 48 CE 3D 02 01
//   prime256v1       1.2.840.10045.3.1.7   -> 2A 86 48 CE 3D 03 01 07
//   ecdsa-with-SHA256 1.2.840.10045.4.3.2  -> 2A 86 48 CE 3D 04 03 02
//   commonName       2.5.4.3                -> 55 04 03
const uint8_t OID_EC_PUBKEY[]  = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const uint8_t OID_PRIME256V1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const uint8_t OID_ECDSA_SHA256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const uint8_t OID_COMMON_NAME[] = { 0x55, 0x04, 0x03 };

// =========================================================================
// Convert raw r||s (64 bytes) into DER ECDSA-Sig-Value.
//   SEQUENCE { r INTEGER, s INTEGER }
// =========================================================================
std::vector<uint8_t> RawRsToDer(const std::vector<uint8_t>& rawRs) {
    if (rawRs.size() != 64) return std::vector<uint8_t>();
    Asn1Builder b;
    b.BeginConstructed(0x30);
    b.WriteInteger(&rawRs[0], 32);
    b.WriteInteger(&rawRs[32], 32);
    b.EndConstructed();
    return b.Take();
}

// =========================================================================
// Detect whether a buffer is already a DER ECDSA-Sig-Value (`30 ...`) vs
// raw r||s.  Some platforms emit DER; WP8.1 emits raw r||s.  Either way, the
// caller wants DER.
// =========================================================================
std::vector<uint8_t> NormalizeEcdsaSignatureToDer(const std::vector<uint8_t>& sig) {
    if (sig.size() == 64) {
        return RawRsToDer(sig);
    }
    // Heuristic: looks like DER if first byte is SEQUENCE and length is sane.
    if (sig.size() >= 8 && sig[0] == 0x30) {
        return sig;
    }
    // Fallback: try interpreting as raw r||s of common sizes (some libs pad).
    if (sig.size() == 64) {
        return RawRsToDer(sig);
    }
    return sig;
}

// =========================================================================
// Extract uncompressed EC point (0x04 || X || Y, 65 bytes) from
// X509SubjectPublicKeyInfo blob exported by the platform.
// SPKI shape:
//   SEQUENCE {
//       AlgorithmIdentifier { OID ecPublicKey, OID prime256v1 },
//       BIT STRING { 0x00 | 0x04 X(32) Y(32) }
//   }
// We don't fully parse; we walk to the BIT STRING contents and skip the
// "unused bits" byte, returning the 65-byte point.
// =========================================================================
std::vector<uint8_t> ExtractUncompressedPointFromSpki(const std::vector<uint8_t>& spki) {
    // Search for the marker 0x03 0x42 0x00 0x04 (BIT STRING, len 0x42 = 66,
    // unused bits = 0, EC point uncompressed prefix 0x04). This is the
    // canonical encoding for a P-256 SPKI public key portion.
    for (size_t i = 0; i + 67 <= spki.size(); i++) {
        if (spki[i]     == 0x03
         && spki[i + 1] == 0x42
         && spki[i + 2] == 0x00
         && spki[i + 3] == 0x04) {
            std::vector<uint8_t> out(65);
            std::memcpy(&out[0], &spki[i + 3], 65);
            return out;
        }
    }
    return std::vector<uint8_t>();
}

// =========================================================================
// Build the AlgorithmIdentifier SEQUENCE for ecdsa-with-SHA256.
//   SEQUENCE { OID 1.2.840.10045.4.3.2 }
// (No parameters per RFC 5758.)
// =========================================================================
void EmitEcdsaSha256AlgId(Asn1Builder& b) {
    b.BeginConstructed(0x30);
    b.WriteOidRaw(OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256));
    b.EndConstructed();
}

// =========================================================================
// Build the SubjectPublicKeyInfo for our P-256 point.
//   SEQUENCE {
//       SEQUENCE { OID ecPublicKey, OID prime256v1 },
//       BIT STRING { 0x00 | uncompressed point }
//   }
// =========================================================================
void EmitSubjectPublicKeyInfo(Asn1Builder& b, const std::vector<uint8_t>& point) {
    b.BeginConstructed(0x30);
    {
        b.BeginConstructed(0x30);
        b.WriteOidRaw(OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY));
        b.WriteOidRaw(OID_PRIME256V1, sizeof(OID_PRIME256V1));
        b.EndConstructed();

        b.WriteBitString(point.empty() ? nullptr : &point[0], point.size(), 0);
    }
    b.EndConstructed();
}

// =========================================================================
// Build a Name = "CN=Vianigram":
//   SEQUENCE {
//       SET {
//           SEQUENCE { OID 2.5.4.3, UTF8String "Vianigram" }
//       }
//   }
// =========================================================================
void EmitNameCnVianigram(Asn1Builder& b) {
    static const char* kCn = "Vianigram";
    size_t cnLen = std::strlen(kCn);

    b.BeginConstructed(0x30);  // Name (SEQUENCE OF RDN)
    {
        b.BeginConstructed(0x31);  // RDN (SET)
        {
            b.BeginConstructed(0x30);  // AttributeTypeAndValue
            b.WriteOidRaw(OID_COMMON_NAME, sizeof(OID_COMMON_NAME));
            // UTF8String tag = 0x0C
            b.WriteBytes(0x0C, (const uint8_t*)kCn, cnLen);
            b.EndConstructed();
        }
        b.EndConstructed();
    }
    b.EndConstructed();
}

// =========================================================================
// Generate 8 random bytes for the cert serial number.
// =========================================================================
std::vector<uint8_t> RandomSerial() {
    auto buf = CryptographicBuffer::GenerateRandom(8);
    std::vector<uint8_t> out = FromIBuffer(buf);
    if (out.empty()) {
        out.assign(8, 0);
    }
    // Force MSB clear so the INTEGER stays positive (DER trims leading 0x00
    // when MSB clear, which is fine and produces a smaller cert).
    out[0] &= 0x7F;
    // But also make sure we don't accidentally produce a zero serial.
    if (out[0] == 0x00) out[0] = 0x01;
    return out;
}

} // anonymous namespace

// =========================================================================
// Impl pinning the platform CryptographicKey.
// =========================================================================
class EcdsaP256KeyPair::Impl {
public:
    Impl(CryptographicKey^ key) : Key(key) {}
    CryptographicKey^ Key;
};

EcdsaP256KeyPair::EcdsaP256KeyPair(std::unique_ptr<EcdsaP256KeyPair::Impl> impl)
    : m_impl(std::move(impl)) {}

EcdsaP256KeyPair::~EcdsaP256KeyPair() {}

std::unique_ptr<EcdsaP256KeyPair> EcdsaP256KeyPair::Generate() {
    try {
        auto provider = AsymmetricKeyAlgorithmProvider::OpenAlgorithm(
            AsymmetricAlgorithmNames::EcdsaP256Sha256);
        auto key = provider->CreateKeyPair(256);
        if (key == nullptr) return std::unique_ptr<EcdsaP256KeyPair>();
        std::unique_ptr<Impl> impl(new Impl(key));
        return std::unique_ptr<EcdsaP256KeyPair>(new EcdsaP256KeyPair(std::move(impl)));
    } catch (Platform::Exception^ ex) {
        vianigram::voip::internal::DebugLog(L"EcdsaP256KeyPair::Generate failed");
        (void)ex;
        return std::unique_ptr<EcdsaP256KeyPair>();
    }
}

std::vector<uint8_t> EcdsaP256KeyPair::SignSha256(const uint8_t* hash, size_t hashLen) {
    if (m_impl == nullptr || m_impl->Key == nullptr) return std::vector<uint8_t>();
    if (hash == nullptr || hashLen != 32) return std::vector<uint8_t>();
    try {
        auto hashBuf = ToIBuffer(hash, hashLen);
        auto sigBuf = CryptographicEngine::SignHashedData(m_impl->Key, hashBuf);
        std::vector<uint8_t> raw = FromIBuffer(sigBuf);
        // WP8.1 returns raw r||s for ECDsaP256Sha256; normalize to DER.
        return NormalizeEcdsaSignatureToDer(raw);
    } catch (Platform::Exception^ ex) {
        (void)ex;
        return std::vector<uint8_t>();
    }
}

std::vector<uint8_t> EcdsaP256KeyPair::GetPublicKeyUncompressed() {
    if (m_impl == nullptr || m_impl->Key == nullptr) return std::vector<uint8_t>();
    try {
        auto spkiBuf = m_impl->Key->ExportPublicKey(
            CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo);
        std::vector<uint8_t> spki = FromIBuffer(spkiBuf);
        return ExtractUncompressedPointFromSpki(spki);
    } catch (Platform::Exception^ ex) {
        (void)ex;
        return std::vector<uint8_t>();
    }
}

std::vector<uint8_t> EcdsaP256KeyPair::ToX509SelfSignedDer() {
    if (m_impl == nullptr || m_impl->Key == nullptr) return std::vector<uint8_t>();

    std::vector<uint8_t> point = GetPublicKeyUncompressed();
    if (point.size() != 65 || point[0] != 0x04) return std::vector<uint8_t>();

    std::vector<uint8_t> serial = RandomSerial();

    time_t now = std::time(nullptr);
    time_t expires = now + 365LL * 24 * 60 * 60;  // 1 year

    // ----- TBS (the part we sign) -----
    Asn1Builder tbs;
    tbs.BeginConstructed(0x30);  // TBSCertificate
    {
        // [0] EXPLICIT INTEGER 2  (v3)
        tbs.BeginConstructed(0xA0);
        tbs.WriteIntegerSmall(2);
        tbs.EndConstructed();

        // serialNumber INTEGER
        tbs.WriteInteger(serial);

        // signature AlgorithmIdentifier (must match outer)
        EmitEcdsaSha256AlgId(tbs);

        // issuer Name
        EmitNameCnVianigram(tbs);

        // validity SEQUENCE { UTCTime, UTCTime }
        tbs.BeginConstructed(0x30);
        tbs.WriteUtcTime(now);
        tbs.WriteUtcTime(expires);
        tbs.EndConstructed();

        // subject Name
        EmitNameCnVianigram(tbs);

        // subjectPublicKeyInfo
        EmitSubjectPublicKeyInfo(tbs, point);
    }
    tbs.EndConstructed();
    std::vector<uint8_t> tbsBytes = tbs.Take();

    // ----- Sign SHA-256(TBS) with the private key -----
    std::vector<uint8_t> tbsHash = Sha256Bytes(tbsBytes);
    if (tbsHash.size() != 32) return std::vector<uint8_t>();
    std::vector<uint8_t> signatureDer = SignSha256(&tbsHash[0], tbsHash.size());
    if (signatureDer.empty()) return std::vector<uint8_t>();

    // ----- Outer Certificate SEQUENCE -----
    Asn1Builder cert;
    cert.BeginConstructed(0x30);  // Certificate
    {
        // Re-emit the TBS verbatim so signature matches what we hashed.
        cert.WriteRaw(tbsBytes);
        // signatureAlgorithm
        EmitEcdsaSha256AlgId(cert);
        // signatureValue BIT STRING (0 unused bits, contents = DER ECDSA-Sig-Value)
        cert.WriteBitString(&signatureDer[0], signatureDer.size(), 0);
    }
    cert.EndConstructed();

    return cert.Take();
}

std::string EcdsaP256KeyPair::ToSha256Fingerprint() {
    std::vector<uint8_t> cert = ToX509SelfSignedDer();
    if (cert.empty()) return std::string();
    std::vector<uint8_t> hash = Sha256Bytes(cert);
    if (hash.size() != 32) return std::string();

    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(32 * 3 - 1);  // 95 chars
    for (size_t i = 0; i < hash.size(); i++) {
        if (i > 0) out.push_back(':');
        out.push_back(kHex[hash[i] >> 4]);
        out.push_back(kHex[hash[i] & 0x0F]);
    }
    return out;
}

}}} // namespace vianigram::voip::infrastructure
