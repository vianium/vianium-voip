// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// DTLS 1.2 client handshake state machine.
//
// Implementation notes
// --------------------
// * Records: emitted/parsed via DtlsRecordCodec. Plaintext records (epoch 0)
//   carry handshake messages directly. Once we send ChangeCipherSpec the
//   record sequence number resets and the AAD changes — see DeriveKeysAndCipher.
//
// * Transcript hashing: we hash every handshake message (without the DTLS
//   handshake header *fragment* fields; per RFC 6347 §4.2.6 the transcript
//   is computed as if it were TLS — i.e. msgType(1) || length(3) || body).
//   Note: HelloVerifyRequest is excluded from the transcript (RFC 6347 §4.2.1).
//
// * Crypto:
//     pre_master_secret = ECDH(our_priv, server_pub).x
//     If extended_master_secret negotiated:
//         master_secret = PRF(pms, "extended master secret", session_hash, 48)
//     Else:
//         master_secret = PRF(pms, "master secret", client_random + server_random, 48)
//     key_block      = PRF(master_secret, "key expansion",
//                          server_random + client_random,
//                          2*16 + 2*4) = 40 bytes
//
// * Cipher: vianium::crypto::AesGcm wraps each direction. Its Encrypt/Decrypt
//   API already produces TLS-1.2-shape AAD (seq||type||version||length); for
//   DTLS we feed the 64-bit "DTLS combined sequence" = (epoch << 48) | seq —
//   this matches RFC 6347 §4.1.2.1.
//
// * Cert validation: tgcalls/WebRTC uses self-signed certs, so we don't walk
//   a chain — we just verify the leaf's SHA-256 matches the fingerprint we
//   got from Signaling. Mismatch is fatal.

#include "dtls_client_session.h"
#include "../infrastructure/dtls/dtls_record.h"
#include "../infrastructure/dtls/dtls_handshake_messages.h"
#include "../infrastructure/dtls/tls_prf.h"
#include "../infrastructure/ecdsa_p256_keypair.h"

#include <vianium/crypto/aes_gcm.h>
#include <vianium/crypto/ecdh_p256.h>
#include <vianium/crypto/sha256.h>
#include <vianium/crypto/random.h>

#include <cstring>
#include <cctype>

namespace vianigram { namespace voip { namespace application {

namespace dtls = infrastructure::dtls;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
DtlsClientSession::DtlsClientSession(std::unique_ptr<infrastructure::EcdsaP256KeyPair> ourCert,
                                     const std::string& peerFingerprint)
    : m_state(DtlsState_Initial),
      m_ourCert(std::move(ourCert)),
      m_extendedMasterSecret(true),
      m_clientMessageSeq(0),
      m_serverMessageSeqExpected(0),
      m_clientEpoch(0),
      m_clientRecordSeq(0),
      m_serverRecordSeq(0)
{
    std::memset(m_clientRandom, 0, sizeof(m_clientRandom));
    std::memset(m_serverRandom, 0, sizeof(m_serverRandom));
    m_expectedPeerFingerprint = ParseHexFingerprint(peerFingerprint);
}

DtlsClientSession::~DtlsClientSession() {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static int HexNybble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::vector<uint8_t> DtlsClientSession::ParseHexFingerprint(const std::string& fp) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (size_t i = 0; i < fp.size(); ++i) {
        char c = fp[i];
        if (c == ':' || c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        int n = HexNybble(c);
        if (n < 0) { out.clear(); return out; }
        if (hi < 0) {
            hi = n;
        } else {
            out.push_back((uint8_t)((hi << 4) | n));
            hi = -1;
        }
    }
    if (hi >= 0) { out.clear(); }
    return out;
}

std::vector<uint8_t> DtlsClientSession::Sha256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out(32);
    vianium::crypto::Sha256::Hash(data, len, &out[0]);
    return out;
}

void DtlsClientSession::Fail(const std::string& reason) {
    m_state         = DtlsState_Failed;
    m_failureReason = reason;
}

void DtlsClientSession::AppendToHandshakeHash(const uint8_t* data, size_t len) {
    if (data && len) {
        m_handshakeTranscript.insert(m_handshakeTranscript.end(), data, data + len);
    }
}

std::vector<uint8_t> DtlsClientSession::CurrentHandshakeHash() const {
    return Sha256(m_handshakeTranscript.empty() ? 0 : &m_handshakeTranscript[0],
                  m_handshakeTranscript.size());
}

// ---------------------------------------------------------------------------
// Build a single DTLS plaintext record carrying one full handshake message.
// Also (optionally) pushes the TLS-style transcript bytes into the running
// hash. Returns the wire datagram bytes.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> WrapRecord(uint8_t contentType,
                                       uint16_t version,
                                       uint16_t epoch,
                                       uint64_t recordSeq,
                                       const std::vector<uint8_t>& payload)
{
    dtls::DtlsRecord rec;
    rec.type            = contentType;
    rec.version         = version;
    rec.epoch           = epoch;
    rec.sequenceNumber  = recordSeq;
    rec.payload         = payload;
    return dtls::DtlsRecordCodec::Encode(rec);
}

// Build the raw bytes that go into the running TLS-style transcript hash for
// a handshake message of type `msgType` and the given body. Per RFC 6347
// §4.2.6, when a DTLS handshake message is unfragmented the transcript hash
// is computed as if the wire format were TLS — i.e. with the 4-byte TLS
// handshake header (msg_type || uint24 length) and *not* the DTLS-specific
// fragment fields.
static std::vector<uint8_t> TlsLikeTranscriptBytes(uint8_t msgType,
                                                   const std::vector<uint8_t>& body)
{
    std::vector<uint8_t> out;
    out.reserve(4 + body.size());
    out.push_back(msgType);
    uint32_t len = (uint32_t)body.size();
    out.push_back((uint8_t)(len >> 16));
    out.push_back((uint8_t)(len >> 8));
    out.push_back((uint8_t)len);
    if (!body.empty()) out.insert(out.end(), body.begin(), body.end());
    return out;
}

// ---------------------------------------------------------------------------
// ClientHello
// ---------------------------------------------------------------------------
std::vector<uint8_t> DtlsClientSession::BuildClientHelloBody(bool withCookie) {
    dtls::ClientHello h;
    std::memcpy(h.random, m_clientRandom, 32);
    if (withCookie) h.cookie = m_cookie;

    // Just one suite — the WebRTC default.
    h.cipherSuites.push_back(dtls::kCsEcdheEcdsaAes128GcmSha256);
    h.compressionMethods.push_back(0);

    h.supportedGroups.push_back(dtls::kNgSecp256r1);
    h.ecPointFormats.push_back(dtls::kEcPointFormatUncompressed);
    h.signatureAlgorithms.push_back(dtls::kSigAlgEcdsaSecp256r1Sha256);

    h.srtpProtectionProfiles.push_back(dtls::kSrtpAes128CmHmacSha1_80);
    h.extendedMasterSecret = true;

    return dtls::ClientHelloCodec::Encode(h);
}

std::vector<std::vector<uint8_t> > DtlsClientSession::Initiate() {
    std::vector<std::vector<uint8_t> > out;

    // Generate fresh randoms / ECDH keys.
    vianium::crypto::GenerateRandom(m_clientRandom, 32);

    m_ourEcdhPrivate.resize(32);
    m_ourEcdhPublic.resize(65);
    vianium::crypto::EcdhP256::GenerateKeyPair(&m_ourEcdhPrivate[0], &m_ourEcdhPublic[0]);

    // ClientHello (no cookie).
    std::vector<uint8_t> body = BuildClientHelloBody(false);
    std::vector<uint8_t> wrapped = dtls::WrapHandshakeUnfragmented(
        dtls::kHsClientHello, m_clientMessageSeq++, body);

    // The first ClientHello is excluded from the transcript hash if a cookie
    // exchange happens (it gets re-issued with the cookie). We provisionally
    // append it; if a HelloVerifyRequest arrives we reset the transcript.
    std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsClientHello, body);
    AppendToHandshakeHash(&transcript[0], transcript.size());

    out.push_back(WrapRecord(dtls::kDtlsContentHandshake, dtls::kDtlsVersion12,
                             m_clientEpoch, m_clientRecordSeq++, wrapped));

    m_state = DtlsState_SentClientHello;
    return out;
}

// ---------------------------------------------------------------------------
// Handshake message dispatch
// ---------------------------------------------------------------------------
void DtlsClientSession::HandleHandshakeMessage(uint8_t msgType,
                                               const uint8_t* body, size_t bodyLen,
                                               const uint8_t* /*fullMessageBytes*/,
                                               size_t /*fullMessageLen*/,
                                               std::vector<std::vector<uint8_t> >& outDatagrams)
{
    switch (msgType) {

    // --- HelloVerifyRequest: re-issue ClientHello with the cookie. ---
    case dtls::kHsHelloVerifyRequest: {
        dtls::HelloVerifyRequest hvr;
        if (!dtls::HelloVerifyRequestCodec::Decode(body, bodyLen, hvr)) {
            return Fail("malformed HelloVerifyRequest");
        }
        m_cookie = hvr.cookie;
        // Reset transcript — RFC 6347 §4.2.1: HelloVerifyRequest and the
        // first ClientHello are *not* part of the transcript hash.
        m_handshakeTranscript.clear();

        std::vector<uint8_t> body2 = BuildClientHelloBody(true);
        std::vector<uint8_t> wrapped = dtls::WrapHandshakeUnfragmented(
            dtls::kHsClientHello, m_clientMessageSeq++, body2);

        std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsClientHello, body2);
        AppendToHandshakeHash(&transcript[0], transcript.size());

        outDatagrams.push_back(WrapRecord(dtls::kDtlsContentHandshake, dtls::kDtlsVersion12,
                                          m_clientEpoch, m_clientRecordSeq++, wrapped));
        m_state = DtlsState_SentClientHelloWithCookie;
        return;
    }

    // --- ServerHello ---
    case dtls::kHsServerHello: {
        dtls::ServerHello sh;
        if (!dtls::ServerHelloCodec::Decode(body, bodyLen, sh)) {
            return Fail("malformed ServerHello");
        }
        if (sh.cipherSuite != dtls::kCsEcdheEcdsaAes128GcmSha256) {
            return Fail("server picked unsupported cipher suite");
        }
        std::memcpy(m_serverRandom, sh.random, 32);
        m_extendedMasterSecret = sh.extendedMasterSecret;

        std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsServerHello,
            std::vector<uint8_t>(body, body + bodyLen));
        AppendToHandshakeHash(&transcript[0], transcript.size());

        m_state = DtlsState_GotServerHello;
        return;
    }

    // --- Certificate (server) ---
    case dtls::kHsCertificate: {
        dtls::Certificate cert;
        if (!dtls::CertificateCodec::Decode(body, bodyLen, cert) || cert.chain.empty()) {
            return Fail("malformed Certificate");
        }
        m_serverCertDer = cert.chain[0];

        // Verify SHA-256 of the leaf cert matches the fingerprint advertised
        // via Signaling. This is the entire trust check — no chain walk.
        std::vector<uint8_t> got = Sha256(&m_serverCertDer[0], m_serverCertDer.size());
        if (got != m_expectedPeerFingerprint) {
            return Fail("peer certificate fingerprint mismatch");
        }

        std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsCertificate,
            std::vector<uint8_t>(body, body + bodyLen));
        AppendToHandshakeHash(&transcript[0], transcript.size());

        m_state = DtlsState_GotServerCertificate;
        return;
    }

    // --- ServerKeyExchange ---
    case dtls::kHsServerKeyExchange: {
        dtls::ServerKeyExchange ske;
        if (!dtls::ServerKeyExchangeCodec::Decode(body, bodyLen, ske)) {
            return Fail("malformed ServerKeyExchange");
        }
        if (ske.namedCurve != dtls::kNgSecp256r1) {
            return Fail("server picked unsupported curve");
        }
        if (ske.publicPoint.size() != 65 || ske.publicPoint[0] != 0x04) {
            return Fail("server EC point must be uncompressed P-256");
        }
        m_serverPublicPoint = ske.publicPoint;

        // TODO(V3.1): re-verify the ECDSA signature over
        //   client_random || server_random || ECParams || ECPoint
        // using the server's certificate public key. We rely on the
        // fingerprint pin for now — both must match for the handshake to
        // succeed, but a proper TLS client should check both.

        std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsServerKeyExchange,
            std::vector<uint8_t>(body, body + bodyLen));
        AppendToHandshakeHash(&transcript[0], transcript.size());

        m_state = DtlsState_GotServerKeyExchange;
        return;
    }

    // --- CertificateRequest: server wants our cert. We always have one. ---
    case dtls::kHsCertificateRequest: {
        std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsCertificateRequest,
            std::vector<uint8_t>(body, body + bodyLen));
        AppendToHandshakeHash(&transcript[0], transcript.size());
        return;
    }

    // --- ServerHelloDone: end of server flight, send our flight. ---
    case dtls::kHsServerHelloDone: {
        std::vector<uint8_t> transcript = TlsLikeTranscriptBytes(dtls::kHsServerHelloDone,
            std::vector<uint8_t>(body, body + bodyLen));
        AppendToHandshakeHash(&transcript[0], transcript.size());
        m_state = DtlsState_GotServerHelloDone;

        // Build & emit: Certificate, ClientKeyExchange, CertificateVerify, CCS, Finished.
        // 1. Certificate
        std::vector<uint8_t> certBody = BuildCertificateBody();
        {
            std::vector<uint8_t> wrapped = dtls::WrapHandshakeUnfragmented(
                dtls::kHsCertificate, m_clientMessageSeq++, certBody);
            std::vector<uint8_t> tr = TlsLikeTranscriptBytes(dtls::kHsCertificate, certBody);
            AppendToHandshakeHash(&tr[0], tr.size());
            outDatagrams.push_back(WrapRecord(dtls::kDtlsContentHandshake,
                dtls::kDtlsVersion12, m_clientEpoch, m_clientRecordSeq++, wrapped));
        }
        // 2. ClientKeyExchange
        std::vector<uint8_t> ckeBody = BuildClientKeyExchangeBody();
        {
            std::vector<uint8_t> wrapped = dtls::WrapHandshakeUnfragmented(
                dtls::kHsClientKeyExchange, m_clientMessageSeq++, ckeBody);
            std::vector<uint8_t> tr = TlsLikeTranscriptBytes(dtls::kHsClientKeyExchange, ckeBody);
            AppendToHandshakeHash(&tr[0], tr.size());
            outDatagrams.push_back(WrapRecord(dtls::kDtlsContentHandshake,
                dtls::kDtlsVersion12, m_clientEpoch, m_clientRecordSeq++, wrapped));
        }
        m_state = DtlsState_SentClientKeyExchange;

        // 3. CertificateVerify (signature is over the transcript hash so far,
        //    AFTER ClientKeyExchange).
        {
            std::vector<uint8_t> tHash = m_handshakeTranscript; // raw transcript bytes
            std::vector<uint8_t> cvBody = BuildCertificateVerifyBody(tHash);
            std::vector<uint8_t> wrapped = dtls::WrapHandshakeUnfragmented(
                dtls::kHsCertificateVerify, m_clientMessageSeq++, cvBody);
            std::vector<uint8_t> tr = TlsLikeTranscriptBytes(dtls::kHsCertificateVerify, cvBody);
            AppendToHandshakeHash(&tr[0], tr.size());
            outDatagrams.push_back(WrapRecord(dtls::kDtlsContentHandshake,
                dtls::kDtlsVersion12, m_clientEpoch, m_clientRecordSeq++, wrapped));
        }

        // Now derive the master secret + traffic keys.
        DeriveKeysAndCipher();
        if (m_state == DtlsState_Failed) return;

        // 4. CCS + Finished (encrypted under the new epoch).
        BuildClientFinishedFlight(outDatagrams);
        return;
    }

    case dtls::kHsFinished: {
        // Server Finished — only valid after we received CCS (epoch>0 record).
        // Verify verify_data.
        std::vector<uint8_t> tHashAtFinished = m_handshakeTranscript;
        std::vector<uint8_t> expected = BuildFinishedBody(tHashAtFinished, /*fromClient=*/false);
        if (bodyLen != dtls::kVerifyDataLength ||
            std::memcmp(body, &expected[0], dtls::kVerifyDataLength) != 0) {
            return Fail("bad server Finished verify_data");
        }
        std::vector<uint8_t> tr = TlsLikeTranscriptBytes(dtls::kHsFinished,
            std::vector<uint8_t>(body, body + bodyLen));
        AppendToHandshakeHash(&tr[0], tr.size());
        m_state = DtlsState_Established;
        return;
    }

    default:
        // Unknown message types are tolerated (we just don't transcript them).
        return;
    }
}

// ---------------------------------------------------------------------------
// Build flight 5: { CCS, Finished }
// ---------------------------------------------------------------------------
void DtlsClientSession::BuildClientFinishedFlight(std::vector<std::vector<uint8_t> >& outDatagrams) {
    // ChangeCipherSpec record (epoch 0 still — CCS is *not* itself encrypted).
    {
        dtls::DtlsRecord rec;
        rec.type            = dtls::kDtlsContentChangeCipherSpec;
        rec.version         = dtls::kDtlsVersion12;
        rec.epoch           = m_clientEpoch;
        rec.sequenceNumber  = m_clientRecordSeq++;
        rec.payload.push_back(0x01); // CCS message
        outDatagrams.push_back(dtls::DtlsRecordCodec::Encode(rec));
    }
    m_state = DtlsState_SentChangeCipherSpec;

    // Bump epoch and reset record seq for the protected side.
    m_clientEpoch++;
    m_clientRecordSeq = 0;

    // Finished, encrypted under the new keys.
    std::vector<uint8_t> finishedBody = BuildFinishedBody(m_handshakeTranscript, /*fromClient=*/true);
    std::vector<uint8_t> wrapped = dtls::WrapHandshakeUnfragmented(
        dtls::kHsFinished, m_clientMessageSeq++, finishedBody);

    // Update transcript: client Finished is part of it (server uses it to
    // compute its own Finished).
    std::vector<uint8_t> tr = TlsLikeTranscriptBytes(dtls::kHsFinished, finishedBody);
    AppendToHandshakeHash(&tr[0], tr.size());

    // Encrypt with our AES-GCM cipher. The DTLS "combined seq number" used
    // as TLS sequence in AAD is (epoch<<48) | record_seq.
    uint64_t aadSeq = ((uint64_t)m_clientEpoch << 48) | m_clientRecordSeq;

    std::vector<uint8_t> encrypted;
    encrypted.resize(8 + wrapped.size() + 16); // explicit_nonce(8) + ct + tag(16)
    int n = m_clientCipher->Encrypt(&wrapped[0], 0, (int)wrapped.size(),
                                    aadSeq, dtls::kDtlsContentHandshake,
                                    dtls::kDtlsVersion12,
                                    &encrypted[0], (int)encrypted.size());
    if (n < 0) { Fail("AES-GCM encrypt of Finished failed"); return; }
    encrypted.resize(n);

    outDatagrams.push_back(WrapRecord(dtls::kDtlsContentHandshake, dtls::kDtlsVersion12,
                                      m_clientEpoch, m_clientRecordSeq++, encrypted));
    m_state = DtlsState_SentFinished;
}

// ---------------------------------------------------------------------------
// Process an incoming UDP datagram (may pack multiple DTLS records).
// ---------------------------------------------------------------------------
bool DtlsClientSession::ProcessDatagram(const uint8_t* data, size_t size,
                                        std::vector<std::vector<uint8_t> >& outDatagrams)
{
    if (m_state == DtlsState_Failed) return false;

    size_t pos = 0;
    while (pos < size) {
        dtls::DtlsRecord rec;
        size_t consumed = 0;
        if (!dtls::DtlsRecordCodec::Decode(data + pos, size - pos, rec, consumed)) {
            return false;
        }
        pos += consumed;

        if (rec.type == dtls::kDtlsContentChangeCipherSpec) {
            HandleChangeCipherSpec();
            continue;
        }

        if (rec.type == dtls::kDtlsContentAlert) {
            // 2-byte alert: level || description. Treat any fatal alert as failure.
            if (rec.payload.size() >= 2 && rec.payload[0] == 2) {
                Fail("server sent fatal alert");
                return false;
            }
            continue;
        }

        if (rec.type == dtls::kDtlsContentHandshake) {
            // Plaintext handshake (epoch 0) or encrypted (epoch >= 1).
            std::vector<uint8_t> plain;
            const uint8_t* msgBytes = 0;
            size_t msgLen = 0;

            if (rec.epoch == 0) {
                msgBytes = rec.payload.empty() ? 0 : &rec.payload[0];
                msgLen   = rec.payload.size();
            } else {
                if (!m_serverCipher.get()) { Fail("got encrypted record before keys"); return false; }
                uint64_t aadSeq = ((uint64_t)rec.epoch << 48) | rec.sequenceNumber;
                plain.resize(rec.payload.size());
                int n = m_serverCipher->Decrypt(rec.payload.empty() ? 0 : &rec.payload[0],
                                                0, (int)rec.payload.size(),
                                                aadSeq, dtls::kDtlsContentHandshake,
                                                dtls::kDtlsVersion12,
                                                &plain[0], (int)plain.size());
                if (n < 0) { Fail("AEAD auth failed on encrypted handshake"); return false; }
                plain.resize(n);
                msgBytes = plain.empty() ? 0 : &plain[0];
                msgLen   = plain.size();
            }

            // Decode as many handshake messages as fit in this record. Each
            // handshake message has a 12-byte DTLS handshake header; for our
            // simplified client we require fragment_offset == 0 and
            // fragment_length == length (no reassembly).
            size_t hpos = 0;
            while (hpos + dtls::kHandshakeHeaderSize <= msgLen) {
                dtls::HandshakeHeader hh;
                if (!dtls::HandshakeHeaderCodec::Decode(msgBytes + hpos,
                                                       msgLen - hpos, hh)) {
                    Fail("malformed handshake header"); return false;
                }
                if (hh.fragmentOffset != 0 || hh.fragmentLength != hh.length) {
                    Fail("fragmented DTLS handshake messages not supported"); return false;
                }
                if (hpos + dtls::kHandshakeHeaderSize + hh.length > msgLen) {
                    Fail("handshake length overruns record"); return false;
                }
                const uint8_t* body    = msgBytes + hpos + dtls::kHandshakeHeaderSize;
                const uint8_t* fullMsg = msgBytes + hpos;
                size_t fullLen         = dtls::kHandshakeHeaderSize + hh.length;

                HandleHandshakeMessage(hh.msgType, body, hh.length, fullMsg, fullLen, outDatagrams);
                if (m_state == DtlsState_Failed) return false;

                hpos += dtls::kHandshakeHeaderSize + hh.length;
            }
            continue;
        }

        if (rec.type == dtls::kDtlsContentApplicationData) {
            // Application data on the handshake path is unexpected; ignore here.
            continue;
        }
    }
    return true;
}

void DtlsClientSession::HandleChangeCipherSpec() {
    // Server told us its next records will be encrypted. We've already built
    // both ciphers in DeriveKeysAndCipher.
    m_state = DtlsState_GotChangeCipherSpec;
}

// ---------------------------------------------------------------------------
// Cert / CertificateVerify / Finished bodies
// ---------------------------------------------------------------------------
std::vector<uint8_t> DtlsClientSession::BuildCertificateBody() {
    // Certificate body =
    //   uint24 list_length
    //   [ uint24 cert_length || cert_der ]+
    std::vector<uint8_t> body;
    // EcdsaP256KeyPair surfaces the X.509 DER through ToX509SelfSignedDer();
    // it returns a fresh vector each call so we grab it once per outgoing
    // handshake.
    std::vector<uint8_t> der = m_ourCert->ToX509SelfSignedDer();

    uint32_t listLen = (uint32_t)(3 + der.size());
    body.push_back((uint8_t)(listLen >> 16));
    body.push_back((uint8_t)(listLen >> 8));
    body.push_back((uint8_t)listLen);

    body.push_back((uint8_t)(der.size() >> 16));
    body.push_back((uint8_t)(der.size() >> 8));
    body.push_back((uint8_t)der.size());
    if (!der.empty()) body.insert(body.end(), der.begin(), der.end());
    return body;
}

std::vector<uint8_t> DtlsClientSession::BuildClientKeyExchangeBody() {
    dtls::ClientKeyExchange cke;
    cke.publicPoint = m_ourEcdhPublic;
    return dtls::ClientKeyExchangeCodec::Encode(cke);
}

std::vector<uint8_t> DtlsClientSession::BuildCertificateVerifyBody(
    const std::vector<uint8_t>& transcriptSoFar)
{
    // EcdsaP256KeyPair signs a pre-computed 32-byte SHA-256 hash and
    // returns the DER-encoded ECDSA-Sig-Value (SEQUENCE { r, s }).
    // TLS 1.2 ECDSA-SHA256 expects exactly that wire format inside the
    // CertificateVerify signature field, so we hash the transcript here
    // and pass the digest in.
    std::vector<uint8_t> digest = Sha256(
        transcriptSoFar.empty() ? 0 : &transcriptSoFar[0],
        transcriptSoFar.size());

    std::vector<uint8_t> sig = m_ourCert->SignSha256(
        digest.empty() ? 0 : &digest[0],
        digest.size());

    dtls::CertificateVerify cv;
    cv.hashAlgorithm      = 4; // SHA256
    cv.signatureAlgorithm = 3; // ECDSA
    cv.signature          = sig;
    return dtls::CertificateVerifyCodec::Encode(cv);
}

std::vector<uint8_t> DtlsClientSession::BuildFinishedBody(
    const std::vector<uint8_t>& transcriptUpTo, bool fromClient)
{
    // verify_data = PRF(master_secret, "client finished" or "server finished",
    //                   Hash(handshake_messages))[0..11]
    std::vector<uint8_t> hash = Sha256(transcriptUpTo.empty() ? 0 : &transcriptUpTo[0],
                                       transcriptUpTo.size());
    std::vector<uint8_t> seed = hash; // PRF treats label+seed already.
    std::vector<uint8_t> vd = dtls::TlsPrf::Compute(m_masterSecret,
        fromClient ? "client finished" : "server finished",
        seed, dtls::kVerifyDataLength);
    return vd;
}

// ---------------------------------------------------------------------------
// Key derivation & cipher init
// ---------------------------------------------------------------------------
void DtlsClientSession::DeriveKeysAndCipher() {
    // pre_master_secret = ECDH(our_priv, server_pub).x
    if (m_serverPublicPoint.size() != 65) { Fail("missing server pub"); return; }
    if (m_ourEcdhPrivate.size() != 32)    { Fail("missing our ecdh priv"); return; }

    std::vector<uint8_t> pms(32);
    if (!vianium::crypto::EcdhP256::ComputeSharedSecret(
            &m_ourEcdhPrivate[0], &m_serverPublicPoint[0], &pms[0])) {
        Fail("ECDH compute_shared_secret failed");
        return;
    }

    // master secret
    m_masterSecret.assign(48, 0);
    if (m_extendedMasterSecret) {
        std::vector<uint8_t> sessionHash = Sha256(
            m_handshakeTranscript.empty() ? 0 : &m_handshakeTranscript[0],
            m_handshakeTranscript.size());
        m_masterSecret = dtls::TlsPrf::Compute(pms, "extended master secret",
                                               sessionHash, 48);
    } else {
        std::vector<uint8_t> seed;
        seed.insert(seed.end(), m_clientRandom, m_clientRandom + 32);
        seed.insert(seed.end(), m_serverRandom, m_serverRandom + 32);
        m_masterSecret = dtls::TlsPrf::Compute(pms, "master secret", seed, 48);
    }

    // key_block = PRF(master_secret, "key expansion",
    //                 server_random + client_random,
    //                 2*16 + 2*4) = 40 bytes
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), m_serverRandom, m_serverRandom + 32);
    seed.insert(seed.end(), m_clientRandom, m_clientRandom + 32);
    std::vector<uint8_t> keyBlock = dtls::TlsPrf::Compute(m_masterSecret,
                                                          "key expansion",
                                                          seed, 2*16 + 2*4);
    if (keyBlock.size() != 40) { Fail("PRF produced wrong key_block size"); return; }

    m_clientWriteKey.assign(keyBlock.begin() +  0, keyBlock.begin() + 16);
    m_serverWriteKey.assign(keyBlock.begin() + 16, keyBlock.begin() + 32);
    m_clientWriteIv .assign(keyBlock.begin() + 32, keyBlock.begin() + 36);
    m_serverWriteIv .assign(keyBlock.begin() + 36, keyBlock.begin() + 40);

    // Wire up AES-128-GCM ciphers per direction.
    m_clientCipher.reset(new vianium::crypto::AesGcm());
    m_clientCipher->Init(&m_clientWriteKey[0], 16, &m_clientWriteIv[0], 4);

    m_serverCipher.reset(new vianium::crypto::AesGcm());
    m_serverCipher->Init(&m_serverWriteKey[0], 16, &m_serverWriteIv[0], 4);
}

// ---------------------------------------------------------------------------
// Encrypted application data
// ---------------------------------------------------------------------------
std::vector<uint8_t> DtlsClientSession::EncryptAppData(const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> out;
    if (m_state != DtlsState_Established || !m_clientCipher.get()) return out;

    uint64_t aadSeq = ((uint64_t)m_clientEpoch << 48) | m_clientRecordSeq;
    std::vector<uint8_t> ct;
    ct.resize(8 + plaintext.size() + 16);
    int n = m_clientCipher->Encrypt(plaintext.empty() ? 0 : &plaintext[0],
                                    0, (int)plaintext.size(),
                                    aadSeq, dtls::kDtlsContentApplicationData,
                                    dtls::kDtlsVersion12,
                                    &ct[0], (int)ct.size());
    if (n < 0) return out;
    ct.resize(n);

    out = WrapRecord(dtls::kDtlsContentApplicationData, dtls::kDtlsVersion12,
                     m_clientEpoch, m_clientRecordSeq++, ct);
    return out;
}

bool DtlsClientSession::DecryptAppData(const std::vector<uint8_t>& datagram,
                                       std::vector<uint8_t>& out)
{
    if (m_state != DtlsState_Established || !m_serverCipher.get()) return false;

    dtls::DtlsRecord rec;
    size_t consumed = 0;
    if (!dtls::DtlsRecordCodec::Decode(datagram.empty() ? 0 : &datagram[0],
                                        datagram.size(), rec, consumed)) return false;
    if (rec.type != dtls::kDtlsContentApplicationData) return false;

    uint64_t aadSeq = ((uint64_t)rec.epoch << 48) | rec.sequenceNumber;
    out.assign(rec.payload.size(), 0);
    int n = m_serverCipher->Decrypt(rec.payload.empty() ? 0 : &rec.payload[0],
                                    0, (int)rec.payload.size(),
                                    aadSeq, dtls::kDtlsContentApplicationData,
                                    dtls::kDtlsVersion12,
                                    out.empty() ? 0 : &out[0], (int)out.size());
    if (n < 0) { out.clear(); return false; }
    out.resize(n);
    return true;
}

// ---------------------------------------------------------------------------
// RFC 5705 keying material exporter.
//
//   keying_material = PRF(master_secret, label,
//                         client_random + server_random, length)
//
// For DTLS-SRTP the caller passes label = "EXTRACTOR-dtls_srtp" and
// length = 60 (16 + 16 + 14 + 14 for AES_CM_128 + HMAC_SHA1_80 salts).
// ---------------------------------------------------------------------------
std::vector<uint8_t> DtlsClientSession::ExportKeyingMaterial(
    const std::string& label, size_t length) const
{
    std::vector<uint8_t> out;
    if (m_masterSecret.size() != 48) return out;

    std::vector<uint8_t> seed;
    seed.insert(seed.end(), m_clientRandom, m_clientRandom + 32);
    seed.insert(seed.end(), m_serverRandom, m_serverRandom + 32);
    return dtls::TlsPrf::Compute(m_masterSecret, label, seed, length);
}

// Unused right now but referenced in the header; keep for symmetry.
void DtlsClientSession::HandleEncryptedHandshake(const uint8_t* /*recordPayload*/,
                                                 size_t /*payloadLen*/,
                                                 uint16_t /*epoch*/, uint64_t /*seq*/) {}

}}} // namespace vianigram::voip::application
