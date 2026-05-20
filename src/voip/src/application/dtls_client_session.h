// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// DTLS 1.2 client handshake state machine for tgcalls voice calls.
//
// Negotiates exactly one cipher suite — TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// (0xC02B), the WebRTC default. After Established, the session protects
// application-data records with AES-128-GCM and can export 60 bytes of keying
// material for SRTP via the RFC 5705 + RFC 5764 "EXTRACTOR-dtls_srtp" exporter.
//
// Lifecycle:
//   1. Construct with our ECDSA-P256 self-signed cert + the peer's expected
//      SHA-256 cert fingerprint (from Signaling).
//   2. Call Initiate() — get the first ClientHello datagram(s).
//   3. Pump every received datagram through ProcessDatagram(); collect any
//      reply datagrams from outDatagrams and send them back.
//   4. When GetState() == Established, call ExportKeyingMaterial("EXTRACTOR-dtls_srtp", 60).
//
// Out of scope (TODO):
//   * Retransmission timer — caller is expected to retry the last flight
//     after ~1 second if no reply.
//   * Fragmented handshake messages on the receive side.
//   * Negotiating multiple cipher suites / renegotiation / session resume.
//   * Full X.509 chain validation — we trust the SHA-256 fingerprint instead,
//     which is the model tgcalls/WebRTC use.

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace vianium { namespace crypto { class AesGcm; } }

namespace vianigram { namespace voip { namespace infrastructure {
    class EcdsaP256KeyPair;
}}}

namespace vianigram { namespace voip { namespace application {

enum DtlsState {
    DtlsState_Initial,
    DtlsState_SentClientHello,
    DtlsState_GotHelloVerifyRequest,
    DtlsState_SentClientHelloWithCookie,
    DtlsState_GotServerHello,
    DtlsState_GotServerCertificate,
    DtlsState_GotServerKeyExchange,
    DtlsState_GotServerHelloDone,
    DtlsState_SentClientKeyExchange,
    DtlsState_SentChangeCipherSpec,
    DtlsState_SentFinished,
    DtlsState_GotChangeCipherSpec,
    DtlsState_Established,
    DtlsState_Failed
};

class DtlsClientSession {
public:
    DtlsClientSession(std::unique_ptr<infrastructure::EcdsaP256KeyPair> ourCert,
                      const std::string& peerFingerprint /* "AB:CD:..." */);
    ~DtlsClientSession();

    // First flight: ClientHello (no cookie).
    std::vector<std::vector<uint8_t> > Initiate();

    // Feed one received UDP datagram. The datagram may pack multiple DTLS
    // records (handshake flight from the peer). outDatagrams is appended
    // with any datagrams the caller should send out.
    bool ProcessDatagram(const uint8_t* data, size_t size,
                         std::vector<std::vector<uint8_t> >& outDatagrams);

    DtlsState GetState() const { return m_state; }
    const std::string& FailureReason() const { return m_failureReason; }

    // After Established only.
    std::vector<uint8_t> EncryptAppData(const std::vector<uint8_t>& plaintext);
    bool                 DecryptAppData(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& out);

    // RFC 5705 keying material exporter. For DTLS-SRTP (RFC 5764) call this
    // with label = "EXTRACTOR-dtls_srtp" and length = 60 to receive
    //   client_write_SRTP_master_key   (16)
    //   server_write_SRTP_master_key   (16)
    //   client_write_SRTP_master_salt  (14)
    //   server_write_SRTP_master_salt  (14)
    std::vector<uint8_t> ExportKeyingMaterial(const std::string& label, size_t length) const;

private:
    // Handshake helpers
    std::vector<uint8_t> BuildClientHelloBody(bool withCookie);
    std::vector<uint8_t> BuildClientKeyExchangeBody();
    std::vector<uint8_t> BuildCertificateBody();
    std::vector<uint8_t> BuildCertificateVerifyBody(const std::vector<uint8_t>& handshakeHashSoFar);
    std::vector<uint8_t> BuildFinishedBody(const std::vector<uint8_t>& handshakeHashUpToFinished, bool fromClient);

    void   AppendToHandshakeHash(const uint8_t* data, size_t len);
    std::vector<uint8_t> CurrentHandshakeHash() const;

    void   DeriveKeysAndCipher();
    void   Fail(const std::string& reason);

    static std::vector<uint8_t> ParseHexFingerprint(const std::string& fp);
    static std::vector<uint8_t> Sha256(const uint8_t* data, size_t len);

    // Process one decoded handshake message (after fragment reassembly).
    void HandleHandshakeMessage(uint8_t msgType,
                                const uint8_t* body, size_t bodyLen,
                                const uint8_t* fullMessageBytes, size_t fullMessageLen,
                                std::vector<std::vector<uint8_t> >& outDatagrams);

    // Process a ChangeCipherSpec record from server.
    void HandleChangeCipherSpec();

    // Encrypted Finished from server (after CCS).
    void HandleEncryptedHandshake(const uint8_t* recordPayload, size_t payloadLen,
                                  uint16_t epoch, uint64_t seq);

    // Build the post-CCS client flight: { CCS, Finished } as datagrams.
    void BuildClientFinishedFlight(std::vector<std::vector<uint8_t> >& outDatagrams);

private:
    DtlsState   m_state;
    std::string m_failureReason;

    std::unique_ptr<infrastructure::EcdsaP256KeyPair> m_ourCert;
    std::vector<uint8_t> m_expectedPeerFingerprint; // 32 bytes

    // Randoms / handshake state
    uint8_t  m_clientRandom[32];
    uint8_t  m_serverRandom[32];
    std::vector<uint8_t> m_cookie;
    std::vector<uint8_t> m_serverPublicPoint;
    std::vector<uint8_t> m_ourEcdhPrivate; // 32 bytes
    std::vector<uint8_t> m_ourEcdhPublic;  // 65 bytes (uncompressed)
    std::vector<uint8_t> m_serverCertDer;
    bool     m_extendedMasterSecret;

    // Handshake message sequence numbers
    uint16_t m_clientMessageSeq;
    uint16_t m_serverMessageSeqExpected;

    // Record layer
    uint16_t m_clientEpoch;
    uint64_t m_clientRecordSeq;
    uint64_t m_serverRecordSeq;

    // Crypto material
    std::vector<uint8_t> m_masterSecret;     // 48
    std::vector<uint8_t> m_clientWriteKey;   // 16
    std::vector<uint8_t> m_serverWriteKey;   // 16
    std::vector<uint8_t> m_clientWriteIv;    // 4
    std::vector<uint8_t> m_serverWriteIv;    // 4

    std::unique_ptr<vianium::crypto::AesGcm> m_clientCipher;
    std::unique_ptr<vianium::crypto::AesGcm> m_serverCipher;

    // Running handshake transcript (raw handshake message bytes, no DTLS hdr,
    // no record header; per RFC 6347 §4.2.6 the transcript is the same as TLS).
    std::vector<uint8_t> m_handshakeTranscript;
};

}}} // namespace vianigram::voip::application
