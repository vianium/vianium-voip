// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
// ecdsa_p256_keypair --- ECDSA-P256-SHA256 keypair backed by the WP8.1
// platform crypto provider (Windows::Security::Cryptography::Core).
//
// Three responsibilities for the Vianigram tgcalls / DTLS pipeline:
//   1. Generate a fresh P-256 keypair via the platform RNG.
//   2. Build a self-signed X.509 v3 certificate (DER) suitable for use as
//      the local DTLS identity.  The cert is hand-rolled because WP8.1
//      does not expose cert generation through its public WinRT APIs.
//   3. Compute the SHA-256 fingerprint of that DER cert in the
//      "AB:CD:EF:..." (uppercase, colon-separated) format required by
//      tgcalls Signaling.
//
// The platform's CryptographicEngine::SignHashedData on WP8.1 returns the
// raw r||s representation (64 bytes) for ECDSA-P256-SHA256.  SignSha256
// wraps that into a DER ECDSA-Sig-Value `SEQUENCE { r INTEGER, s INTEGER }`
// before returning.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace infrastructure {

class EcdsaP256KeyPair {
public:
    // Generate a fresh keypair via the platform RNG.
    // Returns nullptr if platform crypto is unavailable.
    static std::unique_ptr<EcdsaP256KeyPair> Generate();

    ~EcdsaP256KeyPair();

    // Sign a 32-byte SHA-256 hash with ECDSA-P256.
    // Returns DER-encoded ECDSA-Sig-Value: SEQUENCE { r INTEGER, s INTEGER }.
    // Empty vector on failure.
    std::vector<uint8_t> SignSha256(const uint8_t* hash, size_t hashLen);

    // Returns a self-signed X.509 v3 cert in DER format.
    // Subject = Issuer = "CN=Vianigram", validity = [now, now+1y].
    std::vector<uint8_t> ToX509SelfSignedDer();

    // SHA-256 fingerprint of the X.509 DER, formatted "AB:CD:..." (uppercase
    // hex with colons, 95 chars total).
    std::string ToSha256Fingerprint();

    // Get the public key as an uncompressed EC point: 0x04 || X || Y, 65 bytes.
    std::vector<uint8_t> GetPublicKeyUncompressed();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

    explicit EcdsaP256KeyPair(std::unique_ptr<Impl> impl);

    // Non-copyable.
    EcdsaP256KeyPair(const EcdsaP256KeyPair&);
    EcdsaP256KeyPair& operator=(const EcdsaP256KeyPair&);
};

}}} // namespace vianigram::voip::infrastructure
