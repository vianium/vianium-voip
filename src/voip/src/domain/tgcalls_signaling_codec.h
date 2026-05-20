// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct TgcallsSignalingDecryptResult {
    bool Success;
    std::string Error;
    std::vector<uint8_t> Plain;   // post-CTR, after stripping 4-byte seq prefix
    uint32_t Seq;

    TgcallsSignalingDecryptResult() : Success(false), Seq(0) {}
};

class TgcallsSignalingCodec {
public:
    /// shared_key: 256 bytes from the call DH (post-confirm).
    /// is_outgoing: true if WE initiated (initiator side has localIsOutgoing=true).
    /// bytes/length: the raw signalingData blob from updatePhoneCallSignalingData.
    static TgcallsSignalingDecryptResult Decrypt(
        const std::vector<uint8_t>& sharedKey,
        bool isOutgoing,
        const uint8_t* bytes,
        size_t length);

    /// Encrypt the given outer seq + body (frame bytes) using the same
    /// signaling AES-CTR scheme. Returns the [msg_key (16) + ciphertext]
    /// blob ready to be passed to phone.sendSignalingData.
    /// Note: when WE encrypt, x flips compared to decrypt — i.e. for outgoing
    /// messages we use x = 0 + 128, for incoming we'd use x = 8 + 128.
    /// Returns an empty vector on failure (e.g. invalid shared key length).
    static std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& sharedKey,
        bool isOutgoing,
        uint32_t outerSeq,
        const std::vector<uint8_t>& body);
};

}}} // namespace vianigram::voip::domain
