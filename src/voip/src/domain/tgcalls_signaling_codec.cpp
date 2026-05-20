// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "tgcalls_signaling_codec.h"

#include <vianium/crypto/aes_core.h>
#include <vianium/crypto/sha256.h>

#include <cstring>
#include <sstream>
#include <windows.h>

namespace vianigram { namespace voip { namespace domain {

namespace {

const size_t kSharedKeyBytes = 256;
const size_t kMsgKeyBytes = 16;
const size_t kAesBlockBytes = 16;
const size_t kAesKeyBytes = 32;
const size_t kAesIvBytes = 16; // CTR nonce
const size_t kSignalingX = 128; // signaling channel offset

TgcallsSignalingDecryptResult Fail(const char* message) {
    TgcallsSignalingDecryptResult r;
    r.Success = false;
    r.Error = message == 0 ? "" : message;
    return r;
}

void Sha256Hash(const uint8_t* bytes, size_t length, uint8_t out[32]) {
    vianium::crypto::Sha256::Hash(bytes, length, out);
}

void DeriveSignalingAesKeyIv(
    const std::vector<uint8_t>& sharedKey,
    const uint8_t msgKey[kMsgKeyBytes],
    size_t x,
    uint8_t aesKey[kAesKeyBytes],
    uint8_t aesIv[kAesIvBytes])
{
    // sha256a = SHA256(msg_key || sharedKey[x..x+36])
    std::vector<uint8_t> buf;
    uint8_t sA[32];
    uint8_t sB[32];

    buf.insert(buf.end(), msgKey, msgKey + kMsgKeyBytes);
    buf.insert(buf.end(), sharedKey.begin() + x, sharedKey.begin() + x + 36);
    Sha256Hash(&buf[0], buf.size(), sA);

    // sha256b = SHA256(sharedKey[40+x..40+x+36] || msg_key)
    buf.clear();
    buf.insert(buf.end(), sharedKey.begin() + 40 + x, sharedKey.begin() + 40 + x + 36);
    buf.insert(buf.end(), msgKey, msgKey + kMsgKeyBytes);
    Sha256Hash(&buf[0], buf.size(), sB);

    // aes_key = sha256a[0..8] || sha256b[8..24] || sha256a[24..32]   (32 bytes)
    std::memcpy(aesKey, sA, 8);
    std::memcpy(aesKey + 8, sB + 8, 16);
    std::memcpy(aesKey + 24, sA + 24, 8);

    // aes_iv  = sha256b[0..4]  || sha256a[8..16]  || sha256b[24..28] (16 bytes / CTR nonce)
    std::memcpy(aesIv, sB, 4);
    std::memcpy(aesIv + 4, sA + 8, 8);
    std::memcpy(aesIv + 12, sB + 24, 4);
}

// AES-256 CTR mode: encrypt counter blocks with AES-ECB and XOR with input.
// Counter is the 16-byte IV interpreted as big-endian and incremented per block.
void AesCtrXcrypt(
    const uint8_t aesKey[kAesKeyBytes],
    const uint8_t aesIv[kAesIvBytes],
    const uint8_t* in,
    uint8_t* out,
    size_t length)
{
    vianium::crypto::AesKey aes;
    aes.Init(aesKey, 32);

    uint8_t counter[16];
    std::memcpy(counter, aesIv, 16);

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < length) {
        aes.EncryptBlock(counter, keystream);

        size_t take = length - offset;
        if (take > 16) take = 16;
        for (size_t i = 0; i < take; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }
        offset += take;

        // Increment counter as big-endian 128-bit integer.
        for (int i = 15; i >= 0; i--) {
            counter[i] = static_cast<uint8_t>(counter[i] + 1);
            if (counter[i] != 0) break;
        }
    }
}

uint32_t ReadBE32(const uint8_t* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24)
         | (static_cast<uint32_t>(bytes[1]) << 16)
         | (static_cast<uint32_t>(bytes[2]) << 8)
         |  static_cast<uint32_t>(bytes[3]);
}

void WriteBE32(uint8_t* bytes, uint32_t value) {
    bytes[0] = static_cast<uint8_t>(value >> 24);
    bytes[1] = static_cast<uint8_t>(value >> 16);
    bytes[2] = static_cast<uint8_t>(value >> 8);
    bytes[3] = static_cast<uint8_t>(value);
}

void DebugLogA(const std::string& utf8) {
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (needed <= 0) return;
    std::vector<wchar_t> w((size_t)needed);
    ::MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &w[0], needed);
    ::OutputDebugStringW(&w[0]);
}

void LogResult(bool success, const std::string& detail) {
    std::ostringstream os;
    os << "[Tgcalls.Signaling] decrypt "
       << (success ? "ok" : "fail")
       << " " << detail
       << "\n";
    DebugLogA(os.str());
}

} // namespace

TgcallsSignalingDecryptResult TgcallsSignalingCodec::Decrypt(
    const std::vector<uint8_t>& sharedKey,
    bool isOutgoing,
    const uint8_t* bytes,
    size_t length)
{
    if (sharedKey.size() != kSharedKeyBytes) {
        TgcallsSignalingDecryptResult r = Fail("shared key must be exactly 256 bytes");
        LogResult(false, "reason=shared_key_size");
        return r;
    }
    if (bytes == 0 || length < kMsgKeyBytes + kAesBlockBytes) {
        TgcallsSignalingDecryptResult r = Fail("encrypted signaling payload is too short");
        LogResult(false, "reason=too_short");
        return r;
    }
    // The CTR mode allows arbitrary byte length, but Telegram's tgcalls always
    // emits a multiple of 16 bytes of ciphertext (it pads internally).
    size_t encryptedLen = length - kMsgKeyBytes;

    const uint8_t* msgKey = bytes;
    const uint8_t* encrypted = bytes + kMsgKeyBytes;

    // x = (isOutgoing ? 8 : 0) + 128 (signaling adds +128).
    size_t x = (isOutgoing ? 8 : 0) + kSignalingX;

    uint8_t aesKey[kAesKeyBytes];
    uint8_t aesIv[kAesIvBytes];
    DeriveSignalingAesKeyIv(sharedKey, msgKey, x, aesKey, aesIv);

    std::vector<uint8_t> decrypted(encryptedLen);
    AesCtrXcrypt(aesKey, aesIv, encrypted, &decrypted[0], encryptedLen);

    // Verify msg_key == SHA256(sharedKey[88+x..88+x+32] || plaintext)[8..24].
    std::vector<uint8_t> hashInput;
    hashInput.insert(hashInput.end(), sharedKey.begin() + 88 + x, sharedKey.begin() + 88 + x + 32);
    hashInput.insert(hashInput.end(), decrypted.begin(), decrypted.end());

    uint8_t msgKeyLarge[32];
    Sha256Hash(&hashInput[0], hashInput.size(), msgKeyLarge);
    if (std::memcmp(msgKey, msgKeyLarge + 8, 16) != 0) {
        TgcallsSignalingDecryptResult r = Fail("signaling msg_key mismatch");
        std::ostringstream os;
        os << "reason=msg_key_mismatch len=" << encryptedLen;
        LogResult(false, os.str());
        return r;
    }

    if (decrypted.size() < 4) {
        TgcallsSignalingDecryptResult r = Fail("decrypted signaling payload too small for seq");
        LogResult(false, "reason=no_seq");
        return r;
    }

    uint32_t seq = ReadBE32(&decrypted[0]);

    TgcallsSignalingDecryptResult r;
    r.Success = true;
    r.Seq = seq;
    r.Plain.assign(decrypted.begin() + 4, decrypted.end());

    std::ostringstream os;
    os << "seq=" << seq
       << " plain_len=" << r.Plain.size()
       << " direction=" << (isOutgoing ? "out" : "in");
    LogResult(true, os.str());
    return r;
}

std::vector<uint8_t> TgcallsSignalingCodec::Encrypt(
    const std::vector<uint8_t>& sharedKey,
    bool isOutgoing,
    uint32_t outerSeq,
    const std::vector<uint8_t>& body)
{
    if (sharedKey.size() != kSharedKeyBytes) {
        LogResult(false, "reason=encrypt_shared_key_size");
        return std::vector<uint8_t>();
    }

    // Plaintext = [outer_seq (BE)] || body.
    std::vector<uint8_t> plaintext(4 + body.size());
    WriteBE32(&plaintext[0], outerSeq);
    if (!body.empty()) {
        std::memcpy(&plaintext[4], &body[0], body.size());
    }

    // x for outgoing direction = 0 + 128; this MIRRORS the decrypt side
    // where the receiver uses 8 + 128 for our packets. (See upstream
    // EncryptedConnection::encryptPrepared which uses (isOutgoing ? 0 : 8).)
    size_t x = (isOutgoing ? 0 : 8) + kSignalingX;

    // msg_key = SHA256(sharedKey[88+x..88+x+32] || plaintext)[8..24]
    std::vector<uint8_t> hashInput;
    hashInput.insert(hashInput.end(), sharedKey.begin() + 88 + x, sharedKey.begin() + 88 + x + 32);
    hashInput.insert(hashInput.end(), plaintext.begin(), plaintext.end());

    uint8_t msgKeyLarge[32];
    Sha256Hash(&hashInput[0], hashInput.size(), msgKeyLarge);

    std::vector<uint8_t> result(kMsgKeyBytes + plaintext.size());
    std::memcpy(&result[0], msgKeyLarge + 8, 16);

    uint8_t aesKey[kAesKeyBytes];
    uint8_t aesIv[kAesIvBytes];
    DeriveSignalingAesKeyIv(sharedKey, &result[0], x, aesKey, aesIv);

    AesCtrXcrypt(aesKey, aesIv, &plaintext[0], &result[kMsgKeyBytes], plaintext.size());

    std::ostringstream os;
    os << "encrypt seq=" << outerSeq
       << " plain_len=" << plaintext.size()
       << " direction=" << (isOutgoing ? "out" : "in");
    LogResult(true, os.str());
    return result;
}

}}} // namespace vianigram::voip::domain
