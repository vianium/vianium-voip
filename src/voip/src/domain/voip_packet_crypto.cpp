// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "voip_packet_crypto.h"

#include <vianium/crypto/aes_core.h>
#include <vianium/crypto/random.h>
#include <vianium/crypto/sha256.h>

#include <cstring>

namespace vianigram { namespace voip { namespace domain {

namespace {

const size_t kSharedKeyBytes = 256;
const size_t kPeerTagBytes = 16;
const size_t kMsgKeyBytes = 16;
const size_t kAesBlockBytes = 16;
const size_t kAesKeyBytes = 32;
const size_t kAesIvBytes = 32;
const size_t kMaxPlainBytes = 1200;

VoipEncryptedPacketResult Fail(const char* message) {
    VoipEncryptedPacketResult r;
    r.Success = false;
    r.Error = message == 0 ? "" : message;
    return r;
}

void WriteLE16(std::vector<uint8_t>& out, size_t offset, uint16_t value) {
    out[offset] = static_cast<uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

uint16_t ReadLE16(const uint8_t* bytes) {
    return static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
}

void Sha256(const uint8_t* bytes, size_t length, uint8_t out[32]) {
    vianium::crypto::Sha256::Hash(bytes, length, out);
}

void Kdf2(
    const std::vector<uint8_t>& sharedKey,
    const uint8_t msgKey[kMsgKeyBytes],
    size_t x,
    uint8_t aesKey[kAesKeyBytes],
    uint8_t aesIv[kAesIvBytes])
{
    std::vector<uint8_t> buf;
    uint8_t sA[32];
    uint8_t sB[32];

    buf.insert(buf.end(), msgKey, msgKey + kMsgKeyBytes);
    buf.insert(buf.end(), sharedKey.begin() + x, sharedKey.begin() + x + 36);
    Sha256(&buf[0], buf.size(), sA);

    buf.clear();
    buf.insert(buf.end(), sharedKey.begin() + 40 + x, sharedKey.begin() + 40 + x + 36);
    buf.insert(buf.end(), msgKey, msgKey + kMsgKeyBytes);
    Sha256(&buf[0], buf.size(), sB);

    std::memcpy(aesKey, sA, 8);
    std::memcpy(aesKey + 8, sB + 8, 16);
    std::memcpy(aesKey + 24, sA + 24, 8);

    std::memcpy(aesIv, sB, 8);
    std::memcpy(aesIv + 8, sA + 8, 16);
    std::memcpy(aesIv + 24, sB + 24, 8);
}

inline void Xor16(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

bool EncryptIge(
    const uint8_t key[kAesKeyBytes],
    const uint8_t iv[kAesIvBytes],
    const uint8_t* in,
    uint8_t* out,
    size_t length)
{
    if (length == 0 || (length % kAesBlockBytes) != 0) return false;

    vianium::crypto::AesKey aes;
    aes.Init(key, 32);

    uint8_t prevC[16];
    uint8_t prevP[16];
    std::memcpy(prevC, iv, 16);
    std::memcpy(prevP, iv + 16, 16);

    uint8_t tmp[16];
    uint8_t enc[16];
    uint8_t curP[16];
    size_t blocks = length / kAesBlockBytes;
    for (size_t b = 0; b < blocks; b++) {
        const uint8_t* pBlock = in + b * 16;
        uint8_t* cBlock = out + b * 16;
        std::memcpy(curP, pBlock, 16);
        Xor16(tmp, curP, prevC);
        aes.EncryptBlock(tmp, enc);
        Xor16(cBlock, enc, prevP);
        std::memcpy(prevC, cBlock, 16);
        std::memcpy(prevP, curP, 16);
    }
    return true;
}

bool DecryptIge(
    const uint8_t key[kAesKeyBytes],
    const uint8_t iv[kAesIvBytes],
    const uint8_t* in,
    uint8_t* out,
    size_t length)
{
    if (length == 0 || (length % kAesBlockBytes) != 0) return false;

    vianium::crypto::AesKey aes;
    aes.Init(key, 32);

    uint8_t prevC[16];
    uint8_t prevP[16];
    std::memcpy(prevC, iv, 16);
    std::memcpy(prevP, iv + 16, 16);

    uint8_t tmp[16];
    uint8_t dec[16];
    uint8_t curC[16];
    size_t blocks = length / kAesBlockBytes;
    for (size_t b = 0; b < blocks; b++) {
        const uint8_t* cBlock = in + b * 16;
        uint8_t* pBlock = out + b * 16;
        std::memcpy(curC, cBlock, 16);
        Xor16(tmp, curC, prevP);
        aes.DecryptBlock(tmp, dec);
        Xor16(pBlock, dec, prevC);
        std::memcpy(prevC, curC, 16);
        std::memcpy(prevP, pBlock, 16);
    }
    return true;
}

bool ValidateSharedKey(const std::vector<uint8_t>& sharedKey) {
    return sharedKey.size() == kSharedKeyBytes;
}

bool ValidatePeerTag(const std::vector<uint8_t>& peerTag) {
    return peerTag.size() == kPeerTagBytes;
}

bool SamePeerTag(const uint8_t* bytes, const std::vector<uint8_t>& expectedPeerTag) {
    if (expectedPeerTag.empty()) return true;
    if (!ValidatePeerTag(expectedPeerTag)) return false;
    for (size_t i = 0; i < expectedPeerTag.size(); i++) {
        if (bytes[i] != expectedPeerTag[i]) return false;
    }
    return true;
}

size_t DirectionOffset(bool localIsOutgoing, bool sending) {
    if (sending) {
        return localIsOutgoing ? 0 : 8;
    }
    return localIsOutgoing ? 8 : 0;
}

} // namespace

VoipEncryptedPacketResult VoipPacketCrypto::EncryptRelayPacketMtProto2Short(
    const std::vector<uint8_t>& sharedKey,
    bool localIsOutgoing,
    const std::vector<uint8_t>& peerTag,
    const std::vector<uint8_t>& plain)
{
    if (!ValidateSharedKey(sharedKey)) {
        return Fail("VoIP shared key must be exactly 256 bytes");
    }
    if (!ValidatePeerTag(peerTag)) {
        return Fail("VoIP relay peer_tag must be exactly 16 bytes");
    }
    if (plain.empty() || plain.size() > kMaxPlainBytes) {
        return Fail("VoIP plaintext packet length is invalid");
    }

    std::vector<uint8_t> inner;
    inner.resize(2 + plain.size());
    WriteLE16(inner, 0, static_cast<uint16_t>(plain.size()));
    std::memcpy(&inner[2], &plain[0], plain.size());

    size_t padLen = kAesBlockBytes - (inner.size() % kAesBlockBytes);
    if (padLen < kAesBlockBytes) padLen += kAesBlockBytes;
    size_t oldLen = inner.size();
    inner.resize(inner.size() + padLen);
    vianium::crypto::GenerateRandom(&inner[oldLen], padLen);

    size_t x = DirectionOffset(localIsOutgoing, true);
    std::vector<uint8_t> hashInput;
    hashInput.insert(hashInput.end(), sharedKey.begin() + 88 + x, sharedKey.begin() + 88 + x + 32);
    hashInput.insert(hashInput.end(), inner.begin(), inner.end());

    uint8_t msgKeyLarge[32];
    Sha256(&hashInput[0], hashInput.size(), msgKeyLarge);
    uint8_t msgKey[16];
    std::memcpy(msgKey, msgKeyLarge + 8, 16);

    uint8_t aesKey[32];
    uint8_t aesIv[32];
    Kdf2(sharedKey, msgKey, x, aesKey, aesIv);

    std::vector<uint8_t> encrypted(inner.size());
    if (!EncryptIge(aesKey, aesIv, &inner[0], &encrypted[0], inner.size())) {
        return Fail("VoIP AES-IGE encryption failed");
    }

    VoipEncryptedPacketResult r;
    r.Success = true;
    r.Plain = plain;
    r.Bytes.reserve(kPeerTagBytes + kMsgKeyBytes + encrypted.size());
    r.Bytes.insert(r.Bytes.end(), peerTag.begin(), peerTag.end());
    r.Bytes.insert(r.Bytes.end(), msgKey, msgKey + kMsgKeyBytes);
    r.Bytes.insert(r.Bytes.end(), encrypted.begin(), encrypted.end());
    return r;
}

VoipEncryptedPacketResult VoipPacketCrypto::DecryptRelayPacketMtProto2Short(
    const std::vector<uint8_t>& sharedKey,
    bool localIsOutgoing,
    const std::vector<uint8_t>& expectedPeerTag,
    const uint8_t* bytes,
    size_t length)
{
    if (!ValidateSharedKey(sharedKey)) {
        return Fail("VoIP shared key must be exactly 256 bytes");
    }
    if (bytes == 0 || length < kPeerTagBytes + kMsgKeyBytes + kAesBlockBytes) {
        return Fail("VoIP encrypted packet is too short");
    }
    if (!expectedPeerTag.empty() && !SamePeerTag(bytes, expectedPeerTag)) {
        return Fail("VoIP relay peer_tag mismatch");
    }

    size_t offset = kPeerTagBytes;
    const uint8_t* msgKey = bytes + offset;
    offset += kMsgKeyBytes;
    const uint8_t* encrypted = bytes + offset;
    size_t encryptedLen = length - offset;
    if ((encryptedLen % kAesBlockBytes) != 0) {
        return Fail("VoIP encrypted packet length is not block aligned");
    }

    size_t x = DirectionOffset(localIsOutgoing, false);
    uint8_t aesKey[32];
    uint8_t aesIv[32];
    Kdf2(sharedKey, msgKey, x, aesKey, aesIv);

    std::vector<uint8_t> decrypted(encryptedLen);
    if (!DecryptIge(aesKey, aesIv, encrypted, &decrypted[0], encryptedLen)) {
        return Fail("VoIP AES-IGE decryption failed");
    }

    std::vector<uint8_t> hashInput;
    hashInput.insert(hashInput.end(), sharedKey.begin() + 88 + x, sharedKey.begin() + 88 + x + 32);
    hashInput.insert(hashInput.end(), decrypted.begin(), decrypted.end());

    uint8_t msgKeyLarge[32];
    Sha256(&hashInput[0], hashInput.size(), msgKeyLarge);
    if (std::memcmp(msgKey, msgKeyLarge + 8, 16) != 0) {
        return Fail("VoIP encrypted packet msg_key mismatch");
    }

    uint16_t plainLen = ReadLE16(&decrypted[0]);
    if (plainLen == 0 || plainLen > decrypted.size() - 2) {
        return Fail("VoIP encrypted packet inner length is invalid");
    }
    if (decrypted.size() - plainLen < 16) {
        return Fail("VoIP encrypted packet padding is too short");
    }

    VoipEncryptedPacketResult r;
    r.Success = true;
    r.Bytes.assign(bytes, bytes + length);
    r.Plain.assign(decrypted.begin() + 2, decrypted.begin() + 2 + plainLen);
    return r;
}

}}} // namespace vianigram::voip::domain
