// Bridges libtgvoip's pluggable crypto callbacks (TGVOIP_USE_CALLBACK_CRYPTO=1)
// onto the existing Vianigram / VianiumBrowser crypto stack.
//
// Today this file is built into Vianium.libtgvoip but no consumer calls
// RegisterTgvoipCryptoCallbacks(). It exists as groundwork for a future
// VoipEngine fallback path.
//
// The .vcxproj does NOT pull in vianigram::crypto::domain or vianium::crypto
// source files (libtgvoip is a self-contained static library), so the bodies
// are stubbed out with TODO markers. Wiring up the actual implementations is
// done at the consumer layer (e.g. Vianigram.Core.Voip) where both libraries
// are already linked together.
//
// References:
//   - VoIPController.h   :: struct CryptoFunctions
//   - aes_ige.h          :: vianigram::crypto::domain::EncryptIGE / DecryptIGE
//   - sha1.h / sha256.h  :: vianium::crypto::Sha1::Hash / Sha256::Hash

#include "../VoIPController.h"

#include <cstdint>
#include <cstddef>

namespace {

extern "C" void AesIgeEncryptCallback(uint8_t* in, uint8_t* out, size_t length,
                                       uint8_t* key, uint8_t* iv) {
    // TODO: forward to vianigram::crypto::domain::EncryptIGE(key, iv, in, out, length).
    // Stubbed for the vendoring stage so libtgvoip.lib has no external link
    // dependencies on Vianigram.Core.Crypto / Vianium.Core.Tls.
    (void)in; (void)out; (void)length; (void)key; (void)iv;
}

extern "C" void AesIgeDecryptCallback(uint8_t* in, uint8_t* out, size_t length,
                                       uint8_t* key, uint8_t* iv) {
    // TODO: forward to vianigram::crypto::domain::DecryptIGE.
    (void)in; (void)out; (void)length; (void)key; (void)iv;
}

extern "C" void Sha1Callback(uint8_t* msg, size_t length, uint8_t* output) {
    // TODO: forward to vianium::crypto::Sha1::Hash(msg, length, output).
    (void)msg; (void)length; (void)output;
}

extern "C" void Sha256Callback(uint8_t* msg, size_t length, uint8_t* output) {
    // TODO: forward to vianium::crypto::Sha256::Hash(msg, length, output).
    (void)msg; (void)length; (void)output;
}

extern "C" void RandBytesCallback(uint8_t* buf, size_t length) {
    // TODO: BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG) or
    // Windows::Security::Cryptography::CryptographicBuffer::GenerateRandom.
    (void)buf; (void)length;
}

extern "C" void AesCtrEncryptCallback(uint8_t* /*inout*/, size_t /*length*/,
                                       uint8_t* /*key*/, uint8_t* /*iv*/,
                                       uint8_t* /*ecount*/, uint32_t* /*num*/) {
    // Optional in libtgvoip; not used by the MTProto2 voice flow.
}

extern "C" void AesCbcEncryptCallback(uint8_t* /*in*/, uint8_t* /*out*/,
                                       size_t /*length*/, uint8_t* /*key*/,
                                       uint8_t* /*iv*/) {
    // Optional in libtgvoip.
}

extern "C" void AesCbcDecryptCallback(uint8_t* /*in*/, uint8_t* /*out*/,
                                       size_t /*length*/, uint8_t* /*key*/,
                                       uint8_t* /*iv*/) {
    // Optional in libtgvoip.
}

} // namespace

void RegisterTgvoipCryptoCallbacks() {
    tgvoip::VoIPController::crypto.aes_ige_encrypt = &AesIgeEncryptCallback;
    tgvoip::VoIPController::crypto.aes_ige_decrypt = &AesIgeDecryptCallback;
    tgvoip::VoIPController::crypto.sha1            = &Sha1Callback;
    tgvoip::VoIPController::crypto.sha256          = &Sha256Callback;
    tgvoip::VoIPController::crypto.rand_bytes      = &RandBytesCallback;
    tgvoip::VoIPController::crypto.aes_ctr_encrypt = &AesCtrEncryptCallback;
    tgvoip::VoIPController::crypto.aes_cbc_encrypt = &AesCbcEncryptCallback;
    tgvoip::VoIPController::crypto.aes_cbc_decrypt = &AesCbcDecryptCallback;
}
