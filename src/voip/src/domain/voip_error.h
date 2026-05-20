// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>

namespace vianigram { namespace voip { namespace domain {

enum class VoipErrorKind : uint8_t {
    None = 0,
    Unavailable = 1,
    InvalidArgument = 2,
    CryptoUnavailable = 3,
    FingerprintMismatch = 4,
    TransportFailed = 5,
    CodecFailed = 6,
    AudioDeviceFailed = 7,
    InternalError = 8,
    HandshakeTimeout = 9
};

struct VoipError {
    VoipErrorKind Kind;
    int Code;
    std::string Message;

    VoipError() : Kind(VoipErrorKind::None), Code(0) {}

    static VoipError Ok() {
        return VoipError();
    }

    static VoipError Of(VoipErrorKind kind, int code, const char* message) {
        VoipError e;
        e.Kind = kind;
        e.Code = code;
        e.Message = message == nullptr ? "" : message;
        return e;
    }

    static VoipError Unavailable(const char* message) {
        return Of(VoipErrorKind::Unavailable, 0, message);
    }

    bool IsOk() const {
        return Kind == VoipErrorKind::None;
    }
};

inline const char* VoipErrorKindLabel(VoipErrorKind kind) {
    switch (kind) {
        case VoipErrorKind::None: return "ok";
        case VoipErrorKind::Unavailable: return "unavailable";
        case VoipErrorKind::InvalidArgument: return "invalid_argument";
        case VoipErrorKind::CryptoUnavailable: return "crypto_unavailable";
        case VoipErrorKind::FingerprintMismatch: return "fingerprint_mismatch";
        case VoipErrorKind::TransportFailed: return "transport_failed";
        case VoipErrorKind::CodecFailed: return "codec_failed";
        case VoipErrorKind::AudioDeviceFailed: return "audio_device_failed";
        case VoipErrorKind::InternalError: return "internal_error";
        case VoipErrorKind::HandshakeTimeout: return "handshake_timeout";
    }
    return "unknown";
}

}}} // namespace vianigram::voip::domain
