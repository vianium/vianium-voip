// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include "voip_error.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vianigram { namespace voip { namespace domain {

struct VoipDhMaterial {
    VoipError Error;
    std::vector<uint8_t> PublicValue;
    std::vector<uint8_t> PublicHash;
    int64_t KeyFingerprint;
    std::string KeyHandle;

    VoipDhMaterial() : KeyFingerprint(0) {}

    static VoipDhMaterial Fail(const VoipError& error) {
        VoipDhMaterial out;
        out.Error = error;
        return out;
    }

    static VoipDhMaterial Ok() {
        return VoipDhMaterial();
    }
};

}}} // namespace vianigram::voip::domain
