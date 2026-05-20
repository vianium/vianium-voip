// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <string>

namespace vianigram { namespace voip { namespace domain {

struct VoipCapability {
    bool CanExchangeCallKeys;
    bool CanStartMedia;
    std::string Reason;

    VoipCapability() : CanExchangeCallKeys(false), CanStartMedia(false) {}

    static VoipCapability Unavailable(const char* reason) {
        VoipCapability c;
        c.CanExchangeCallKeys = false;
        c.CanStartMedia = false;
        c.Reason = reason == nullptr ? "" : reason;
        return c;
    }

    static VoipCapability KeyExchangeOnly(const char* reason) {
        VoipCapability c;
        c.CanExchangeCallKeys = true;
        c.CanStartMedia = false;
        c.Reason = reason == nullptr ? "" : reason;
        return c;
    }

    static VoipCapability MediaReady() {
        VoipCapability c;
        c.CanExchangeCallKeys = true;
        c.CanStartMedia = true;
        c.Reason.clear();
        return c;
    }
};

}}} // namespace vianigram::voip::domain
