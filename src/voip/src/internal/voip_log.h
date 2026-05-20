// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <windows.h>

namespace vianigram { namespace voip { namespace internal {

inline void DebugLog(const wchar_t* message) {
#if defined(VIANIGRAM_VOIP_VERBOSE)
    if (message != nullptr) {
        ::OutputDebugStringW(message);
        ::OutputDebugStringW(L"\n");
    }
#else
    (void)message;
#endif
}

}}} // namespace vianigram::voip::internal
