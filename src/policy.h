#pragma once

#include <cstdint>

namespace hkdfguard {

    enum class KeyStoragePolicy : uint32_t {
        PreferTpm   = 0,
        RequireTpm  = 1,
        SoftwareOnly = 2
    };

    // Returns the machine-wide effective policy.
    // Never throws.
    // Invalid or missing policy values fall back to a safe default.
    KeyStoragePolicy LoadEffectivePolicy() noexcept;

} // namespace hkdfguard
