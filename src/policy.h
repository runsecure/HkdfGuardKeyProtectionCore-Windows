#pragma once

#include <cstdint>
#include <optional>

namespace hkdfguard {

    enum class KeyStoragePolicy : uint32_t {
        PreferTpm   = 0,
        RequireTpm  = 1,
        SoftwareOnly = 2
    };

    // Returns the machine-wide effective policy.
    // Never throws.
    // Invalid or missing policy values fall back to a safe default.
    //
    // Reads the real registry value (see policy.cpp). When this translation
    // unit is built with HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE defined, a
    // test policy override - see SetTestPolicyOverride below - is checked
    // first; in a normal (non-test) build that macro is never defined, so
    // this always reads the registry.
    KeyStoragePolicy LoadEffectivePolicy() noexcept;

// Test-only seam: makes LoadEffectivePolicy() return `policy` instead of
// reading the registry, regardless of this machine's actual configured
// policy - lets tests exercise all three KeyStoragePolicy branches
// deterministically. Pass std::nullopt to clear the override and resume
// reading the real registry value.
//
// Compiled in only when HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE is defined -
// tests/CMakeLists.txt defines it for test_roundtrip's own copy of this
// file only. hkdfguard.dll's own build (the top-level CMakeLists.txt) never
// defines it, so this function - and the override state it would control -
// does not exist at all in the shipped DLL; there is no runtime flag or
// code path in release code that could ever activate it. Not thread-safe,
// by design: a single-threaded test process is the only intended caller.
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestPolicyOverride(std::optional<KeyStoragePolicy> policy) noexcept;
#endif

} // namespace hkdfguard
