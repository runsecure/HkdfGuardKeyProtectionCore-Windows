#pragma once

#include "handle_traits.h"
#include "wire_format.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hkdfguard {

    constexpr uint32_t kCurrentKeyId = 1;

    struct ResolvedKek {
        ScopedNCryptProv provider;
        ScopedNCryptKey key;
        uint8_t provider_type;
        uint32_t key_id;
    };

    //
    // Ensures the KEK exists and is configured correctly.
    //
    // Responsibilities:
    //
    //   - Resolve effective TPM/software policy
    //   - Create KEK if missing
    //   - Apply ACLs
    //   - Verify ACLs
    //   - Verify key properties
    //
    // The supplied groups receive unwrap/use access.
    //
    // Throws HkdfGuardError on failure.
    //
    void EnsureKek(
        const std::wstring& service,
        const std::vector<std::wstring>& aclGroups);

    //
    // Opens an existing KEK for wrap operations.
    //
    // Never creates a key.
    //
    // Intended for runtime use after EnsureKek()
    // has completed provisioning.
    //
    ResolvedKek OpenKekForWrap(
        const std::wstring& service);

    //
    // Opens an existing KEK for unwrap operations.
    //
    // Never creates a key.
    //
    ResolvedKek OpenKekForUnwrap(
        const std::wstring& service,
        uint8_t provider_type,
        uint32_t key_id);

    //
    // Test-only helper.
    //
    void DeleteKek(
        const std::wstring& service,
        uint8_t provider_type,
        uint32_t key_id);

} // namespace hkdfguard