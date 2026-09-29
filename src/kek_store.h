#pragma once

#include "handle_traits.h"
#include "wire_format.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hkdfguard {

    // Every `service` parameter below is used verbatim to build the
    // persisted KEK's name (see kek_store.cpp's KeyName) - this layer does
    // no normalization of its own. The public C ABI (hkdfguard.cpp)
    // lowercases and validates `service` before calling any of these, so
    // two callers whose service names differ only in case resolve to the
    // same KEK; a caller that reaches this API directly (bypassing
    // hkdfguard.cpp, as this project's own tests do to reach CreateKek/
    // KekExists/DeleteKek for setup and cleanup) is responsible for
    // supplying an already-normalized `service` itself if it wants that
    // same behavior.
    //
    // kCurrentKeyId lives in wire_format.h (visible here via the #include
    // above) - it's fundamentally a wire-format fact (the one KeyId value
    // ParseWrappedDek ever accepts), not a kek_store-specific one, and this
    // file just reuses it for the key name it builds.

    struct ResolvedKek {
        ScopedNCryptProv provider;
        ScopedNCryptKey key;
        uint8_t provider_type;
        uint32_t key_id;
    };

    //
    // Reports whether the service's KEK already exists, per the effective
    // TPM/software policy. Never creates or modifies a key.
    //
    // Throws HkdfGuardError on failure (a genuine provider error, not the
    // key simply not existing).
    //
    bool KekExists(
        const std::wstring& service);

    //
    // Creates the KEK if missing, or verifies it if present.
    //
    // Responsibilities:
    //
    //   - Read and validate the machine key-use group policy
    //     (policy.h's LoadKeyUseGroupsPolicy + key_acl.h's
    //     ValidateKeyUseGroups) - before touching the key store, so a bad
    //     policy fails cleanly with HKDFGUARD_ERR_GROUP_INVALID and no key
    //   - Resolve effective TPM/software policy
    //   - Create KEK if missing
    //   - Apply ACLs (creation only - see hkdfguard.h)
    //   - Verify ACLs
    //   - Verify key properties
    //
    // Throws HkdfGuardError on failure.
    //
    void CreateKek(
        const std::wstring& service);

    //
    // Opens an existing KEK for wrap operations.
    //
    // Never creates a key.
    //
    // Intended for runtime use after CreateKek()
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