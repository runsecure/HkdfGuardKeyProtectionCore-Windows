#pragma once

#include "handle_traits.h"
#include "wire_format.h"
#include <cstdint>
#include <string>

namespace hkdfguard {

// Key generation used by this format version. A future format version could
// introduce a new KeyId to support KEK rotation without breaking the wire
// format (a new persisted key with a different name, referenced by KeyId).
constexpr uint32_t kCurrentKeyId = 1;

// Bundles everything callers need after locating/creating a KEK: the two
// handles that own it, plus which provider and KeyId it came from (so a
// wrap operation can record them in the wrapped payload). Ordinary
// aggregate struct - not RAII itself, but its two handle members
// (ScopedNCryptProv, ScopedNCryptKey) are, so a ResolvedKek still cleans
// itself up correctly on destruction "for free," just by containing them.
struct ResolvedKek {
    ScopedNCryptProv provider; // must outlive `key` and any NCryptImportKey calls against it
    ScopedNCryptKey key;
    uint8_t provider_type;
    uint32_t key_id;
};

// `service` identifies which persistent KEK to use - callers that wrap DEKs
// for different purposes (e.g. different applications or tenants) can pass
// different service names to get independent, non-interoperable KEKs. The
// same service name must be supplied on both wrap and unwrap; it is not
// itself recorded in the wrapped payload.

// Resolves the KEK to use for a wrap operation: tries the Microsoft Platform
// Crypto Provider (TPM/vTPM) first, opening the existing persisted key or
// creating it if absent; if that provider is unavailable or fails for any
// reason, falls back to the Microsoft Software Key Storage Provider with the
// same open-or-create logic. The KEK is machine-wide scoped (via
// NCRYPT_MACHINE_KEY_FLAG - see kek_store.cpp) and non-exportable: it is
// not tied to the calling account, so a different account than the one
// that created it can later open and use it (subject to the key's ACL).
// Creating a new machine-wide key requires the calling process to be
// elevated; this is the intended shape for a deployment-time utility that
// wraps a DEK once, ahead of a separate, lower-privileged account
// unwrapping it later. Throws HkdfGuardError(HKDFGUARD_ERR_PROVIDER) if
// both providers fail.
//
// `const std::wstring& service` - a *reference* to a std::wstring (C++'s
// "wide string" type, holding UTF-16 characters, which is what every
// Windows API that takes text ultimately wants) rather than a copy of one.
// Passing by `const&` avoids copying the string's characters just to make
// this function call, while `const` promises the function won't modify the
// caller's string through this reference.
ResolvedKek ResolveOrCreateKekForWrap(const std::wstring& service);

// Opens the specific KEK identified by `service` and a wrapped payload's
// provider_type and key_id, for use during unwrap. Never creates a key.
// Throws HkdfGuardError(HKDFGUARD_ERR_PROVIDER) if the provider or key
// cannot be opened (e.g. a different service name, a different machine, or
// a TPM that is no longer available). Since the KEK is machine-wide
// scoped, this succeeds for any local account the key's ACL permits -
// unlike a per-user key, it does not need to be the same account that
// originally wrapped the DEK.
ResolvedKek OpenKekForUnwrap(const std::wstring& service, uint8_t provider_type, uint32_t key_id);

// Deletes the persisted KEK identified by `service`/`provider_type`/
// `key_id`. Not part of the public C ABI - used by tests to avoid leaving
// KEKs behind in the user's key storage. Throws
// HkdfGuardError(HKDFGUARD_ERR_PROVIDER) if the provider or key cannot be
// opened, or if deletion fails.
void DeleteKek(const std::wstring& service, uint8_t provider_type, uint32_t key_id);

} // namespace hkdfguard
