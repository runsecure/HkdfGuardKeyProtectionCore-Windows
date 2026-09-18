#include "kek_store.h"
#include "errors.h"
#include <string>

namespace hkdfguard {

namespace {

// Builds the actual name a KEK is persisted under in Windows' key storage:
// e.g. service "myapp" and key_id 1 becomes L"HkdfGuardWin_myapp_v1". The
// `L"..."` prefix on each string literal marks it as a *wide* string literal
// (an array of wchar_t, UTF-16 on Windows) rather than the narrow (char,
// typically UTF-8/ASCII) literals used elsewhere in the project (like
// hkdfguard.cpp's UTF-8 `service` parameter) - matching what
// std::wstring/NCrypt's LPCWSTR key-name parameters need. `operator+` on
// std::wstring concatenates, same as it does for std::string, so this whole
// expression builds up the final name piece by piece into one new string.
std::wstring KeyName(const std::wstring& service, uint32_t key_id) {
    return L"HkdfGuardWin_" + service + L"_v" + std::to_wstring(key_id);
}

// Maps a provider_type byte (see wire_format.h's kProviderTypeTpm /
// kProviderTypeSoftware) to the actual provider name string NCrypt expects.
// The `?:` ternary operator here is just a compact `if/else` that produces a
// value: "if provider_type equals kProviderTypeTpm, the result is
// MS_PLATFORM_CRYPTO_PROVIDER, otherwise it's MS_KEY_STORAGE_PROVIDER."
// LPCWSTR ("long pointer to constant wide string" - Windows' own typedef
// for `const wchar_t*`) is the type both of those provider-name constants
// have.
LPCWSTR ProviderName(uint8_t provider_type) {
    return (provider_type == kProviderTypeTpm) ? MS_PLATFORM_CRYPTO_PROVIDER : MS_KEY_STORAGE_PROVIDER;
}

// Opens the existing persisted KEK by name on the given provider, or creates
// it (non-exportable, key-agreement-only, current-user scoped) if it does
// not yet exist. Throws HkdfGuardError(HKDFGUARD_ERR_PROVIDER) on any
// failure, including the provider itself being unavailable.
ResolvedKek ResolveOrCreateOnProvider(
    const std::wstring& service, LPCWSTR provider_name, uint8_t provider_type, uint32_t key_id) {
    // `ResolvedKek result;` default-constructs the struct - its two Scoped*
    // members start out owning nothing, and its two plain fields are filled
    // in immediately below (they don't have default values of their own).
    ResolvedKek result;
    result.provider_type = provider_type;
    result.key_id = key_id;

    // NCryptOpenStorageProvider is how you get a handle to one of Windows'
    // key-storage backends at all - e.g. "the TPM-backed one" or "the pure
    // software one" - before you can open or create any key within it.
    // `result.provider.put()` (see handle_traits.h) hands the API the
    // address to write the new handle into.
    SECURITY_STATUS status = NCryptOpenStorageProvider(result.provider.put(), provider_name, 0);
    if (status != ERROR_SUCCESS) {
        // This is exactly the failure path that lets
        // ResolveOrCreateKekForWrap (below) detect "no TPM here" and fall
        // back to the software provider - see its own comment for how.
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenStorageProvider failed");
    }

    std::wstring name = KeyName(service, key_id);

    // dwFlags = 0 (no NCRYPT_MACHINE_KEY_FLAG) => current-user scope.
    status = NCryptOpenKey(result.provider.get(), result.key.put(), name.c_str(), 0, 0);
    if (status == ERROR_SUCCESS) {
        // The key already existed from a previous call - nothing left to
        // do, hand back what we've got. Returning `result` here moves it
        // out (see handle_traits.h's note on ScopedHandle's move
        // constructor); nothing is copied.
        return result;
    }
    // NTE_BAD_KEYSET is NCrypt's specific "no key with that name exists in
    // this provider yet" error - the one and only failure we're prepared to
    // recover from by creating a new key. Anything else (e.g. access
    // denied) is treated as a hard failure instead.
    if (status != NTE_BAD_KEYSET) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenKey failed");
    }

    // Key does not exist yet on this provider: create it.
    status = NCryptCreatePersistedKey(
        result.provider.get(), result.key.put(),
        NCRYPT_ECDH_P256_ALGORITHM, name.c_str(), 0, 0);
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptCreatePersistedKey failed");
    }

    // Before finalizing the new key, explicitly lock down what it's allowed
    // to be used for. These two NCryptSetProperty calls' return values are
    // deliberately not checked: they're best-effort hardening on top of
    // what's already the provider's own default policy (a freshly created
    // key isn't exportable and isn't usable for anything unless explicitly
    // enabled), not something this function's correctness depends on.
    DWORD export_policy = 0; // no NCRYPT_ALLOW_EXPORT_FLAG => non-exportable private key
    NCryptSetProperty(
        result.key.get(), NCRYPT_EXPORT_POLICY_PROPERTY,
        // NCryptSetProperty's data parameter is a generic `PBYTE` (pointer
        // to bytes); `reinterpret_cast<PBYTE>(&export_policy)` reinterprets
        // the address of our local DWORD as a byte pointer so its 4 bytes
        // can be handed over that way - the standard pattern for passing a
        // "plain old data" value through this kind of untyped API.
        reinterpret_cast<PBYTE>(&export_policy), sizeof(export_policy), 0);

    DWORD key_usage = NCRYPT_ALLOW_KEY_AGREEMENT_FLAG; // only ECDH key-agreement, nothing else
    NCryptSetProperty(
        result.key.get(), NCRYPT_KEY_USAGE_PROPERTY,
        reinterpret_cast<PBYTE>(&key_usage), sizeof(key_usage), 0);

    // NCryptFinalizeKey commits the key: after this call it's actually
    // usable and persisted to storage, and most of its properties
    // (including the two just set above) can no longer be changed.
    status = NCryptFinalizeKey(result.key.get(), 0);
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptFinalizeKey failed");
    }

    return result;
}

} // namespace

ResolvedKek ResolveOrCreateKekForWrap(const std::wstring& service) {
    // Try the TPM/vTPM-backed provider first...
    try {
        return ResolveOrCreateOnProvider(service, MS_PLATFORM_CRYPTO_PROVIDER, kProviderTypeTpm, kCurrentKeyId);
    } catch (const HkdfGuardError&) {
        // ...and if that throws for *any* reason (most commonly: this
        // machine simply has no TPM/vTPM, so NCryptOpenStorageProvider
        // itself failed above), silently fall through to try the software
        // provider instead - this empty `catch` block is the entire
        // implementation of the "automatic TPM -> software fallback"
        // requirement. Note the caught exception isn't examined or
        // rethrown; only HkdfGuardError is caught here (not `catch (...)`),
        // so a genuinely unexpected C++ exception type would still
        // propagate rather than being silently swallowed.
        // TPM/vTPM unavailable or unusable (no TPM, container without access,
        // etc.) - fall back to the software-backed provider automatically.
    }
    // Reaching this line means the try block above threw (and was caught);
    // if this call also throws, that exception propagates up to
    // hkdfguard.cpp uncaught by this function, which is correct - both
    // providers have now failed, and there's no further fallback.
    return ResolveOrCreateOnProvider(service, MS_KEY_STORAGE_PROVIDER, kProviderTypeSoftware, kCurrentKeyId);
}

ResolvedKek OpenKekForUnwrap(const std::wstring& service, uint8_t provider_type, uint32_t key_id) {
    ResolvedKek result;
    result.provider_type = provider_type;
    result.key_id = key_id;

    SECURITY_STATUS status = NCryptOpenStorageProvider(result.provider.put(), ProviderName(provider_type), 0);
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenStorageProvider failed");
    }

    // Unlike ResolveOrCreateOnProvider, this function only ever *opens* -
    // if NCryptOpenKey fails for any reason (including "doesn't exist"),
    // that's treated as an unconditional failure; unwrap must never create
    // a new KEK, since a newly-created key could never actually decrypt
    // anything wrapped under whatever KEK originally produced this payload.
    std::wstring name = KeyName(service, key_id);
    status = NCryptOpenKey(result.provider.get(), result.key.put(), name.c_str(), 0, 0);
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenKey failed");
    }

    return result;
}

void DeleteKek(const std::wstring& service, uint8_t provider_type, uint32_t key_id) {
    ScopedNCryptProv provider;
    SECURITY_STATUS status = NCryptOpenStorageProvider(provider.put(), ProviderName(provider_type), 0);
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenStorageProvider failed");
    }

    std::wstring name = KeyName(service, key_id);
    ScopedNCryptKey key;
    status = NCryptOpenKey(provider.get(), key.put(), name.c_str(), 0, 0);
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenKey failed");
    }

    // NCryptDeleteKey both removes the persisted key from storage *and*
    // invalidates the handle it's called with, as part of one operation -
    // unlike every other NCrypt function used in this project, which only
    // ever *uses* a handle and leaves closing it to us (via ScopedNCryptKey
    // later, or explicitly).
    status = NCryptDeleteKey(key.get(), 0);
    // Because NCryptDeleteKey already invalidated `key`'s handle above
    // (this is true even if the delete failed), we must not let
    // ScopedNCryptKey's destructor also try to close it - that would be a
    // double-close on an already-invalid handle. `key.release()` (see
    // handle_traits.h) tells `key` to forget the handle without closing it,
    // exactly for this situation.
    key.release(); // NCryptDeleteKey invalidates the handle even on failure; do not also free it
    if (status != ERROR_SUCCESS) {
        throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptDeleteKey failed");
    }
}

} // namespace hkdfguard
