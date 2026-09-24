#include "kek_store.h"
#include "errors.h"
#include <string>
#include "policy.h"

namespace hkdfguard {
    namespace {
        //KEK Storage Location policy
        static constexpr KeyStoragePolicy kDefaultPolicy = KeyStoragePolicy::PreferTpm;

        // Builds the actual name a KEK is persisted under in Windows' key storage:
        // e.g. service "myapp" and key_id 1 becomes L"HkdfGuardWin_myapp_v1". The
        // `L"..."` prefix on each string literal marks it as a *wide* string literal
        // (an array of wchar_t, UTF-16 on Windows) rather than the narrow (char,
        // typically UTF-8/ASCII) literals used elsewhere in the project (like
        // hkdfguard.cpp's UTF-8 `service` parameter) - matching what
        // std::wstring/NCrypt's LPCWSTR key-name parameters need. `operator+` on
        // std::wstring concatenates, same as it does for std::string, so this whole
        // expression builds up the final name piece by piece into one new string.
        std::wstring KeyName(const std::wstring &service, uint32_t key_id) {
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
        // it (non-exportable, key-agreement-only, machine-wide scoped) if it does
        // not yet exist. Throws HkdfGuardError(HKDFGUARD_ERR_PROVIDER) on any
        // failure, including the provider itself being unavailable.
        ResolvedKek ResolveOrCreateOnProvider(
            const std::wstring &service, LPCWSTR provider_name, uint8_t provider_type, uint32_t key_id) {
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

            // NCRYPT_MACHINE_KEY_FLAG => this key lives in the machine-wide key
            // store, not the calling account's own profile: any local account can
            // open/use it (subject to the key's ACL, left at NCrypt's default for
            // a machine key), not only the one that created it. This is
            // deliberate - the deployment model this project targets is "a
            // deployment-time process, typically elevated, wraps a DEK once; a
            // different, lower-privileged service account unwraps it later" - see
            // OpenKekForUnwrap below, which must request the same flag for that
            // second account's NCryptOpenKey to find this key at all (per-user and
            // machine-wide are two disjoint key stores from NCrypt's perspective,
            // not a fallback chain).
            status = NCryptOpenKey(result.provider.get(), result.key.put(), name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG);
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

            // Key does not exist yet on this provider: create it, machine-wide
            // (see the NCryptOpenKey call above for why). Creating a machine key
            // requires the calling process to be running elevated - by design, per
            // the deployment model this targets: an elevated deployment-time
            // utility calls hkdfguard_wrap_dek once (which creates the KEK on
            // first use), and the lower-privileged account that unwraps it later
            // never needs to create anything.
            status = NCryptCreatePersistedKey(
                result.provider.get(), result.key.put(),
                NCRYPT_ECDH_P256_ALGORITHM, name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG);
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

    ResolvedKek ResolveOrCreateKekForWrap(
    const std::wstring& service)
    {
        switch (LoadEffectivePolicy()) {

            case KeyStoragePolicy::RequireTpm:
                return ResolveOrCreateOnProvider(
                    service,
                    MS_PLATFORM_CRYPTO_PROVIDER,
                    kProviderTypeTpm,
                    kCurrentKeyId);

            case KeyStoragePolicy::SoftwareOnly:
                return ResolveOrCreateOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kProviderTypeSoftware,
                    kCurrentKeyId);

            case KeyStoragePolicy::PreferTpm:
                try {
                    return ResolveOrCreateOnProvider(
                        service,
                        MS_PLATFORM_CRYPTO_PROVIDER,
                        kProviderTypeTpm,
                        kCurrentKeyId);
                }
                catch (const HkdfGuardError&) {
                    return ResolveOrCreateOnProvider(
                        service,
                        MS_KEY_STORAGE_PROVIDER,
                        kProviderTypeSoftware,
                        kCurrentKeyId);
                }
        }

        throw HkdfGuardError(
            HKDFGUARD_ERR_INVALID_POLICY,
            "invalid key storage policy");
    }

    ResolvedKek OpenKekForUnwrap(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
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
        // NCRYPT_MACHINE_KEY_FLAG must match what the key was created with
        // (see ResolveOrCreateOnProvider) - this is exactly what lets an
        // account other than the one that wrapped the DEK successfully find
        // and use this key: opening without the flag would search that
        // account's own per-user key store instead, where this key was never
        // created, and fail with NTE_BAD_KEYSET regardless of privileges.
        std::wstring name = KeyName(service, key_id);
        status = NCryptOpenKey(result.provider.get(), result.key.put(), name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenKey failed");
        }

        return result;
    }

    void DeleteKek(const std::wstring &service, uint8_t provider_type, uint32_t key_id) {
        ScopedNCryptProv provider;
        SECURITY_STATUS status = NCryptOpenStorageProvider(provider.put(), ProviderName(provider_type), 0);
        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(HKDFGUARD_ERR_PROVIDER, "NCryptOpenStorageProvider failed");
        }

        std::wstring name = KeyName(service, key_id);
        ScopedNCryptKey key;
        // Same NCRYPT_MACHINE_KEY_FLAG requirement as OpenKekForUnwrap above -
        // this key was created machine-wide, so it must also be opened (in
        // order to then be deleted) machine-wide.
        status = NCryptOpenKey(provider.get(), key.put(), name.c_str(), 0, NCRYPT_MACHINE_KEY_FLAG);
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
