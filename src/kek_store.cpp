#include "kek_store.h"
#include "errors.h"
#include <string>
#include "policy.h"
#include "key_acl.h"

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
        LPCWSTR ProviderName(
            uint8_t provider_type)
        {
            switch (provider_type)
            {
                case kProviderTypeTpm:
                    return MS_PLATFORM_CRYPTO_PROVIDER;

                case kProviderTypeSoftware:
                    return MS_KEY_STORAGE_PROVIDER;

                default:
                    throw HkdfGuardError(
                        HKDFGUARD_ERR_PROVIDER,
                        "invalid provider type");
            }
        }

        // Verifies the Algorithm is P256
        void VerifyAlgorithm(
            NCRYPT_KEY_HANDLE key)
        {
            wchar_t algorithm[64] = {};

            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_ALGORITHM_PROPERTY,
                    reinterpret_cast<PBYTE>(algorithm),
                    sizeof(algorithm),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key algorithm");
            }

            if (wcscmp(
                    algorithm,
                    NCRYPT_ECDH_P256_ALGORITHM) != 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "unexpected key algorithm");
            }
        }

        // Additional verification that key length is 256
        void VerifyKeyLength(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD length = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_LENGTH_PROPERTY,
                    reinterpret_cast<PBYTE>(&length),
                    sizeof(length),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key length");
            }

            if (length != 256)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "unexpected key length");
            }
        }

        // Verifies the Usage is allow key agreement
        void VerifyUsage(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD usage = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    reinterpret_cast<PBYTE>(&usage),
                    sizeof(usage),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key usage");
            }

            if ((usage &
                 NCRYPT_ALLOW_KEY_AGREEMENT_FLAG) == 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key agreement usage missing");
            }
        }

        // Verifies there is no export agreement
        void VerifyExportPolicy(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD policy = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    reinterpret_cast<PBYTE>(&policy),
                    sizeof(policy),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query export policy");
            }

            if (policy &
                (NCRYPT_ALLOW_EXPORT_FLAG |
                 NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG))
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key unexpectedly exportable");
            }
        }

        // Verify the key is hardware backed when we set the TpmRequired policy
        void VerifyHardwareBacked(
            NCRYPT_KEY_HANDLE key)
        {
            DWORD implType = 0;
            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_IMPL_TYPE_PROPERTY,
                    reinterpret_cast<PBYTE>(&implType),
                    sizeof(implType),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query implementation type");
            }

            if ((implType & NCRYPT_IMPL_HARDWARE_FLAG) == 0)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "key is not hardware backed");
            }
        }

        void VerifyKeyProperties(
            NCRYPT_KEY_HANDLE key,
            KeyStoragePolicy policy,
            uint8_t provider_type)
        {
            VerifyAlgorithm(key);
            VerifyKeyLength(key);
            VerifyUsage(key);
            VerifyExportPolicy(key);

            if (policy == KeyStoragePolicy::RequireTpm ||
                provider_type == kProviderTypeTpm)
            {
                VerifyHardwareBacked(key);
            }
        }

        ResolvedKek OpenKekOnProvider(
            const std::wstring& service,
            LPCWSTR provider_name,
            uint8_t provider_type,
            uint32_t key_id,
            KeyStoragePolicy policy)
        {
            ResolvedKek result;

            result.provider_type = provider_type;
            result.key_id = key_id;

            SECURITY_STATUS status =
                NCryptOpenStorageProvider(
                    result.provider.put(),
                    provider_name,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptOpenStorageProvider failed");
            }

            std::wstring name =
                KeyName(service, key_id);

            status =
                NCryptOpenKey(
                    result.provider.get(),
                    result.key.put(),
                    name.c_str(),
                    0,
                    NCRYPT_MACHINE_KEY_FLAG);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptOpenKey failed");
            }

            VerifyKeyProperties(
                result.key.get(),
                policy,
                provider_type);

            return result;
        }

        void EnsureKekOnProvider(
            const std::wstring& service,
            LPCWSTR providerName,
            uint8_t providerType,
            const std::vector<std::wstring>& aclGroups,
            KeyStoragePolicy policy)
        {
            //
            // Open provider.
            //

            ScopedNCryptProv provider;

            SECURITY_STATUS status =
                NCryptOpenStorageProvider(
                    provider.put(),
                    providerName,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptOpenStorageProvider failed");
            }

            //
            // Open existing key.
            //

            std::wstring name =
                KeyName(
                    service,
                    kCurrentKeyId);

            ScopedNCryptKey key;

            status =
                NCryptOpenKey(
                    provider.get(),
                    key.put(),
                    name.c_str(),
                    0,
                    NCRYPT_MACHINE_KEY_FLAG);

            if (status == ERROR_SUCCESS)
            {
                VerifyKeyProperties(
                    key.get(),
                    policy,
                    providerType);

                return;
            }

            if (status != NTE_BAD_KEYSET)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptOpenKey failed");
            }

            //
            // Create missing key.
            //

            status =
                NCryptCreatePersistedKey(
                    provider.get(),
                    key.put(),
                    NCRYPT_ECDH_P256_ALGORITHM,
                    name.c_str(),
                    0,
                    NCRYPT_MACHINE_KEY_FLAG);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptCreatePersistedKey failed");
            }

            DWORD exportPolicy = 0;

            status =
                NCryptSetProperty(
                    key.get(),
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    reinterpret_cast<PBYTE>(&exportPolicy),
                    sizeof(exportPolicy),
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "setting export policy failed");
            }

            DWORD keyUsage =
                NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;

            status =
                NCryptSetProperty(
                    key.get(),
                    NCRYPT_KEY_USAGE_PROPERTY,
                    reinterpret_cast<PBYTE>(&keyUsage),
                    sizeof(keyUsage),
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "setting key usage failed");
            }

            //
            // NEW:
            //

            ApplyKeyAcl(
                key.get(),
                aclGroups);

            status =
                NCryptFinalizeKey(
                    key.get(),
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptFinalizeKey failed");
            }

            VerifyKeyProperties(
                key.get(),
                policy,
                providerType);

            VerifyKeyAcl(
                key.get(),
                aclGroups);
        }
    } // namespace

    void EnsureKek(
        const std::wstring& service,
        const std::vector<std::wstring>& aclGroups)
    {
        KeyStoragePolicy policy =
            LoadEffectivePolicy();

        switch (policy)
        {
            case KeyStoragePolicy::RequireTpm:
            {
                EnsureKekOnProvider(
                    service,
                    MS_PLATFORM_CRYPTO_PROVIDER,
                    kProviderTypeTpm,
                    aclGroups,
                    policy);

                return;
            }

            case KeyStoragePolicy::SoftwareOnly:
            {
                EnsureKekOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kProviderTypeSoftware,
                    aclGroups,
                    policy);

                return;
            }

            case KeyStoragePolicy::PreferTpm:
            {
                try
                {
                    EnsureKekOnProvider(
                        service,
                        MS_PLATFORM_CRYPTO_PROVIDER,
                        kProviderTypeTpm,
                        aclGroups,
                        policy);
                }
                catch (const HkdfGuardError&)
                {
                    EnsureKekOnProvider(
                        service,
                        MS_KEY_STORAGE_PROVIDER,
                        kProviderTypeSoftware,
                        aclGroups,
                        policy);
                }

                return;
            }
        }

        throw HkdfGuardError(
            HKDFGUARD_ERR_INVALID_POLICY,
            "invalid key storage policy");
    }

    ResolvedKek OpenKekForWrap(
        const std::wstring& service)
    {
        KeyStoragePolicy policy = LoadEffectivePolicy();

        switch (policy) {

            case KeyStoragePolicy::RequireTpm:
                return OpenKekOnProvider(
                    service,
                    MS_PLATFORM_CRYPTO_PROVIDER,
                    kProviderTypeTpm,
                    kCurrentKeyId,
                    policy);

            case KeyStoragePolicy::SoftwareOnly:
                return OpenKekOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kProviderTypeSoftware,
                    kCurrentKeyId,
                    policy);

            case KeyStoragePolicy::PreferTpm:
                try {
                    return OpenKekOnProvider(
                        service,
                        MS_PLATFORM_CRYPTO_PROVIDER,
                        kProviderTypeTpm,
                        kCurrentKeyId,
                        policy);
                }
                catch (const HkdfGuardError&) {
                    return OpenKekOnProvider(
                        service,
                        MS_KEY_STORAGE_PROVIDER,
                        kProviderTypeSoftware,
                        kCurrentKeyId,
                        policy);
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

        KeyStoragePolicy policy = LoadEffectivePolicy();

        VerifyKeyProperties(
            result.key.get(),
            policy,
            result.provider_type);

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
