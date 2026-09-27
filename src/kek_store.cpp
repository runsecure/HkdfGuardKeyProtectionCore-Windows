#include "kek_store.h"
#include "errors.h"
#include <string>
#include "policy.h"
#include "key_acl.h"

namespace hkdfguard {
    namespace {
        // Builds the actual name a KEK is persisted under in Windows' key storage:
        // e.g. service "myapp" and key_id 1 becomes L"hkdfguardwin_myapp_v1". The
        // `L"..."` prefix on each string literal marks it as a *wide* string literal
        // (an array of wchar_t, UTF-16 on Windows) rather than the narrow (char,
        // typically UTF-8/ASCII) literals used elsewhere in the project (like
        // hkdfguard.cpp's UTF-8 `service` parameter) - matching what
        // std::wstring/NCrypt's LPCWSTR key-name parameters need. `operator+` on
        // std::wstring concatenates, same as it does for std::string, so this whole
        // expression builds up the final name piece by piece into one new string.
        //
        // Every literal piece here is deliberately lowercase, matching
        // hkdfguard.cpp's NormalizeService, which lowercases `service` itself
        // before it ever reaches this function - so the fully-assembled name
        // is lowercase end to end, not just the caller-supplied portion of
        // it.
        std::wstring KeyName(const std::wstring &service, uint32_t key_id) {
            return L"hkdfguardwin_" + service + L"_v" + std::to_wstring(key_id);
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

        // Verifies the key is an ECDH key. Checks NCRYPT_ALGORITHM_GROUP_PROPERTY
        // ("Algorithm Group", e.g. "ECDH") rather than NCRYPT_ALGORITHM_PROPERTY
        // ("Algorithm Name", the curve-qualified AlgId originally passed to
        // NCryptCreatePersistedKey, e.g. "ECDH_P256"): at least one real TPM KSP
        // (an AMD fTPM's Microsoft Platform Crypto Provider) has been observed
        // reporting "Algorithm Name" as the bare algorithm family ("ECDH")
        // rather than the curve-qualified name it was created with, even though
        // the key genuinely is a P-256 key - the Software KSP, and presumably
        // other TPM KSPs, do preserve the curve-qualified name, but this
        // project can't assume every provider does. "Algorithm Group" is
        // consistently "ECDH" for an ECDH key on every provider observed
        // (curve-independent by definition), so checking it instead is
        // portable across providers without weakening this check: the curve
        // itself (P-256 specifically, not P-384/P-521) is independently
        // pinned by VerifyKeyLength below.
        void VerifyAlgorithm(
            NCRYPT_KEY_HANDLE key)
        {
            wchar_t algorithmGroup[64] = {};

            DWORD cbResult = 0;

            SECURITY_STATUS status =
                NCryptGetProperty(
                    key,
                    NCRYPT_ALGORITHM_GROUP_PROPERTY,
                    reinterpret_cast<PBYTE>(algorithmGroup),
                    sizeof(algorithmGroup),
                    &cbResult,
                    0);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "cannot query key algorithm group");
            }

            if (wcscmp(
                    algorithmGroup,
                    NCRYPT_ECDH_ALGORITHM_GROUP) != 0)
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

        // Verifies the key's reported usage permits the key-agreement
        // operation this project actually performs (NCryptSecretAgreement -
        // see ecdh_hkdf.cpp's DeriveWrappingKeyForUnwrap).
        //
        // Accepts NCRYPT_ALLOW_DECRYPT_FLAG as well as
        // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG: at least one real TPM KSP (an AMD
        // fTPM's Microsoft Platform Crypto Provider) has been observed
        // hard-pinning every freshly-created ECDH_P256 key's usage to
        // NCRYPT_ALLOW_DECRYPT_FLAG and rejecting any attempt to set
        // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG instead (NCryptSetProperty
        // returns NTE_NOT_SUPPORTED - see CreateKekOnProvider's comment on
        // that same call). Verified empirically that this is a labeling
        // quirk, not an actual capability restriction: a genuine
        // NCryptSecretAgreement call against such a key, using a real
        // ephemeral peer public key, succeeds and produces a correct shared
        // secret. An ECDH key has no meaningful "decrypt" operation of its
        // own on Windows CNG (NCryptDecrypt is for RSA-family keys) - by the
        // time this function runs, VerifyAlgorithm has already confirmed
        // the key's algorithm group genuinely is ECDH, so accepting the
        // Decrypt flag here only accommodates this provider's mislabeling
        // of a key already known to be ECDH; it does not admit any
        // different, unintended key type.
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
                 (NCRYPT_ALLOW_KEY_AGREEMENT_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG)) == 0)
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

        // Verify the key is hardware backed when we set the TpmRequired policy.
        //
        // Takes `provider` in addition to `key` because at least one real TPM
        // KSP (an AMD fTPM's Microsoft Platform Crypto Provider) has been
        // observed returning NTE_NOT_SUPPORTED for NCRYPT_IMPL_TYPE_PROPERTY
        // on every *key* handle it hands out (creation handle or freshly
        // reopened, doesn't matter) - the property is simply not implemented
        // at the key level on that provider - while the identical property
        // queried on the *provider* handle itself succeeds and correctly
        // reports NCRYPT_IMPL_HARDWARE_FLAG. Falling back to the provider
        // handle only when the key-level query specifically reports
        // NTE_NOT_SUPPORTED preserves the more precise per-key check on
        // providers that support it, while still failing closed (a genuine
        // query error, or a provider/key that isn't actually hardware
        // backed, still throws either way).
        void VerifyHardwareBacked(
            NCRYPT_KEY_HANDLE key,
            NCRYPT_PROV_HANDLE provider)
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

            if (status == NTE_NOT_SUPPORTED)
            {
                status =
                    NCryptGetProperty(
                        provider,
                        NCRYPT_IMPL_TYPE_PROPERTY,
                        reinterpret_cast<PBYTE>(&implType),
                        sizeof(implType),
                        &cbResult,
                        0);
            }

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
            NCRYPT_PROV_HANDLE provider,
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
                VerifyHardwareBacked(key, provider);
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
                result.provider.get(),
                policy,
                provider_type);

            return result;
        }

        // Opens the storage provider and reports whether the service's key
        // already exists there, without creating or modifying anything.
        // Throws HkdfGuardError for a genuine provider error; a missing key
        // (NTE_BAD_KEYSET) is reported via the return value, not an
        // exception.
        bool KekExistsOnProvider(
            const std::wstring& service,
            LPCWSTR providerName,
            uint32_t key_id)
        {
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

            std::wstring name =
                KeyName(service, key_id);

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
                return true;
            }

            if (status == NTE_BAD_KEYSET)
            {
                return false;
            }

            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                "NCryptOpenKey failed");
        }

        void CreateKekOnProvider(
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
                    provider.get(),
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

            // Best-effort, and deliberately NOT fatal if the provider
            // rejects it outright: at least one real TPM KSP (an AMD
            // fTPM's Microsoft Platform Crypto Provider) has been observed
            // returning NTE_NOT_SUPPORTED for this exact call on an
            // ECDH_P256 key, hard-pinning every such key's usage to
            // NCRYPT_ALLOW_DECRYPT_FLAG instead and refusing to change it -
            // even though the key is still fully functional for a genuine
            // NCryptSecretAgreement (verified empirically against real TPM
            // hardware: the "Decrypt" label is a provider quirk, not an
            // actual capability restriction). Treating this call's failure
            // as fatal made RequireTpm/PreferTpm unable to ever use a real
            // TPM on that class of hardware, with PreferTpm silently
            // falling back to the software provider instead of surfacing
            // the problem. VerifyKeyProperties below (via VerifyUsage,
            // which accepts NCRYPT_ALLOW_DECRYPT_FLAG as well as
            // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG for exactly this reason)
            // re-reads the key's *actual* resulting usage after
            // NCryptFinalizeKey and still fails closed if it's ever
            // genuinely missing both - that check, not this call's own
            // status, is what keeps the security guarantee intact.
            NCryptSetProperty(
                key.get(),
                NCRYPT_KEY_USAGE_PROPERTY,
                reinterpret_cast<PBYTE>(&keyUsage),
                sizeof(keyUsage),
                0);

            //
            // Grant the supplied groups unwrap/use access. Must happen before
            // NCryptFinalizeKey below - NCrypt key properties (including the
            // security descriptor) are only settable while the key is still
            // in its unfinalized, "provisional" state.
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

            // Verify against a *freshly-reopened* handle, not `key` (the one
            // still held from creation/finalization): at least one real TPM
            // KSP (an AMD fTPM's Microsoft Platform Crypto Provider) has
            // been observed reporting stale/incomplete property values -
            // NCRYPT_LENGTH_PROPERTY as 0 rather than 256 - when queried on
            // the creation handle immediately after NCryptFinalizeKey,
            // while the exact same property on a freshly-opened handle for
            // the identical, already-finalized key correctly reports 256.
            // The Software KSP doesn't exhibit this (its creation handle
            // already reports accurate values), but reopening costs little
            // and this is what makes verification reliable on both.
            ScopedNCryptKey verifyKey;

            status =
                NCryptOpenKey(
                    provider.get(),
                    verifyKey.put(),
                    name.c_str(),
                    0,
                    NCRYPT_MACHINE_KEY_FLAG);

            if (status != ERROR_SUCCESS)
            {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "NCryptOpenKey (post-finalize verification) failed");
            }

            VerifyKeyProperties(
                verifyKey.get(),
                provider.get(),
                policy,
                providerType);

            VerifyKeyAcl(
                verifyKey.get(),
                aclGroups);
        }
    } // namespace

    bool KekExists(
        const std::wstring& service)
    {
        KeyStoragePolicy policy =
            LoadEffectivePolicy();

        switch (policy)
        {
            case KeyStoragePolicy::RequireTpm:
                return KekExistsOnProvider(
                    service,
                    MS_PLATFORM_CRYPTO_PROVIDER,
                    kCurrentKeyId);

            case KeyStoragePolicy::SoftwareOnly:
                return KekExistsOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kCurrentKeyId);

            case KeyStoragePolicy::PreferTpm:
                if (KekExistsOnProvider(
                        service,
                        MS_PLATFORM_CRYPTO_PROVIDER,
                        kCurrentKeyId))
                {
                    return true;
                }

                return KekExistsOnProvider(
                    service,
                    MS_KEY_STORAGE_PROVIDER,
                    kCurrentKeyId);
        }

        throw HkdfGuardError(
            HKDFGUARD_ERR_INVALID_POLICY,
            "invalid key storage policy");
    }

    void CreateKek(
        const std::wstring& service,
        const std::vector<std::wstring>& aclGroups)
    {
        KeyStoragePolicy policy =
            LoadEffectivePolicy();

        switch (policy)
        {
            case KeyStoragePolicy::RequireTpm:
            {
                CreateKekOnProvider(
                    service,
                    MS_PLATFORM_CRYPTO_PROVIDER,
                    kProviderTypeTpm,
                    aclGroups,
                    policy);

                return;
            }

            case KeyStoragePolicy::SoftwareOnly:
            {
                CreateKekOnProvider(
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
                    CreateKekOnProvider(
                        service,
                        MS_PLATFORM_CRYPTO_PROVIDER,
                        kProviderTypeTpm,
                        aclGroups,
                        policy);
                }
                catch (const HkdfGuardError&)
                {
                    CreateKekOnProvider(
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

        // Unlike CreateKekOnProvider, this function only ever *opens* -
        // if NCryptOpenKey fails for any reason (including "doesn't exist"),
        // that's treated as an unconditional failure; unwrap must never create
        // a new KEK, since a newly-created key could never actually decrypt
        // anything wrapped under whatever KEK originally produced this payload.
        // NCRYPT_MACHINE_KEY_FLAG must match what the key was created with
        // (see CreateKekOnProvider) - this is exactly what lets an
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
            result.provider.get(),
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
