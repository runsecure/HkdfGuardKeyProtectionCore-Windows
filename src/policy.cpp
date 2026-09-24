#include "policy.h"

#include <windows.h>

namespace hkdfguard {

    namespace {

        // Administratively-managed policy location.
        //
        // Intended to be deployable via:
        //
        //   Group Policy Preferences
        //   Intune
        //   DSC
        //   SCCM
        //   Manual registry configuration
        //
        constexpr wchar_t kPolicyKey[] =
            L"Software\\Policies\\HkdfGuard";

        constexpr wchar_t kPolicyValue[] =
            L"KeyStoragePolicy";

        // Security-focused default.
        //
        // Existing behavior today is:
        //   TPM if available
        //   otherwise software provider
        //
        constexpr KeyStoragePolicy kDefaultPolicy =
            KeyStoragePolicy::PreferTpm;

    } // namespace

    KeyStoragePolicy LoadEffectivePolicy() noexcept
    {
        HKEY key = nullptr;

        LONG status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            kPolicyKey,
            0,
            KEY_QUERY_VALUE,
            &key);

        if (status != ERROR_SUCCESS) {
            return kDefaultPolicy;
        }

        DWORD value = 0;
        DWORD type = 0;
        DWORD size = sizeof(value);

        status = RegQueryValueExW(
            key,
            kPolicyValue,
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);

        RegCloseKey(key);

        if (status != ERROR_SUCCESS) {
            return kDefaultPolicy;
        }

        if (type != REG_DWORD) {
            return kDefaultPolicy;
        }

        switch (value) {

            case static_cast<DWORD>(KeyStoragePolicy::PreferTpm):
                return KeyStoragePolicy::PreferTpm;

            case static_cast<DWORD>(KeyStoragePolicy::RequireTpm):
                return KeyStoragePolicy::RequireTpm;

            case static_cast<DWORD>(KeyStoragePolicy::SoftwareOnly):
                return KeyStoragePolicy::SoftwareOnly;

            default:
                // Unknown administrator value.
                // Fail safely.
                return kDefaultPolicy;
        }
    }

} // namespace hkdfguard