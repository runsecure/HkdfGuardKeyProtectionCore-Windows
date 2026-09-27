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

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        // See SetTestPolicyOverride/LoadEffectivePolicy in policy.h. Empty by
        // default, so a test binary that never calls SetTestPolicyOverride
        // still falls through to the real registry read below.
        std::optional<KeyStoragePolicy> g_testPolicyOverride;
#endif

    } // namespace

#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
    void SetTestPolicyOverride(std::optional<KeyStoragePolicy> policy) noexcept
    {
        g_testPolicyOverride = policy;
    }
#endif

    KeyStoragePolicy LoadEffectivePolicy() noexcept
    {
#if defined(HKDFGUARD_ENABLE_TEST_POLICY_OVERRIDE)
        if (g_testPolicyOverride.has_value())
        {
            return *g_testPolicyOverride;
        }
#endif

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