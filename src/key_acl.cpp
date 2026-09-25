#include "key_acl.h"
#include "errors.h"

#include <windows.h>
#include <aclapi.h>

#include <optional>
#include <string>
#include <vector>

namespace hkdfguard {
    namespace {
        using SidBuffer = std::vector<BYTE>;

        constexpr ACCESS_MASK kKekAdminAccess =
                GENERIC_ALL;

        constexpr ACCESS_MASK kKekUseAccess =
                GENERIC_READ;

        SidBuffer CreateWellKnownSidBuffer(
            WELL_KNOWN_SID_TYPE type) {
            DWORD size = SECURITY_MAX_SID_SIZE;

            SidBuffer sid(size);

            if (!CreateWellKnownSid(
                type,
                nullptr,
                sid.data(),
                &size)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "CreateWellKnownSid failed");
            }

            sid.resize(size);

            return sid;
        }

        SidBuffer ResolveAccountSid(
            const std::wstring &accountName) {
            DWORD sidSize = 0;
            DWORD domainSize = 0;
            SID_NAME_USE sidType;

            LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                nullptr,
                &sidSize,
                nullptr,
                &domainSize,
                &sidType);

            if (sidSize == 0) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "unable to resolve account SID");
            }

            SidBuffer sid(sidSize);

            std::wstring domain(
                domainSize,
                L'\0');

            if (!LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                sid.data(),
                &sidSize,
                domain.data(),
                &domainSize,
                &sidType)) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "unable to resolve account SID");
            }

            sid.resize(sidSize);

            return sid;
        }

        std::optional<SidBuffer> TryResolveAccountSid(
            const std::wstring &accountName) {
            DWORD sidSize = 0;
            DWORD domainSize = 0;
            SID_NAME_USE sidType;

            LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                nullptr,
                &sidSize,
                nullptr,
                &domainSize,
                &sidType);

            if (sidSize == 0) {
                return std::nullopt;
            }

            SidBuffer sid(sidSize);

            std::wstring domain(
                domainSize,
                L'\0');

            if (!LookupAccountNameW(
                nullptr,
                accountName.c_str(),
                sid.data(),
                &sidSize,
                domain.data(),
                &domainSize,
                &sidType)) {
                return std::nullopt;
            }

            sid.resize(sidSize);

            return sid;
        }

        EXPLICIT_ACCESSW BuildAccessEntry(
            PSID sid,
            ACCESS_MASK accessMask) {
            EXPLICIT_ACCESSW entry{};

            entry.grfAccessPermissions =
                    accessMask;

            entry.grfAccessMode =
                    GRANT_ACCESS;

            entry.grfInheritance =
                    NO_INHERITANCE;

            entry.Trustee.TrusteeForm =
                    TRUSTEE_IS_SID;

            entry.Trustee.TrusteeType =
                    TRUSTEE_IS_GROUP;

            entry.Trustee.ptstrName =
                    static_cast<LPWSTR>(sid);

            return entry;
        }

        void AddFullControlAce(
            std::vector<EXPLICIT_ACCESSW> &entries,
            SidBuffer &sid) {
            entries.push_back(
                BuildAccessEntry(
                    sid.data(),
                    kKekAdminAccess));
        }

        void AddKeyUseAce(
            std::vector<EXPLICIT_ACCESSW> &entries,
            SidBuffer &sid) {
            entries.push_back(
                BuildAccessEntry(
                    sid.data(),
                    kKekUseAccess));
        }

        bool DaclContainsSid(
            PACL acl,
            PSID expectedSid) {
            for (DWORD i = 0;
                 i < acl->AceCount;
                 ++i) {
                void *ace = nullptr;

                if (!GetAce(
                    acl,
                    i,
                    &ace)) {
                    continue;
                }

                auto *header =
                        static_cast<ACE_HEADER *>(ace);

                if (header->AceType !=
                    ACCESS_ALLOWED_ACE_TYPE) {
                    continue;
                }

                auto *allowed =
                        static_cast<ACCESS_ALLOWED_ACE *>(ace);

                PSID sid =
                        &allowed->SidStart;

                if (EqualSid(
                    sid,
                    expectedSid)) {
                    return true;
                }
            }

            return false;
        }

        void VerifyPrincipalPresent(
            PACL acl,
            const SidBuffer &sid) {
            if (!DaclContainsSid(
                acl,
                const_cast<BYTE *>(
                    sid.data()))) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "expected princip*l missing from key ACL");
            }
        }

        std::vector<BYTE> BuildSecurityDescriptor(
            const std::vector<std::wstring> &additionalGroups) {
            std::vector<EXPLICIT_ACCESSW> entries;

            auto systemSid =
                    CreateWellKnownSidBuffer(
                        WinLocalSystemSid);

            AddFullControlAce(
                entries,
                systemSid);

            auto adminSid =
                    CreateWellKnownSidBuffer(
                        WinBuiltinAdministratorsSid);

            AddFullControlAce(
                entries,
                adminSid);

            std::vector<SidBuffer> optionalSids;

            if (auto group =
                    TryResolveAccountSid(
                        kHkdfGuardAdminsGroup)) {
                optionalSids.push_back(
                    std::move(*group));

                AddFullControlAce(
                    entries,
                    optionalSids.back());
            }

            if (auto group =
                    TryResolveAccountSid(
                        kHkdfGuardUsersGroup)) {
                optionalSids.push_back(
                    std::move(*group));

                AddKeyUseAce(
                    entries,
                    optionalSids.back());
            }

            for (const auto &name: additionalGroups) {
                optionalSids.push_back(
                    ResolveAccountSid(name));

                AddKeyUseAce(
                    entries,
                    optionalSids.back());
            }

            PACL acl = nullptr;

            DWORD status =
                    SetEntriesInAclW(
                        static_cast<ULONG>(entries.size()),
                        entries.data(),
                        nullptr,
                        &acl);

            if (status != ERROR_SUCCESS) {
                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "SetEntriesInAclW failed");
            }

            SECURITY_DESCRIPTOR sd{};

            if (!InitializeSecurityDescriptor(
                &sd,
                SECURITY_DESCRIPTOR_REVISION)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "InitializeSecurityDescriptor failed");
            }

            if (!SetSecurityDescriptorDacl(
                &sd,
                TRUE,
                acl,
                FALSE)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "SetSecurityDescriptorDacl failed");
            }

            DWORD requiredSize = 0;

            MakeSelfRelativeSD(
                &sd,
                nullptr,
                &requiredSize);

            std::vector<BYTE> result(
                requiredSize);

            if (!MakeSelfRelativeSD(
                &sd,
                reinterpret_cast<PSECURITY_DESCRIPTOR>(
                    result.data()),
                &requiredSize)) {
                LocalFree(acl);

                throw HkdfGuardError(
                    HKDFGUARD_ERR_PROVIDER,
                    "MakeSelfRelativeSD failed");
            }

            LocalFree(acl);

            return result;
        }
    } // namespace

    void ApplyKeyAcl(
        NCRYPT_KEY_HANDLE key,
        const std::vector<std::wstring> &additionalGroups) {
        auto descriptor =
                BuildSecurityDescriptor(
                    additionalGroups);

        SECURITY_STATUS status =
                NCryptSetProperty(
                    key,
                    NCRYPT_SECURITY_DESCR_PROPERTY,
                    descriptor.data(),
                    static_cast<DWORD>(descriptor.size()),
                    DACL_SECURITY_INFORMATION);

        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                "failed to apply key ACL");
        }
    }

    void VerifyKeyAcl(
        NCRYPT_KEY_HANDLE key,
        const std::vector<std::wstring> &additionalGroups) {
        //
        // Read security descriptor
        //

        DWORD size = 0;

        SECURITY_STATUS status = NCryptGetProperty(
            key,
            NCRYPT_SECURITY_DESCR_PROPERTY,
            nullptr,
            0,
            &size,
            DACL_SECURITY_INFORMATION);

        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                "unable to read key ACL");
        }

        std::vector<BYTE> descriptor(size);

        status =
                NCryptGetProperty(
                    key,
                    NCRYPT_SECURITY_DESCR_PROPERTY,
                    descriptor.data(),
                    size,
                    &size,
                    DACL_SECURITY_INFORMATION);

        if (status != ERROR_SUCCESS) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                "unable to read key ACL");
        }

        PACL acl = nullptr;
        BOOL present = FALSE;
        BOOL defaulted = FALSE;

        if (!GetSecurityDescriptorDacl(
            reinterpret_cast<PSECURITY_DESCRIPTOR>(
                descriptor.data()),
            &present,
            &acl,
            &defaulted)) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                "unable to parse key ACL");
        }

        if (!present || acl == nullptr) {
            throw HkdfGuardError(
                HKDFGUARD_ERR_PROVIDER,
                "key ACL missing");
        }

        //
        // Verify SYSTEM
        //

        VerifyPrincipalPresent(
            acl,
            CreateWellKnownSidBuffer(
                WinLocalSystemSid));

        //
        // Verify Administrators
        //

        VerifyPrincipalPresent(
            acl,
            CreateWellKnownSidBuffer(
                WinBuiltinAdministratorsSid));

        //
        // Optional groups
        //

        if (auto sid =
                TryResolveAccountSid(
                    kHkdfGuardAdminsGroup)) {
            VerifyPrincipalPresent(
                acl,
                *sid);
        }

        if (auto sid =
                TryResolveAccountSid(
                    kHkdfGuardUsersGroup)) {
            VerifyPrincipalPresent(
                acl,
                *sid);
        }

        for (const auto &group: additionalGroups) {
            VerifyPrincipalPresent(
                acl,
                ResolveAccountSid(group));
        }
    }
} // namespace hkdfguard
