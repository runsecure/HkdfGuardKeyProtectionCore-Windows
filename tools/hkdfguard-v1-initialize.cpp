// CLI tool: wraps a caller-supplied Data Encryption Key (DEK) under a
// persistent, machine-wide, TPM-backed (or software-fallback) KEK and
// writes the wrapped payload to a file.
//
// Calls into hkdfguard.dll through its stable C ABI (hkdfguard_wrap_dek),
// the same interface any other-language caller uses - this tool links only
// against include/hkdfguard.h and the hkdfguard import library, nothing
// from src/. Mirrors this project's macOS and Linux equivalents
// (hkdfguard-v1-initialize) argument-for-argument, with one Windows-only
// addition: --group|-g. Windows has no POSIX-style implicit "group" the
// way 0640 relies on for those two platforms, so the caller names one
// explicitly here instead.
//
// The KEK's `service` identity is `<service-name>.<material-identifier>`:
// the material identifier lets one logical service own up to 256 distinct
// KEKs (e.g. for key rotation), each addressed by its own `service` string
// under the hood.
//
// Usage:
//   hkdfguard-v1-initialize <key-file-path> \
//       --material-identifier|-mi <1-256> \
//       --service-name|-sn <name> \
//       --dek|-d <base64> \
//       --group|-g <name> \
//       [--force|-f]
//
// The wrapped payload is written to <key-file-path> with an explicit,
// non-inherited DACL: the calling account (the process token's owner SID)
// gets read+write, --group's account gets read-only, and no one else is
// granted anything - the Windows analog of this project's macOS/Linux
// tools' POSIX 0640 (owner rw, one group r, no one else). Set atomically
// at file-creation time via CreateFileW's own security-attributes
// parameter, not applied after the fact.
//
// With --force against a pre-existing file, that file's old contents are
// securely overwritten in place (8 alternating all-zero/random passes,
// each flushed before the next starts) and deleted before the new file is
// created - see SecureOverwriteAndRemoveIfExists/WriteWrappedKeyFile below
// for the exact sequence and its one intentional fallback, matching this
// project's macOS implementation pass-for-pass. Only ever runs when
// --force is passed; without it, an existing file is never touched at all
// (WriteWrappedKeyFile's plain CREATE_NEW fails outright instead).
//
// Note: --dek on the command line is visible to other processes on the
// same host (e.g. via a WMI process/command-line query) for the life of
// this process, like any command-line argument. That's a general
// limitation of passing secrets on argv, not specific to this tool.

#include "hkdfguard.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

constexpr wchar_t kProgramName[] = L"hkdfguard-v1-initialize";
constexpr long kMaterialIdentifierMin = 1;
constexpr long kMaterialIdentifierMax = 256;
constexpr size_t kDekLen = 32;
// Generous starting capacity for the wrapped payload - retried once at the
// library-reported size on HKDFGUARD_ERR_BUFFER_TOO_SMALL, so this only
// needs to be a reasonable common case, not an absolute upper bound.
// Matches the macOS/Linux tools' own initial-capacity constant.
constexpr int32_t kInitialWrappedCapacity = 512;
// Number of secure-overwrite passes SecureOverwriteAndRemoveIfExists below
// performs on a pre-existing file before deleting it, alternating an
// all-zero pass and a random-bytes pass, four times each.
constexpr size_t kSecureOverwritePassCount = 8;

// This tool's own operational-error type - deliberately not reusing the
// DLL's internal HkdfGuardError (src/errors.h), since this tool depends
// only on the public C ABI (include/hkdfguard.h) and the import library,
// nothing from src/. Carries a wide message directly (rather than a narrow
// std::string) since almost everything this tool reports on - file paths,
// group/service names, FormatMessageW output - is naturally wide already;
// this avoids constant narrow/wide conversion at every throw site.
struct CliError {
    std::wstring message;
    explicit CliError(std::wstring m) : message(std::move(m)) {}
};

// Renders a Win32 error code (as returned by GetLastError(), or an NTSTATUS
// cast to DWORD for a BCrypt failure) as a human-readable string, the
// standard documented FormatMessageW idiom.
std::wstring FormatWin32Error(DWORD code) {
    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring result = (len > 0 && buf != nullptr) ? std::wstring(buf, len) : L"(unknown error)";
    if (buf != nullptr) {
        LocalFree(buf);
    }
    // FormatMessageW's system messages typically end in "\r\n"; trim it so
    // callers can embed the result mid-sentence without a stray line break.
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) {
        result.pop_back();
    }
    return result;
}

// Minimal RAII wrapper for a Win32 file HANDLE - this tool's own local
// copy of the same idea src/handle_traits.h uses for NCrypt/BCrypt handles
// elsewhere in this project, kept local since this tool intentionally
// depends only on the public hkdfguard.h header, nothing from src/.
class ScopedFileHandle {
public:
    explicit ScopedFileHandle(HANDLE h = INVALID_HANDLE_VALUE) : handle_(h) {}
    ~ScopedFileHandle() { reset(); }
    ScopedFileHandle(const ScopedFileHandle&) = delete;
    ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;

    void reset(HANDLE h = INVALID_HANDLE_VALUE) {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            CloseHandle(handle_);
        }
        handle_ = h;
    }
    HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr; }

private:
    HANDLE handle_;
};

// MARK: - Argument parsing

struct Args {
    std::wstring keyFilePath;
    long materialIdentifier = 0;
    std::wstring serviceName;
    std::wstring dekBase64;
    std::wstring groupName;
    bool force = false;
};

enum class ParseOutcome { Run, Help };

void PrintUsage() {
    fwprintf(
        stderr,
        L"Usage: %ls <key-file-path> --material-identifier|-mi <%ld-%ld> --service-name|-sn <name> "
        L"--dek|-d <base64> --group|-g <name> [--force|-f]\n",
        kProgramName, kMaterialIdentifierMin, kMaterialIdentifierMax);
}

// Throws CliError on any parse failure; returns ParseOutcome::Help if
// --help/-h was seen (in which case `out` is left unpopulated - the caller
// must check the return value before using `out`).
ParseOutcome ParseArgs(int argc, wchar_t* argv[], Args& out) {
    std::optional<std::wstring> keyFilePath;
    std::optional<long> materialIdentifier;
    std::optional<std::wstring> serviceName;
    std::optional<std::wstring> dekBase64;
    std::optional<std::wstring> groupName;
    bool force = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h") {
            return ParseOutcome::Help;
        } else if (arg == L"--force" || arg == L"-f") {
            force = true;
        } else if (arg == L"--material-identifier" || arg == L"-mi") {
            if (i + 1 >= argc) {
                throw CliError(arg + L" requires a value");
            }
            std::wstring value = argv[++i];
            wchar_t* end = nullptr;
            long parsed = wcstol(value.c_str(), &end, 10);
            if (end == value.c_str() || *end != L'\0') {
                throw CliError(L"--material-identifier must be an integer, got \"" + value + L"\"");
            }
            if (parsed < kMaterialIdentifierMin || parsed > kMaterialIdentifierMax) {
                throw CliError(
                    L"--material-identifier must be between " + std::to_wstring(kMaterialIdentifierMin) +
                    L" and " + std::to_wstring(kMaterialIdentifierMax) + L", got " + std::to_wstring(parsed));
            }
            materialIdentifier = parsed;
        } else if (arg == L"--service-name" || arg == L"-sn") {
            if (i + 1 >= argc) {
                throw CliError(arg + L" requires a value");
            }
            std::wstring value = argv[++i];
            if (value.empty()) {
                throw CliError(L"--service-name must not be empty");
            }
            serviceName = value;
        } else if (arg == L"--dek" || arg == L"-d") {
            if (i + 1 >= argc) {
                throw CliError(arg + L" requires a value");
            }
            dekBase64 = argv[++i];
        } else if (arg == L"--group" || arg == L"-g") {
            if (i + 1 >= argc) {
                throw CliError(arg + L" requires a value");
            }
            std::wstring value = argv[++i];
            if (value.empty()) {
                throw CliError(L"--group must not be empty");
            }
            groupName = value;
        } else if (!keyFilePath.has_value() && (arg.empty() || arg[0] != L'-')) {
            keyFilePath = arg;
        } else {
            throw CliError(L"unrecognized argument: " + arg);
        }
    }

    if (!keyFilePath) throw CliError(L"missing required <key-file-path>");
    if (!materialIdentifier) throw CliError(L"missing required --material-identifier|-mi");
    if (!serviceName) throw CliError(L"missing required --service-name|-sn");
    if (!dekBase64) throw CliError(L"missing required --dek|-d");
    if (!groupName) throw CliError(L"missing required --group|-g");

    out.keyFilePath = *keyFilePath;
    out.materialIdentifier = *materialIdentifier;
    out.serviceName = *serviceName;
    out.dekBase64 = *dekBase64;
    out.groupName = *groupName;
    out.force = force;
    return ParseOutcome::Run;
}

// MARK: - Base64 / UTF-8 conversion

// Decodes `input` (standard base64) into raw bytes via CNG's Crypt32
// string-conversion API - no third-party dependency needed, matching this
// project's general preference for native platform APIs over external
// crates/packages.
std::vector<BYTE> Base64Decode(const std::wstring& input) {
    DWORD size = 0;
    if (!CryptStringToBinaryW(
            input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, nullptr, &size, nullptr,
            nullptr)) {
        throw CliError(L"--dek is not valid base64: " + FormatWin32Error(GetLastError()));
    }
    std::vector<BYTE> out(size);
    if (!CryptStringToBinaryW(
            input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, out.data(), &size, nullptr,
            nullptr)) {
        throw CliError(L"--dek is not valid base64: " + FormatWin32Error(GetLastError()));
    }
    out.resize(size);
    return out;
}

// Converts a wide (UTF-16) string to UTF-8, matching what hkdfguard_wrap_dek's
// `service` parameter expects - the same UTF-8 convention every ABI entry
// point in this project uses - the reverse of hkdfguard.cpp's own
// MultiByteToWideChar conversion of the caller's service string.
std::string ToUtf8(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    int len = WideCharToMultiByte(
        CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        throw CliError(L"failed to convert \"" + wide + L"\" to UTF-8");
    }
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), len, nullptr, nullptr);
    return out;
}

// MARK: - Wrap

std::wstring DescribeStatus(int32_t code) {
    switch (code) {
        case HKDFGUARD_OK: return L"success";
        case HKDFGUARD_ERR_INVALID_ARG: return L"invalid argument (bad service name or DEK length)";
        case HKDFGUARD_ERR_BUFFER_TOO_SMALL: return L"output buffer too small";
        case HKDFGUARD_ERR_PROVIDER: return L"KEK provider/key open or create failed";
        case HKDFGUARD_ERR_CRYPTO: return L"a cryptographic operation failed";
        case HKDFGUARD_ERR_AUTH_FAILED: return L"AES-GCM authentication failed";
        case HKDFGUARD_ERR_MALFORMED: return L"wrapped payload is not valid";
        case HKDFGUARD_ERR_INTERNAL: return L"an internal error occurred in hkdfguard.dll";
        default: return L"unknown status code " + std::to_wstring(code);
    }
}

// Calls hkdfguard_wrap_dek, retrying once at the library-reported required
// size if the initial buffer was too small - same pattern as the
// macOS/Linux tools' own wrap helper.
std::vector<uint8_t> WrapDek(const std::string& service, const std::vector<BYTE>& dek) {
    std::vector<uint8_t> wrapped(static_cast<size_t>(kInitialWrappedCapacity));
    int32_t wrappedLen = static_cast<int32_t>(wrapped.size());

    int32_t rc = hkdfguard_wrap_dek(
        service.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrappedLen);

    if (rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL) {
        // wrappedLen now holds the size the library actually needs; retry once at that size.
        wrapped.assign(static_cast<size_t>(wrappedLen), 0);
        rc = hkdfguard_wrap_dek(
            service.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrappedLen);
    }

    if (rc != HKDFGUARD_OK) {
        throw CliError(L"hkdfguard_wrap_dek failed: " + DescribeStatus(rc));
    }

    wrapped.resize(static_cast<size_t>(wrappedLen));
    return wrapped;
}

// Enforces that the combined `<service-name>.<material-identifier>` string -
// the exact value passed to hkdfguard_wrap_dek as `service` - contains only
// ASCII alphanumeric characters or '.', matching this project's macOS/Linux
// tools. The material identifier is already digits-only (see its parse in
// ParseArgs), so in practice this only constrains --service-name, but it's
// checked on the combined string to match exactly what gets passed to the
// ABI call.
void ValidateServiceCharset(const std::wstring& service) {
    for (wchar_t c : service) {
        bool isAsciiAlnum = (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
        if (!isAsciiAlnum && c != L'.') {
            throw CliError(
                L"combined service name \"" + service + L"\" must contain only alphanumeric characters or '.'");
        }
    }
}

// MARK: - Security descriptor: owner read/write, one named group read-only

// Fetches the current process token's owner SID (TokenOwner) - the SID
// Windows itself documents as "the default owner for objects this process
// creates" - as an owned buffer (copied out of the token info block, which
// is about to be freed).
std::vector<BYTE> GetProcessOwnerSid() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        throw CliError(L"OpenProcessToken failed: " + FormatWin32Error(GetLastError()));
    }
    DWORD size = 0;
    GetTokenInformation(hToken, TokenOwner, nullptr, 0, &size);
    if (size == 0) {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        throw CliError(L"GetTokenInformation(TokenOwner) size query failed: " + FormatWin32Error(err));
    }
    std::vector<BYTE> buf(size);
    BOOL ok = GetTokenInformation(hToken, TokenOwner, buf.data(), size, &size);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(hToken);
    if (!ok) {
        throw CliError(L"GetTokenInformation(TokenOwner) failed: " + FormatWin32Error(err));
    }

    auto* tokenOwner = reinterpret_cast<TOKEN_OWNER*>(buf.data());
    DWORD sidLen = GetLengthSid(tokenOwner->Owner);
    std::vector<BYTE> sid(sidLen);
    if (!CopySid(sidLen, sid.data(), tokenOwner->Owner)) {
        throw CliError(L"CopySid(owner) failed: " + FormatWin32Error(GetLastError()));
    }
    return sid;
}

// Resolves `groupName` (a local or domain group name, e.g. "Administrators"
// or "MYDOMAIN\SomeGroup") to its SID, rejecting anything that isn't
// actually a group account (a plain user name, for instance) so a typo
// doesn't silently grant read access to the wrong kind of principal.
std::vector<BYTE> ResolveGroupSid(const std::wstring& groupName) {
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidType;
    // First call: size query. LookupAccountNameW returns FALSE here even
    // on the expected path (buffers too small); the real signal is that
    // sidSize/domainSize come back non-zero.
    LookupAccountNameW(nullptr, groupName.c_str(), nullptr, &sidSize, nullptr, &domainSize, &sidType);
    if (sidSize == 0) {
        throw CliError(L"--group \"" + groupName + L"\" could not be resolved: " + FormatWin32Error(GetLastError()));
    }
    std::vector<BYTE> sid(sidSize);
    std::wstring domain(domainSize, L'\0');
    if (!LookupAccountNameW(
            nullptr, groupName.c_str(), sid.data(), &sidSize, domain.data(), &domainSize, &sidType)) {
        throw CliError(L"--group \"" + groupName + L"\" could not be resolved: " + FormatWin32Error(GetLastError()));
    }
    if (sidType != SidTypeGroup && sidType != SidTypeAlias && sidType != SidTypeWellKnownGroup) {
        throw CliError(L"--group \"" + groupName + L"\" does not name a group account");
    }
    return sid;
}

// Owns every buffer a security descriptor granting "owner read/write, one
// group read-only, no one else, no inherited ACEs" needs to stay alive for
// as long as it's in use - a self-contained bundle rather than several
// out-parameters the caller would otherwise have to keep in sync by hand.
// The Windows analog of this project's macOS/Linux tools' POSIX 0640
// (owner rw, one group r, no one else).
class OwnerReadWriteGroupReadSecurity {
public:
    OwnerReadWriteGroupReadSecurity(std::vector<BYTE> ownerSid, std::vector<BYTE> groupSid)
        : ownerSid_(std::move(ownerSid)), groupSid_(std::move(groupSid)) {
        PSID owner = SidPtr(ownerSid_);
        PSID group = SidPtr(groupSid_);

        DWORD aclSize = static_cast<DWORD>(
            sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(owner) +
            GetLengthSid(group));
        // ACL buffers must be DWORD-aligned, per Windows' own documented
        // requirement; round up rather than trust the sum above to already
        // land on a boundary.
        aclSize = (aclSize + 7) & ~static_cast<DWORD>(7);

        aclBuf_.resize(aclSize);
        PACL acl = reinterpret_cast<PACL>(aclBuf_.data());
        if (!InitializeAcl(acl, aclSize, ACL_REVISION)) {
            throw CliError(L"InitializeAcl failed: " + FormatWin32Error(GetLastError()));
        }
        if (!AddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ | FILE_GENERIC_WRITE, owner)) {
            throw CliError(L"AddAccessAllowedAce(owner) failed: " + FormatWin32Error(GetLastError()));
        }
        if (!AddAccessAllowedAce(acl, ACL_REVISION, FILE_GENERIC_READ, group)) {
            throw CliError(L"AddAccessAllowedAce(group) failed: " + FormatWin32Error(GetLastError()));
        }

        if (!InitializeSecurityDescriptor(&sd_, SECURITY_DESCRIPTOR_REVISION)) {
            throw CliError(L"InitializeSecurityDescriptor failed: " + FormatWin32Error(GetLastError()));
        }
        if (!SetSecurityDescriptorOwner(&sd_, owner, FALSE)) {
            throw CliError(L"SetSecurityDescriptorOwner failed: " + FormatWin32Error(GetLastError()));
        }
        if (!SetSecurityDescriptorDacl(&sd_, TRUE, acl, FALSE)) {
            throw CliError(L"SetSecurityDescriptorDacl failed: " + FormatWin32Error(GetLastError()));
        }
        // Blocks this DACL from being merged with any inherited ACEs from
        // the parent directory - without this, a permissive parent-folder
        // ACL could silently widen access beyond the two ACEs just set.
        if (!SetSecurityDescriptorControl(&sd_, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
            throw CliError(L"SetSecurityDescriptorControl failed: " + FormatWin32Error(GetLastError()));
        }
    }

    // Valid only for as long as this object is alive - the returned
    // SECURITY_ATTRIBUTES' lpSecurityDescriptor points at this object's own
    // sd_ member, which in turn points into ownerSid_/groupSid_/aclBuf_,
    // all owned together right here.
    SECURITY_ATTRIBUTES attributes() const {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = const_cast<SECURITY_DESCRIPTOR*>(&sd_);
        sa.bInheritHandle = FALSE;
        return sa;
    }

private:
    static PSID SidPtr(std::vector<BYTE>& sid) { return static_cast<PSID>(static_cast<void*>(sid.data())); }

    std::vector<BYTE> ownerSid_;
    std::vector<BYTE> groupSid_;
    std::vector<BYTE> aclBuf_;
    SECURITY_DESCRIPTOR sd_{};
};

// MARK: - Writing the wrapped key file

// Fills `buffer` with cryptographically random bytes via CNG's system RNG
// - the same BCryptGenRandom call this project's own AES-GCM code
// (src/aes_gcm.cpp) uses for nonces, not a plain PRNG.
void FillRandom(std::vector<BYTE>& buffer) {
    NTSTATUS status =
        BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw CliError(L"BCryptGenRandom failed (status 0x" + std::to_wstring(static_cast<unsigned long>(status)) + L")");
    }
}

// Before a --force overwrite is allowed to destroy an existing wrapped-key
// file, this overwrites its *current* contents in place -
// kSecureOverwritePassCount (8) alternating all-zero/random passes, each
// flushed to the storage medium before the next pass starts so they're
// genuinely sequential rather than coalesced by the page cache - and only
// then deletes it. Only ever called when --force was passed; without
// --force, an existing file is never touched at all
// (WriteWrappedKeyFile's plain CREATE_NEW fails outright instead).
//
// If the file doesn't exist, this is a no-op. If it exists but can't be
// opened for writing (ERROR_ACCESS_DENIED, or ERROR_SHARING_VIOLATION if
// another process has it open) the overwrite passes are skipped entirely
// and this falls back to a plain delete, per explicit product direction:
// destroying the old bytes first is worth attempting, but not worth
// failing the whole command over when this process isn't even allowed to
// write to the file it's about to replace.
//
// Caveat this can't fully solve, worth knowing rather than assuming away:
// on SSDs generally (wear leveling) and on any filesystem that does
// copy-on-write or transparent compression, writing new bytes to a file's
// logical offsets does not guarantee those bytes land on the same physical
// storage cells the old bytes occupied - the old bytes can persist in
// already-remapped blocks until the medium itself reclaims them. This is a
// best-effort measure against casual recovery, not a cryptographic
// guarantee against a determined attacker with access to the raw storage.
void SecureOverwriteAndRemoveIfExists(const std::wstring& path) {
    ScopedFileHandle file(CreateFileW(
        path.c_str(), GENERIC_WRITE, 0 /* exclusive access for the duration of the passes */, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return; // nothing to overwrite or delete
        }
        if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
            // Can't write to it - skip the overwrite passes and go
            // straight to trying to remove it.
            if (!DeleteFileW(path.c_str())) {
                DWORD delErr = GetLastError();
                if (delErr != ERROR_FILE_NOT_FOUND) {
                    throw CliError(L"failed to remove " + path + L": " + FormatWin32Error(delErr));
                }
            }
            return;
        }
        throw CliError(L"failed to open " + path + L" for secure overwrite: " + FormatWin32Error(err));
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file.get(), &fileSize)) {
        throw CliError(L"failed to get size of " + path + L": " + FormatWin32Error(GetLastError()));
    }

    if (fileSize.QuadPart > 0) {
        std::vector<BYTE> buffer(static_cast<size_t>(fileSize.QuadPart), 0);

        for (size_t pass = 0; pass < kSecureOverwritePassCount; ++pass) {
            if (pass % 2 == 0) {
                std::fill(buffer.begin(), buffer.end(), static_cast<BYTE>(0)); // "step 1": all-zero
            } else {
                FillRandom(buffer); // "step 2": random bits, via the OS CSPRNG
            }

            LARGE_INTEGER zero{};
            if (!SetFilePointerEx(file.get(), zero, nullptr, FILE_BEGIN)) {
                throw CliError(
                    L"failed to seek " + path + L" during secure-overwrite pass " + std::to_wstring(pass + 1) +
                    L": " + FormatWin32Error(GetLastError()));
            }

            DWORD totalWritten = 0;
            const DWORD bufferSize = static_cast<DWORD>(buffer.size());
            while (totalWritten < bufferSize) {
                DWORD written = 0;
                if (!WriteFile(file.get(), buffer.data() + totalWritten, bufferSize - totalWritten, &written, nullptr)) {
                    throw CliError(
                        L"failed to write secure-overwrite pass " + std::to_wstring(pass + 1) + L" to " + path +
                        L": " + FormatWin32Error(GetLastError()));
                }
                totalWritten += written;
            }

            if (!FlushFileBuffers(file.get())) {
                throw CliError(
                    L"failed to flush " + path + L" during secure-overwrite pass " + std::to_wstring(pass + 1) +
                    L": " + FormatWin32Error(GetLastError()));
            }
        }

        SecureZeroMemory(buffer.data(), buffer.size());
    }

    // Windows (unlike POSIX) generally refuses to delete a file that still
    // has an open handle without FILE_SHARE_DELETE - close explicitly
    // before DeleteFileW rather than relying on ScopedFileHandle's
    // destructor to run first.
    file.reset();

    if (!DeleteFileW(path.c_str())) {
        throw CliError(L"failed to remove " + path + L" after secure overwrite: " + FormatWin32Error(GetLastError()));
    }
}

// Opens `path` fresh (CREATE_NEW - atomically fails if it already exists,
// this tool's actual correctness guarantee against the exists-then-create
// race, same role O_EXCL/O_CREAT plays in the macOS/Linux tools) and writes
// `bytes` to it, with `security`'s ACL attached from the moment the file is
// created - no window where it briefly exists with broader (e.g.
// inherited-from-parent-directory) permissions before being locked down
// after the fact.
void WriteWrappedKeyFile(
    const std::wstring& path, const std::vector<uint8_t>& bytes, const OwnerReadWriteGroupReadSecurity& security) {
    SECURITY_ATTRIBUTES sa = security.attributes();
    ScopedFileHandle file(
        CreateFileW(path.c_str(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_EXISTS) {
            throw CliError(path + L" already exists; pass --force|-f to overwrite");
        }
        throw CliError(L"failed to open " + path + L" for writing: " + FormatWin32Error(err));
    }

    DWORD totalWritten = 0;
    const DWORD bytesSize = static_cast<DWORD>(bytes.size());
    while (totalWritten < bytesSize) {
        DWORD written = 0;
        if (!WriteFile(file.get(), bytes.data() + totalWritten, bytesSize - totalWritten, &written, nullptr)) {
            throw CliError(L"failed to write " + path + L": " + FormatWin32Error(GetLastError()));
        }
        totalWritten += written;
    }
}

// MARK: - Run

void Run(Args& args) {
    // Fast, friendly pre-check: fail before ever touching the TPM/Software
    // Key Storage Provider if the output path obviously already exists and
    // --force wasn't passed. WriteWrappedKeyFile's CREATE_NEW is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if (!args.force) {
        DWORD attrs = GetFileAttributesW(args.keyFilePath.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            throw CliError(args.keyFilePath + L" already exists; pass --force|-f to overwrite");
        }
    }

    // Resolved before any TPM/Software Key Storage Provider work, so a bad
    // --group name fails fast rather than after an expensive (and, with
    // --force, destructive) operation has already run. Doesn't touch any
    // secret material either way.
    OwnerReadWriteGroupReadSecurity security(GetProcessOwnerSid(), ResolveGroupSid(args.groupName));

    // `service` (and its UTF-8 form) is not secret -- it's a logical
    // identifier, not key material -- so both live for the rest of this
    // function's scope, including the final status message below. This is
    // computed before the DEK's own tightly-scoped block so that block can
    // end the instant the DEK is no longer needed, without `service` also
    // needing to be reconstructed afterward for the printf at the bottom.
    std::wstring service = args.serviceName + L"." + std::to_wstring(args.materialIdentifier);
    ValidateServiceCharset(service);
    std::string serviceUtf8 = ToUtf8(service);

    std::vector<uint8_t> wrapped;
    {
        // Both the base64 *text* (`args.dekBase64`) and the decoded
        // plaintext DEK *bytes* (`dek`) are secret, and both are scoped as
        // tightly as possible around exactly the statements that need
        // them: decode, wipe the text immediately (it has now served its
        // one purpose), validate the byte length, wrap, then `dek` is
        // wiped by `dekGuard` the instant this block ends -- immediately
        // after WrapDek is done with it, not at the end of Run() (which
        // would otherwise leave it sitting in memory, unused but unwiped,
        // through --group resolution above, and through the ACL work,
        // the potentially-slow 8-pass secure-overwrite, and the final
        // file write below). Matches the "shrink the scope to shrink the
        // lifetime" technique this project's own DLL uses for the exact
        // same reason (e.g. hkdfguard.cpp's `wrapping_key`, ecdh_hkdf.cpp's
        // `prk`/`t1`) -- hkdfguard_wrap_dek itself reads the plaintext DEK
        // directly from whatever pointer it's given and never copies or
        // zeroes it internally (see aes_gcm.cpp's own comment on this),
        // so this caller-side zeroing is not optional defense-in-depth --
        // it is the only place this ever happens at all.
        std::vector<BYTE> dek = Base64Decode(args.dekBase64);

        // The base64 text has now served its only purpose: wipe this
        // process's one owned copy of it right here, rather than leaving
        // it sitting in `args` for the rest of this function (or, without
        // this, for the rest of the process's life until `args` is
        // eventually destroyed -- and a plain std::wstring destructor
        // does not zero its buffer, it only deallocates it). This does
        // not erase the original command-line argument the OS/CRT still
        // holds elsewhere -- see this file's header comment on that
        // inherent, unavoidable argv-visibility limitation -- it erases
        // the one copy this code actually controls, which is the one
        // thing zeroing it here can actually fix.
        SecureZeroMemory(args.dekBase64.data(), args.dekBase64.size() * sizeof(wchar_t));
        args.dekBase64.clear();

        // Zeroes `dek` -- up to its *capacity*, not just its current
        // size -- the instant this block ends, on every exit path (the
        // length-validation throw immediately below, or falling off the
        // end after a successful WrapDek call). Capacity rather than size
        // because Base64Decode's std::vector<BYTE> is sized once from
        // CryptStringToBinaryW's size query and then (in the extremely
        // unlikely case the real decode reports fewer bytes than that
        // query did) shrunk with resize(), which reduces size() but is not
        // guaranteed to reduce the underlying allocation -- zeroing only
        // up to size() in that edge case would leave a few stale plaintext
        // bytes sitting in the still-allocated tail of the buffer.
        struct DekGuard {
            std::vector<BYTE>& buf;
            ~DekGuard() { SecureZeroMemory(buf.data(), buf.capacity()); }
        } dekGuard{dek};

        if (dek.size() != kDekLen) {
            throw CliError(
                L"--dek must decode to exactly " + std::to_wstring(kDekLen) + L" bytes, got " +
                std::to_wstring(dek.size()));
        }

        wrapped = WrapDek(serviceUtf8, dek);
        // dekGuard zeroes `dek` here, as this block ends -- immediately
        // after WrapDek returns the wrapped (encrypted, no longer secret)
        // form, which is the only thing that survives past this point.
    }

    if (args.force) {
        SecureOverwriteAndRemoveIfExists(args.keyFilePath);
    }

    WriteWrappedKeyFile(args.keyFilePath, wrapped, security);

    fwprintf(
        stdout, L"wrapped key written to %ls (%zu bytes, owner read/write + %ls read-only, service \"%ls\")\n",
        args.keyFilePath.c_str(), wrapped.size(), args.groupName.c_str(), service.c_str());
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    Args args;
    try {
        if (ParseArgs(argc, argv, args) == ParseOutcome::Help) {
            PrintUsage();
            return 0;
        }
    } catch (const CliError& e) {
        fwprintf(stderr, L"error: %ls\n", e.message.c_str());
        PrintUsage();
        return 2;
    }

    try {
        Run(args);
        return 0;
    } catch (const CliError& e) {
        fwprintf(stderr, L"error: %ls\n", e.message.c_str());
        return 1;
    } catch (const std::exception& e) {
        fwprintf(stderr, L"error: %hs\n", e.what());
        return 1;
    }
}
