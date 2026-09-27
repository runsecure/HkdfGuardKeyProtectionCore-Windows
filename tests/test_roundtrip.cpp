// This is a small hand-rolled test program, not built on a testing
// framework like GoogleTest - it's a plain `main()` that runs a sequence of
// checks and reports pass/fail for each, then exits 0 (success, the
// standard "everything's fine" exit code a shell/CI system checks) or 1
// (failure) depending on whether anything failed. CMake's `ctest` (see
// tests/CMakeLists.txt) just runs this .exe and treats exit code 0 as a
// passing test.
#include "hkdfguard.h"  // the public ABI under test
#include "kek_store.h"  // CreateKek/KekExists/OpenKekForWrap/DeleteKek - internal helpers, used directly below
#include "policy.h"     // SetTestPolicyOverride - internal test-only seam, used directly below

#include <cstdio>
#include <cstring>
#include <stdexcept> // std::exception, caught in CleanupKek and CheckPolicyCreatesKek
#include <vector>
#include <string>

// Anonymous namespace: everything in this block is private to this one
// file (see aes_gcm.cpp for the fuller explanation of what this construct
// does) - not that it matters much in a standalone test .exe with no other
// translation units to collide with, but it's the same convention used
// throughout the rest of the project.
namespace {

// A running count of failed checks, incremented by Check() below and read
// back in main() to decide the process's final exit code.
int g_failures = 0;

// The test harness's one primitive: print PASS or FAIL for a labeled
// condition, and keep count of failures. `const char* what` is a
// human-readable label describing what's being checked, printed alongside
// the result.
void Check(bool condition, const char* what) {
    if (condition) {
        std::printf("[PASS] %s\n", what);
    } else {
        std::printf("[FAIL] %s\n", what);
        ++g_failures;
    }
}

// Builds a deterministic (not random) 32-byte test DEK: each byte is some
// simple, distinct function of its index, purely so bugs that shuffle or
// truncate bytes are easy to spot rather than every byte looking the same.
// Returned as a `std::vector<uint8_t>` - a plain (non-secure) dynamic byte
// buffer is fine here since this is test data, not a real secret to
// protect.
std::vector<uint8_t> MakeDek() {
    std::vector<uint8_t> dek(HKDFGUARD_DEK_LEN);
    for (int i = 0; i < HKDFGUARD_DEK_LEN; ++i) {
        dek[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 7 + 11);
    }
    return dek;
}

// Used to verify the "output buffer zeroed on failure" requirement: scans
// `len` bytes starting at `buf` and returns true only if every single one
// is 0.
bool AllZero(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != 0) return false;
    }
    return true;
}

// Two distinct service names used across the checks below, each in both
// its UTF-8 form (`char`, passed to the public ABI functions) and wide
// form (`wchar_t`, passed to the internal DeleteKek for cleanup - see
// kek_store.h). Because both are plain ASCII text, the UTF-8 bytes and the
// UTF-16 code units happen to correspond 1:1 character-for-character, so
// writing out both literals by hand here (rather than converting one from
// the other at runtime) is a safe shortcut for test code specifically.
//
// Only alphanumeric characters and '.' are used - hkdfguard.cpp's
// IsValidServiceChar rejects everything else, including '-' (see check 17
// below).
constexpr char kService[] = "hkdfguardwin.test.service";
constexpr wchar_t kServiceWide[] = L"hkdfguardwin.test.service";
constexpr char kServiceOther[] = "hkdfguardwin.test.service.other";
constexpr wchar_t kServiceOtherWide[] = L"hkdfguardwin.test.service.other";

// Dedicated service names for the hkdfguard_kek_exists/hkdfguard_create_kek
// lifecycle checks (0) and the groups_csv length/whitespace checks (0c)
// below - kept separate from kService so those checks can rely on the
// service having no KEK yet at the point they run.
constexpr char kServiceLifecycle[] = "hkdfguardwin.test.lifecycle";
constexpr wchar_t kServiceLifecycleWide[] = L"hkdfguardwin.test.lifecycle";
constexpr char kServiceNoKek[] = "hkdfguardwin.test.nokek";
constexpr char kServiceGroupsCsv[] = "hkdfguardwin.test.groupscsv";
constexpr wchar_t kServiceGroupsCsvWide[] = L"hkdfguardwin.test.groupscsv";

// Deletes the KEK created for `service` during this test run, so repeated
// runs don't accumulate persisted keys in the user's key storage. Uses the
// internal kek_store API directly (not part of the public C ABI). The KEK
// only exists under whichever single provider actually created it
// (`provider_type`, read back from a payload wrapped for this service), so
// only that provider is queried.
void CleanupKek(const wchar_t* service_wide, uint8_t provider_type, const char* label) {
    try {
        // `std::wstring(service_wide)` constructs a std::wstring by copying
        // from the `const wchar_t*` literal - DeleteKek's parameter type is
        // `const std::wstring&` (see kek_store.h), so this conversion has
        // to happen somewhere, and it's simplest to do it right here at the
        // one call site rather than changing DeleteKek's signature just for
        // this test.
        hkdfguard::DeleteKek(std::wstring(service_wide), provider_type, hkdfguard::kCurrentKeyId);
        std::printf("[INFO] cleaned up KEK for %s\n", label);
    } catch (const std::exception& e) {
        // Cleanup failing doesn't fail the test itself (it's not what this
        // test is checking) - it's just surfaced as a warning so it's
        // visible in the test log if something about deletion is broken.
        // `e.what()` retrieves the message HkdfGuardError's constructor
        // stored via std::runtime_error - see errors.h.
        std::printf("[WARN] failed to clean up KEK for %s: %s\n", label, e.what());
    }
}

// Forces LoadEffectivePolicy() to return `policy` for the duration of this
// call (via the test-only SetTestPolicyOverride seam - see policy.h), then
// exercises CreateKek/KekExists/OpenKekForWrap directly against the
// internal kek_store API - the same internal API CleanupKek's DeleteKek
// call above uses, bypassing hkdfguard.dll entirely - so this test can
// cover all three KeyStoragePolicy branches deterministically, regardless
// of this machine's actual registry policy or TPM/vTPM availability.
// Cleans up whatever it creates before returning, and always clears the
// override on the way out.
//
// `tpmMayBeUnavailable` accepts CreateKek throwing as a legitimate outcome
// rather than a test failure: RequireTpm's documented contract is "use the
// TPM-backed provider or fail outright, never fall back to software," and
// this test has no way to know whether the machine it's running on
// actually has a TPM/vTPM.
void CheckPolicyCreatesKek(
    hkdfguard::KeyStoragePolicy policy,
    const wchar_t* serviceWide,
    const std::string& label,
    bool tpmMayBeUnavailable) {
    hkdfguard::SetTestPolicyOverride(policy);

    try {
        hkdfguard::CreateKek(serviceWide, {});
        Check(true, (label + ": create_kek succeeds").c_str());

        Check(hkdfguard::KekExists(serviceWide), (label + ": kek_exists reports true afterward").c_str());

        hkdfguard::ResolvedKek kek = hkdfguard::OpenKekForWrap(serviceWide);
        std::printf("    (%s: provider_type = %d)\n", label.c_str(), kek.provider_type);

        if (policy == hkdfguard::KeyStoragePolicy::RequireTpm) {
            Check(
                kek.provider_type == hkdfguard::kProviderTypeTpm,
                (label + ": RequireTpm never falls back to the software provider").c_str());
        }
        if (policy == hkdfguard::KeyStoragePolicy::SoftwareOnly) {
            Check(
                kek.provider_type == hkdfguard::kProviderTypeSoftware,
                (label + ": SoftwareOnly uses the software provider").c_str());
        }

        hkdfguard::DeleteKek(serviceWide, kek.provider_type, hkdfguard::kCurrentKeyId);
    } catch (const std::exception& e) {
        if (tpmMayBeUnavailable) {
            std::printf(
                "[INFO] %s: create_kek failed - acceptable without real TPM/vTPM hardware on this machine: %s\n",
                label.c_str(), e.what());
        } else {
            Check(false, (label + ": create_kek should not fail on this policy").c_str());
            std::printf("    (%s)\n", e.what());
        }
    }

    hkdfguard::SetTestPolicyOverride(std::nullopt);
}

} // namespace

int main() {
    std::vector<uint8_t> dek = MakeDek();
    int32_t rc;

    // ---- 0. hkdfguard_kek_exists / hkdfguard_create_kek lifecycle. ----
    // kServiceLifecycle has never been used before this point in the test,
    // so kek_exists is expected to genuinely report "not found" here, not
    // just "didn't error."
    int32_t lifecycle_exists = -1;
    rc = hkdfguard_kek_exists(kServiceLifecycle, &lifecycle_exists);
    Check(rc == HKDFGUARD_OK, "kek_exists succeeds for a service with no KEK yet");
    Check(lifecycle_exists == 0, "kek_exists reports false before the KEK is created");

    rc = hkdfguard_create_kek(kServiceLifecycle, nullptr);
    Check(rc == HKDFGUARD_OK, "create_kek provisions a new KEK");

    lifecycle_exists = -1;
    rc = hkdfguard_kek_exists(kServiceLifecycle, &lifecycle_exists);
    Check(rc == HKDFGUARD_OK, "kek_exists succeeds after the KEK is created");
    Check(lifecycle_exists == 1, "kek_exists reports true after the KEK is created");

    // create_kek is safe to call again for an already-provisioned service:
    // it verifies rather than failing or re-creating.
    rc = hkdfguard_create_kek(kServiceLifecycle, nullptr);
    Check(rc == HKDFGUARD_OK, "create_kek is idempotent for an already-provisioned service");

    // wrap now succeeds, since create_kek has provisioned the KEK it needs.
    std::vector<uint8_t> lifecycle_wrapped(HKDFGUARD_WRAPPED_LEN);
    int32_t lifecycle_wrapped_len = static_cast<int32_t>(lifecycle_wrapped.size());
    rc = hkdfguard_wrap_dek(
        kServiceLifecycle, dek.data(), static_cast<int32_t>(dek.size()), lifecycle_wrapped.data(),
        &lifecycle_wrapped_len);
    Check(rc == HKDFGUARD_OK, "wrap succeeds once create_kek has provisioned the KEK");

    // ---- 0b. wrap fails outright for a service with no KEK - wrap never ----
    //          creates one implicitly (only create_kek does).
    std::vector<uint8_t> no_kek_scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t no_kek_scratch_len = static_cast<int32_t>(no_kek_scratch.size());
    rc = hkdfguard_wrap_dek(
        kServiceNoKek, dek.data(), static_cast<int32_t>(dek.size()), no_kek_scratch.data(), &no_kek_scratch_len);
    Check(rc == HKDFGUARD_ERR_PROVIDER, "wrap fails when no KEK has been provisioned for the service");

    // ---- 0c. kek_exists / create_kek argument validation. ----
    rc = hkdfguard_kek_exists(nullptr, &lifecycle_exists);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "kek_exists rejects null service");

    rc = hkdfguard_kek_exists(kServiceLifecycle, nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "kek_exists rejects null out_exists");

    rc = hkdfguard_kek_exists("", &lifecycle_exists);
    Check(rc == HKDFGUARD_ERR_SERVICE_NAME_INVALID, "kek_exists rejects empty service");

    rc = hkdfguard_create_kek(nullptr, nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "create_kek rejects null service");

    // A groups_csv longer than kMaxGroupsCsvLen (8192 bytes, see
    // hkdfguard.cpp) is rejected before ever touching the KEK store - proven
    // here against kServiceLifecycle, which already has a KEK, since
    // ParseAndConvertGroups runs before CreateKek either way.
    const std::string too_long_groups_csv(8193, 'A');
    rc = hkdfguard_create_kek(kServiceLifecycle, too_long_groups_csv.c_str());
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "create_kek rejects a groups_csv longer than 8192 bytes");

    // A groups_csv of exactly 8192 bytes - one real, universally-present
    // group name ("Everyone") surrounded by whitespace, padded out to the
    // boundary with trailing commas (which parse as empty tokens and are
    // silently skipped) - succeeds. This also proves leading/trailing
    // whitespace around a group name is trimmed before resolution: without
    // trimming, " Everyone " does not name any account, and create_kek
    // would fail with HKDFGUARD_ERR_PROVIDER instead. Uses a fresh service
    // (kServiceGroupsCsv), since create_kek only ever applies ACLs at
    // initial creation - reusing an already-provisioned service like
    // kServiceLifecycle wouldn't actually exercise group resolution here.
    std::string boundary_groups_csv = " Everyone ";
    boundary_groups_csv.append(8192 - boundary_groups_csv.size(), ',');
    rc = hkdfguard_create_kek(kServiceGroupsCsv, boundary_groups_csv.c_str());
    Check(
        rc == HKDFGUARD_OK,
        "create_kek accepts a groups_csv of exactly 8192 bytes and trims whitespace around group names");
    bool groups_csv_service_created = (rc == HKDFGUARD_OK);

    std::vector<uint8_t> groups_csv_wrapped(HKDFGUARD_WRAPPED_LEN);
    int32_t groups_csv_wrapped_len = static_cast<int32_t>(groups_csv_wrapped.size());
    if (groups_csv_service_created) {
        rc = hkdfguard_wrap_dek(
            kServiceGroupsCsv, dek.data(), static_cast<int32_t>(dek.size()), groups_csv_wrapped.data(),
            &groups_csv_wrapped_len);
        Check(rc == HKDFGUARD_OK, "wrap succeeds against the groups_csv test service's newly-created KEK");
    }

    // ---- 1. Provision kService's KEK, then a basic wrap -> unwrap ----
    //         roundtrip.
    rc = hkdfguard_create_kek(kService, nullptr);
    Check(rc == HKDFGUARD_OK, "create_kek provisions kService's KEK");

    std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_LEN);
    // `wrapped_len` is initialized to the buffer's actual capacity before
    // the call - this is the "in" half of the in/out `out_len` parameter
    // (see hkdfguard.h); hkdfguard_wrap_dek reads this to know how much
    // room it has, then overwrites it with the real output length.
    int32_t wrapped_len = static_cast<int32_t>(wrapped.size());

    // `&wrapped_len` - the address-of operator - is how a plain local
    // variable is turned into the `int32_t*` the function signature
    // requires for its in/out parameter.
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrapped_len);
    Check(rc == HKDFGUARD_OK, "wrap succeeds");
    Check(wrapped_len == HKDFGUARD_WRAPPED_LEN, "wrap produces fixed-size payload");

    // Byte offset 1 of the wrapped payload is ProviderType (see
    // wire_format.h's layout table) - reading it directly out of the
    // wrapped bytes like this, rather than through any library function, is
    // deliberate: it's testing the actual on-the-wire output, the same
    // thing any other language's binding would see.
    uint8_t provider_type = wrapped[1];
    Check(provider_type == 1 || provider_type == 2, "provider type is TPM(1) or Software(2)");
    std::printf("    (provider_type = %d)\n", provider_type);

    std::vector<uint8_t> unwrapped(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped.data(), &unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds");
    Check(unwrapped_len == HKDFGUARD_DEK_LEN, "unwrap produces 32-byte DEK");
    // std::memcmp (declared in <cstring>) compares raw bytes and returns 0
    // when they're identical - the standard way to check two byte buffers
    // are equal, since operator== isn't defined for raw pointers/arrays the
    // way it is for e.g. std::vector or std::string.
    Check(std::memcmp(dek.data(), unwrapped.data(), HKDFGUARD_DEK_LEN) == 0, "unwrapped DEK matches original");

    // ---- 1b. Service names are case-insensitive: a service name that only ----
    //          differs in case from kService resolves to the exact same KEK,
    //          and wrap/unwrap can mix casing freely across calls - not just
    //          "same KEK, but the AAD only matches if the casing happens to
    //          be identical too" (see hkdfguard.cpp's NormalizeService,
    //          which normalizes the AAD bytes as well as the KEK name).
    constexpr char kServiceMixedCase[] = "HkdfGuardWin.Test.SERVICE";

    int32_t mixed_case_exists = -1;
    rc = hkdfguard_kek_exists(kServiceMixedCase, &mixed_case_exists);
    Check(rc == HKDFGUARD_OK, "kek_exists succeeds for a differently-cased alias of an existing service");
    Check(mixed_case_exists == 1, "kek_exists reports true for a differently-cased alias of an existing service");

    rc = hkdfguard_create_kek(kServiceMixedCase, nullptr);
    Check(rc == HKDFGUARD_OK, "create_kek is idempotent for a differently-cased alias of an existing service");

    // Wrap using the mixed-case alias; it must reuse kService's existing KEK
    // (same provider), not provision a second, independent one.
    std::vector<uint8_t> wrapped_mixed_case(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_mixed_case_len = static_cast<int32_t>(wrapped_mixed_case.size());
    rc = hkdfguard_wrap_dek(
        kServiceMixedCase, dek.data(), static_cast<int32_t>(dek.size()), wrapped_mixed_case.data(),
        &wrapped_mixed_case_len);
    Check(rc == HKDFGUARD_OK, "wrap succeeds using a differently-cased alias of an existing service");
    Check(wrapped_mixed_case[1] == provider_type, "wrap via a differently-cased alias reuses the same provider/KEK");

    // Unwrap that payload using the original lowercase form.
    std::vector<uint8_t> unwrapped_via_lowercase(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_via_lowercase_len = static_cast<int32_t>(unwrapped_via_lowercase.size());
    rc = hkdfguard_unwrap_dek(
        kService, wrapped_mixed_case.data(), wrapped_mixed_case_len, unwrapped_via_lowercase.data(),
        &unwrapped_via_lowercase_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds using the lowercase form of a payload wrapped via a mixed-case alias");
    Check(
        std::memcmp(dek.data(), unwrapped_via_lowercase.data(), HKDFGUARD_DEK_LEN) == 0,
        "unwrapped DEK matches original when wrap/unwrap use differently-cased service names");

    // And the reverse direction: unwrap `wrapped` (from check 1 above,
    // wrapped under the original lowercase kService) using the mixed-case
    // alias instead.
    std::vector<uint8_t> unwrapped_via_mixed_case(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_via_mixed_case_len = static_cast<int32_t>(unwrapped_via_mixed_case.size());
    rc = hkdfguard_unwrap_dek(
        kServiceMixedCase, wrapped.data(), wrapped_len, unwrapped_via_mixed_case.data(),
        &unwrapped_via_mixed_case_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds using a mixed-case alias of the service a payload was wrapped under");
    Check(
        std::memcmp(dek.data(), unwrapped_via_mixed_case.data(), HKDFGUARD_DEK_LEN) == 0,
        "unwrapped DEK matches original when unwrap uses a differently-cased alias of the wrapping service");

    // ---- 2. Unwrapping the same payload again is idempotent: the payload ----
    //         isn't mutated/consumed by a successful unwrap, so a second,
    //         independent unwrap of the exact same bytes must succeed again
    //         and recover the identical DEK.
    std::vector<uint8_t> unwrapped_again(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_again_len = static_cast<int32_t>(unwrapped_again.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped_again.data(), &unwrapped_again_len);
    Check(rc == HKDFGUARD_OK, "unwrapping the same payload a second time succeeds");
    Check(
        std::memcmp(dek.data(), unwrapped_again.data(), HKDFGUARD_DEK_LEN) == 0,
        "second unwrap of the same payload recovers the identical DEK");

    // ---- 3. Repeated wrap reuses the same (provider, KeyId). ----
    // KeyId is fixed for this format version, and provider selection should
    // be stable across calls rather than flip-flopping.
    std::vector<uint8_t> wrapped2(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped2_len = static_cast<int32_t>(wrapped2.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped2.data(), &wrapped2_len);
    Check(rc == HKDFGUARD_OK, "second wrap succeeds");
    Check(wrapped2[1] == provider_type, "second wrap reuses the same provider type");

    // ---- 4. hkdfguard_generate_and_wrap_dek: generates its own DEK, wraps
    //         it under the same KEK as the calls above, and never hands
    //         the plaintext back. ----
    std::vector<uint8_t> generated1(HKDFGUARD_WRAPPED_LEN);
    int32_t generated1_len = static_cast<int32_t>(generated1.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, generated1.data(), &generated1_len);
    Check(rc == HKDFGUARD_OK, "generate_and_wrap succeeds");
    Check(generated1_len == HKDFGUARD_WRAPPED_LEN, "generate_and_wrap produces fixed-size payload");
    Check(generated1[1] == provider_type, "generate_and_wrap reuses the same provider type");

    // Unwrapping it recovers a real 32-byte DEK - proving the payload
    // generate_and_wrap_dek produced is a genuine, independently unwrappable
    // WrappedDekV1, not just a plausible-looking buffer.
    std::vector<uint8_t> generated1_unwrapped(HKDFGUARD_DEK_LEN);
    int32_t generated1_unwrapped_len = static_cast<int32_t>(generated1_unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, generated1.data(), generated1_len, generated1_unwrapped.data(), &generated1_unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap of a generate_and_wrap_dek payload succeeds");
    Check(generated1_unwrapped_len == HKDFGUARD_DEK_LEN, "unwrap of a generate_and_wrap_dek payload produces 32-byte DEK");

    // A second call generates an *independent* random DEK - not the fixed
    // MakeDek() test vector, and not a repeat of the first call's DEK. This
    // is the actual check that fresh randomness was sourced each time
    // (rather than e.g. an all-zero or otherwise fixed buffer slipping
    // through): with a 32-byte CSPRNG-sourced DEK, two calls producing the
    // same bytes is astronomically unlikely, so any match indicates a real
    // bug.
    std::vector<uint8_t> generated2(HKDFGUARD_WRAPPED_LEN);
    int32_t generated2_len = static_cast<int32_t>(generated2.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, generated2.data(), &generated2_len);
    Check(rc == HKDFGUARD_OK, "second generate_and_wrap succeeds");
    std::vector<uint8_t> generated2_unwrapped(HKDFGUARD_DEK_LEN);
    int32_t generated2_unwrapped_len = static_cast<int32_t>(generated2_unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, generated2.data(), generated2_len, generated2_unwrapped.data(), &generated2_unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap of the second generate_and_wrap_dek payload succeeds");
    Check(
        std::memcmp(generated1_unwrapped.data(), generated2_unwrapped.data(), HKDFGUARD_DEK_LEN) != 0,
        "two generate_and_wrap_dek calls produce different DEKs");
    Check(
        std::memcmp(dek.data(), generated1_unwrapped.data(), HKDFGUARD_DEK_LEN) != 0,
        "generate_and_wrap_dek's DEK differs from the fixed test vector");

    // ---- 5. generate_and_wrap_dek argument validation. ----
    std::vector<uint8_t> gen_scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t gen_scratch_len = static_cast<int32_t>(gen_scratch.size());
    rc = hkdfguard_generate_and_wrap_dek(nullptr, gen_scratch.data(), &gen_scratch_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "generate_and_wrap rejects null service");

    std::vector<uint8_t> gen_tiny_buf(HKDFGUARD_WRAPPED_LEN - 1);
    int32_t gen_tiny_buf_len = static_cast<int32_t>(gen_tiny_buf.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, gen_tiny_buf.data(), &gen_tiny_buf_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "generate_and_wrap rejects too-small output buffer");

    // ---- 6. Invalid dek_len. ----
    int32_t bad_len = 16;
    std::vector<uint8_t> scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t scratch_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), bad_len, scratch.data(), &scratch_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects wrong dek_len");

    // ---- 7. Buffer too small on wrap. ----
    // (Named `tiny_buf`/`tiny_out`, not `small`/`small_out`, because
    // <windows.h> - pulled in transitively through kek_store.h - #defines
    // the plain identifier `small` as a legacy MIDL type; using it as a
    // variable name here would fail to compile.)
    std::vector<uint8_t> tiny_buf(HKDFGUARD_WRAPPED_LEN - 1);
    int32_t tiny_buf_len = static_cast<int32_t>(tiny_buf.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), tiny_buf.data(), &tiny_buf_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "wrap rejects too-small output buffer");

    // ---- 8. Buffer too small on unwrap. ----
    std::vector<uint8_t> tiny_out(HKDFGUARD_DEK_LEN - 1);
    int32_t tiny_out_len = static_cast<int32_t>(tiny_out.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, tiny_out.data(), &tiny_out_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "unwrap rejects too-small output buffer");

    // ---- 9. Malformed payload (truncated). ----
    // `std::vector<uint8_t> truncated(wrapped.begin(), wrapped.begin() +
    // wrapped_len - 1)` builds a *new* vector from a range of `wrapped`'s
    // elements - here, every element except the last one - using the
    // "iterator pair" constructor: `.begin()` is an iterator (a
    // pointer-like object) to the first element, and `.begin() + N` one
    // pointing N elements later; the constructor copies everything from the
    // first iterator up to (but not including) the second.
    std::vector<uint8_t> truncated(wrapped.begin(), wrapped.begin() + wrapped_len - 1);
    // Pre-filled with 0xAA (not 0) specifically so the AllZero() check below
    // is actually testing something - if the buffer already started at all
    // zeros, seeing zeros afterward wouldn't prove the library did anything.
    std::vector<uint8_t> out_for_malformed(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t malformed_out_len = static_cast<int32_t>(out_for_malformed.size());
    rc = hkdfguard_unwrap_dek(kService, truncated.data(), static_cast<int32_t>(truncated.size()),
                              out_for_malformed.data(), &malformed_out_len);
    Check(rc == HKDFGUARD_ERR_MALFORMED, "unwrap rejects truncated payload");
    Check(AllZero(out_for_malformed.data(), out_for_malformed.size()), "output buffer zeroed after malformed payload");

    // ---- 10. Corrupted ciphertext -> authentication failure, output zeroed. ----
    // `std::vector<uint8_t> corrupted = wrapped;` copies the whole vector
    // (std::vector's copy constructor, unlike SecureBuffer's, is not
    // deleted - it's perfectly fine to copy plain wrapped-payload bytes,
    // which aren't secret).
    std::vector<uint8_t> corrupted = wrapped;
    // `^= 0xFF` flips every bit of that one byte (XOR-assignment) -
    // guaranteed to change its value no matter what it was, corrupting one
    // byte inside the ciphertext region (see wire_format.h's offset table:
    // byte 100 falls between kCiphertextOffset=84 and kTagOffset=116).
    corrupted[100] ^= 0xFF; // inside the ciphertext region
    std::vector<uint8_t> out_for_auth(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t auth_out_len = static_cast<int32_t>(out_for_auth.size());
    rc = hkdfguard_unwrap_dek(kService, corrupted.data(), static_cast<int32_t>(corrupted.size()),
                              out_for_auth.data(), &auth_out_len);
    Check(rc == HKDFGUARD_ERR_AUTH_FAILED, "unwrap rejects corrupted ciphertext");
    Check(AllZero(out_for_auth.data(), out_for_auth.size()), "output buffer zeroed after auth failure");

    // ---- 11. Corrupted tag -> authentication failure, output zeroed. ----
    std::vector<uint8_t> corrupted_tag = wrapped;
    corrupted_tag[wrapped_len - 1] ^= 0xFF; // inside the tag region (the payload's very last byte)
    std::vector<uint8_t> out_for_tag(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t tag_out_len = static_cast<int32_t>(out_for_tag.size());
    rc = hkdfguard_unwrap_dek(kService, corrupted_tag.data(), static_cast<int32_t>(corrupted_tag.size()),
                              out_for_tag.data(), &tag_out_len);
    Check(rc == HKDFGUARD_ERR_AUTH_FAILED, "unwrap rejects corrupted tag");
    Check(AllZero(out_for_tag.data(), out_for_tag.size()), "output buffer zeroed after tag failure");

    // ---- 12. Invalid service (null / empty) is rejected on wrap. ----
    // Null service fails the null-pointer check (HKDFGUARD_ERR_INVALID_ARG);
    // an empty (but non-null) service fails the length check instead, which
    // hkdfguard.cpp's ValidateAndConvertService reports as the more specific
    // HKDFGUARD_ERR_SERVICE_NAME_INVALID - see check 17 below for the
    // charset check that same function applies.
    int32_t null_service_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(nullptr, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &null_service_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects null service");

    int32_t empty_service_out_len = static_cast<int32_t>(scratch.size());
    // `""` is a valid, non-null pointer to a single '\0' byte - a distinct
    // case from `nullptr` above, and this checks the length-based rejection
    // rather than the null-pointer rejection.
    rc = hkdfguard_wrap_dek("", dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &empty_service_out_len);
    Check(rc == HKDFGUARD_ERR_SERVICE_NAME_INVALID, "wrap rejects empty service");

    // ---- 13. A different service gets its own independent KEK, and a ----
    //          payload wrapped under one service cannot be unwrapped under
    //          another.
    rc = hkdfguard_create_kek(kServiceOther, nullptr);
    Check(rc == HKDFGUARD_OK, "create_kek provisions kServiceOther's KEK");

    bool other_service_wrapped = false;
    std::vector<uint8_t> wrapped_other(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_other_len = static_cast<int32_t>(wrapped_other.size());
    rc = hkdfguard_wrap_dek(kServiceOther, dek.data(), static_cast<int32_t>(dek.size()), wrapped_other.data(), &wrapped_other_len);
    Check(rc == HKDFGUARD_OK, "wrap with a different service succeeds");
    other_service_wrapped = (rc == HKDFGUARD_OK);

    std::vector<uint8_t> out_wrong_service(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t out_wrong_service_len = static_cast<int32_t>(out_wrong_service.size());
    rc = hkdfguard_unwrap_dek(kServiceOther, wrapped.data(), wrapped_len, out_wrong_service.data(), &out_wrong_service_len);
    // kServiceOther's own KEK now exists (created just above), so this
    // legitimately opens *that* KEK and fails AES-GCM authentication rather
    // than failing to find a key at all - either is a correct "wrong
    // service can't unwrap" outcome.
    Check(rc == HKDFGUARD_ERR_PROVIDER || rc == HKDFGUARD_ERR_AUTH_FAILED, "unwrap with the wrong service fails");
    Check(AllZero(out_wrong_service.data(), out_wrong_service.size()), "output buffer zeroed after wrong-service failure");

    // ---- 14. Null-pointer argument validation, wrap side. ----
    // Each of dek/out/out_len is checked independently, with the other two
    // arguments otherwise valid, so a bug that only guards one of the three
    // pointers can't hide behind another argument also being invalid.
    int32_t null_arg_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, nullptr, HKDFGUARD_DEK_LEN, scratch.data(), &null_arg_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects null dek");

    null_arg_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), nullptr, &null_arg_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects null out");

    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects null out_len");

    // ---- 15. Negative dek_len is rejected the same way as any other wrong ----
    //          length (not just a too-small positive one) - a signed/unsigned
    //          confusion here could otherwise let a negative length slip past
    //          the `!= HKDFGUARD_DEK_LEN` check.
    int32_t neg_len_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), -1, scratch.data(), &neg_len_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects negative dek_len");

    // ---- 16. Service name length boundary: exactly 128 bytes (the documented ----
    //          maximum) succeeds; 129 bytes fails. Uses its own dedicated
    //          service names so cleanup doesn't collide with the KEKs created
    //          above.
    const std::string service128(128, 'a');
    const std::string service129(129, 'a');

    rc = hkdfguard_create_kek(service128.c_str(), nullptr);
    Check(rc == HKDFGUARD_OK, "create_kek accepts a service name exactly at the 128-byte maximum");
    bool service128_created = (rc == HKDFGUARD_OK);

    std::vector<uint8_t> wrapped_128(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_128_len = static_cast<int32_t>(wrapped_128.size());
    bool service128_wrapped = false;
    if (service128_created) {
        rc = hkdfguard_wrap_dek(
            service128.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped_128.data(), &wrapped_128_len);
        Check(rc == HKDFGUARD_OK, "wrap accepts a service name exactly at the 128-byte maximum");
        service128_wrapped = (rc == HKDFGUARD_OK);
    }

    int32_t service129_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        service129.c_str(), dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &service129_out_len);
    Check(rc == HKDFGUARD_ERR_SERVICE_NAME_INVALID, "wrap rejects a service name one byte over the 128-byte maximum");

    // ---- 17. A service name outside the alphanumeric-or-'.' allowlist is ----
    //          rejected - including one that's otherwise perfectly valid
    //          UTF-8. hkdfguard.cpp's IsValidServiceChar charset check runs
    //          before the separate UTF-8-decoding step, and rejects any byte
    //          outside ASCII alphanumeric/'.', so both this check and check
    //          18 below are, today, exercising that same charset rejection
    //          rather than the UTF-8-specific one.
    // 0x80 alone is a bare UTF-8 continuation byte with no preceding lead
    // byte - never valid at that position in any well-formed UTF-8 string,
    // and also simply not an allowed service-name character either way.
    const char kInvalidUtf8Service[] = "\x80\x80";
    int32_t invalid_utf8_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        kInvalidUtf8Service, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &invalid_utf8_out_len);
    Check(rc == HKDFGUARD_ERR_SERVICE_NAME_INVALID, "wrap rejects a service name that is not valid UTF-8");

    // ---- 18. A well-formed but non-ASCII UTF-8 service name is rejected. ----
    // UTF-8 bytes for U+00E9 (e-acute), U+65E5 (a CJK character), and
    // U+1F511 (the "key" emoji) - written as hex escapes, not literal source
    // characters, so this doesn't depend on the compiler's assumed
    // source-file encoding. Every one of these bytes has the high bit set,
    // so IsValidServiceChar rejects all of them, even though the sequence as
    // a whole is valid UTF-8 - proving the charset restriction is in fact
    // stricter than "valid UTF-8", not merely a rephrasing of it.
    constexpr char kNonAsciiService[] = "hkdfguardwin.test.\xC3\xA9\xE6\x97\xA5\xF0\x9F\x94\x91";
    int32_t non_ascii_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        kNonAsciiService, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &non_ascii_out_len);
    Check(rc == HKDFGUARD_ERR_SERVICE_NAME_INVALID, "wrap rejects a well-formed but non-ASCII UTF-8 service name");

    // ---- 19. Null-pointer argument validation, unwrap side. ----
    int32_t null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null out_len");

    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, nullptr, &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null out");

    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, nullptr, wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null wrapped");

    // ---- 20. Invalid service (null / empty) is rejected on the unwrap side too. ----
    // Check 12 above only checked this for wrap; unwrap validates `service`
    // through the exact same ValidateAndConvertService helper, but that's an
    // implementation detail this test shouldn't assume - each public entry
    // point gets its own check.
    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(nullptr, wrapped.data(), wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null service");

    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek("", wrapped.data(), wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_SERVICE_NAME_INVALID, "unwrap rejects empty service");

    // ---- 21. Negative wrapped_len is rejected as malformed, not treated as ----
    //          an enormous unsigned length - ParseWrappedDek checks the sign
    //          explicitly before ever casting it to size_t (see
    //          wire_format.cpp), and this is what proves that check is live.
    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), -1, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_MALFORMED, "unwrap rejects negative wrapped_len");

    // ---- 22. Corrupted Version byte is rejected as malformed. ----
    std::vector<uint8_t> corrupted_version = wrapped;
    corrupted_version[0] ^= 0xFF; // Version is byte offset 0 (see wire_format.h)
    std::vector<uint8_t> out_for_version(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t version_out_len = static_cast<int32_t>(out_for_version.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_version.data(), static_cast<int32_t>(corrupted_version.size()),
        out_for_version.data(), &version_out_len);
    Check(rc == HKDFGUARD_ERR_MALFORMED, "unwrap rejects a corrupted version byte");
    Check(AllZero(out_for_version.data(), out_for_version.size()), "output buffer zeroed after corrupted-version failure");

    // ---- 23. Corrupted ProviderType byte is rejected as malformed. ----
    // Set to 0, a value neither kProviderTypeTpm(1) nor kProviderTypeSoftware(2)
    // ever takes on for a genuine payload.
    std::vector<uint8_t> corrupted_provider = wrapped;
    corrupted_provider[1] = 0; // ProviderType is byte offset 1 (see wire_format.h)
    std::vector<uint8_t> out_for_provider(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t provider_out_len = static_cast<int32_t>(out_for_provider.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_provider.data(), static_cast<int32_t>(corrupted_provider.size()),
        out_for_provider.data(), &provider_out_len);
    Check(rc == HKDFGUARD_ERR_MALFORMED, "unwrap rejects an unrecognized provider type byte");
    Check(AllZero(out_for_provider.data(), out_for_provider.size()), "output buffer zeroed after unrecognized-provider-type failure");

    // ---- 24. Null-pointer argument validation, generate_and_wrap_dek. ----
    int32_t gen_null_out_len = static_cast<int32_t>(gen_scratch.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, nullptr, &gen_null_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "generate_and_wrap rejects null out");

    rc = hkdfguard_generate_and_wrap_dek(kService, gen_scratch.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "generate_and_wrap rejects null out_len");

    // ---- 25. KeyStoragePolicy is honored for all three values, forced via ----
    //          a test-only override so this doesn't depend on this
    //          machine's real registry policy setting or TPM/vTPM
    //          availability (see policy.h's SetTestPolicyOverride and
    //          CheckPolicyCreatesKek above). Every check above this point
    //          already exercises the real, registry-reading
    //          LoadEffectivePolicy() inside hkdfguard.dll on every wrap/
    //          unwrap/create_kek call - hkdfguard.dll never calls
    //          SetTestPolicyOverride itself, and the override lives in a
    //          separate copy of policy.cpp's state compiled directly into
    //          this .exe (see tests/CMakeLists.txt), so it has no way to
    //          affect the DLL even if it wanted to. This section is the
    //          only place that test-only override is exercised.
    CheckPolicyCreatesKek(
        hkdfguard::KeyStoragePolicy::SoftwareOnly,
        L"hkdfguardwin.test.policy.softwareonly",
        "SoftwareOnly policy",
        /*tpmMayBeUnavailable=*/false);

    CheckPolicyCreatesKek(
        hkdfguard::KeyStoragePolicy::PreferTpm,
        L"hkdfguardwin.test.policy.prefertpm",
        "PreferTpm policy",
        /*tpmMayBeUnavailable=*/false); // always succeeds: falls back to software when there's no TPM

    CheckPolicyCreatesKek(
        hkdfguard::KeyStoragePolicy::RequireTpm,
        L"hkdfguardwin.test.policy.requiretpm",
        "RequireTpm policy",
        /*tpmMayBeUnavailable=*/true); // no fallback - may legitimately fail without real TPM hardware

    // ---- Cleanup. ----
    // Remove the KEKs this test run created so they don't accumulate in the
    // user's key storage across repeated runs. (CheckPolicyCreatesKek above
    // already cleans up after itself.)
    CleanupKek(kServiceLifecycleWide, lifecycle_wrapped[1], "lifecycle test service");
    if (groups_csv_service_created) {
        CleanupKek(kServiceGroupsCsvWide, groups_csv_wrapped[1], "groups_csv boundary/trim test service");
    }
    CleanupKek(kServiceWide, provider_type, "primary test service");
    if (other_service_wrapped) {
        // wrapped_other[1] is the second service's own ProviderType byte -
        // may differ from `provider_type` above in principle, so it's read
        // independently rather than assumed to match.
        CleanupKek(kServiceOtherWide, wrapped_other[1], "secondary test service");
    }
    if (service128_wrapped) {
        const std::wstring service128_wide(128, L'a');
        CleanupKek(service128_wide.c_str(), wrapped_128[1], "128-byte-service-name test service");
    }

    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
