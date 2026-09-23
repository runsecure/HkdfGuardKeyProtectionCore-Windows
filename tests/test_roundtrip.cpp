// This is a small hand-rolled test program, not built on a testing
// framework like GoogleTest - it's a plain `main()` that runs a sequence of
// checks and reports pass/fail for each, then exits 0 (success, the
// standard "everything's fine" exit code a shell/CI system checks) or 1
// (failure) depending on whether anything failed. CMake's `ctest` (see
// tests/CMakeLists.txt) just runs this .exe and treats exit code 0 as a
// passing test.
#include "hkdfguard.h"  // the public ABI under test
#include "kek_store.h"  // DeleteKek, kCurrentKeyId - internal helpers, used only for cleanup below

#include <windows.h> // MultiByteToWideChar, used by Utf8ToWide below
#include <cstdio>
#include <cstring>
#include <stdexcept> // std::exception, caught in CleanupKek
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

// Converts a null-terminated UTF-8 string to UTF-16, the same conversion
// hkdfguard.cpp's own ValidateAndConvertService performs internally on the
// `service` bytes passed to hkdfguard_wrap_dek/hkdfguard_unwrap_dek. Used
// below to compute the wide form of the multi-byte-UTF-8 test service name
// for cleanup, rather than trusting a hand-typed wchar_t literal to happen
// to match that conversion's output byte-for-byte (surrogate-pair encoding
// for a character outside the Basic Multilingual Plane is easy to get
// subtly wrong by hand).
std::wstring Utf8ToWide(const char* s) {
    int len = static_cast<int>(strlen(s));
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, s, len, nullptr, 0);
    std::wstring wide(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, len, wide.data(), wide_len);
    return wide;
}

// Two distinct service names used across the checks below, each in both
// its UTF-8 form (`char`, passed to the public ABI functions) and wide
// form (`wchar_t`, passed to the internal DeleteKek for cleanup - see
// kek_store.h). Because both are plain ASCII text, the UTF-8 bytes and the
// UTF-16 code units happen to correspond 1:1 character-for-character, so
// writing out both literals by hand here (rather than converting one from
// the other at runtime) is a safe shortcut for test code specifically.
constexpr char kService[] = "hkdfguardwin-test-service";
constexpr wchar_t kServiceWide[] = L"hkdfguardwin-test-service";
constexpr char kServiceOther[] = "hkdfguardwin-test-service-other";
constexpr wchar_t kServiceOtherWide[] = L"hkdfguardwin-test-service-other";

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

} // namespace

int main() {
    // ---- 1. Basic wrap -> unwrap roundtrip. ----
    std::vector<uint8_t> dek = MakeDek();
    std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_LEN);
    // `wrapped_len` is initialized to the buffer's actual capacity before
    // the call - this is the "in" half of the in/out `out_len` parameter
    // (see hkdfguard.h); hkdfguard_wrap_dek reads this to know how much
    // room it has, then overwrites it with the real output length.
    int32_t wrapped_len = static_cast<int32_t>(wrapped.size());

    // `&wrapped_len` - the address-of operator - is how a plain local
    // variable is turned into the `int32_t*` the function signature
    // requires for its in/out parameter.
    int32_t rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrapped_len);
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

    // ---- 1b. Unwrapping the same payload again is idempotent: the payload ----
    //          isn't mutated/consumed by a successful unwrap, so a second,
    //          independent unwrap of the exact same bytes must succeed again
    //          and recover the identical DEK.
    std::vector<uint8_t> unwrapped_again(HKDFGUARD_DEK_LEN);
    int32_t unwrapped_again_len = static_cast<int32_t>(unwrapped_again.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped_again.data(), &unwrapped_again_len);
    Check(rc == HKDFGUARD_OK, "unwrapping the same payload a second time succeeds");
    Check(
        std::memcmp(dek.data(), unwrapped_again.data(), HKDFGUARD_DEK_LEN) == 0,
        "second unwrap of the same payload recovers the identical DEK");

    // ---- 2. Repeated wrap reuses the same (provider, KeyId). ----
    // KeyId is fixed for this format version, and provider selection should
    // be stable across calls rather than flip-flopping.
    std::vector<uint8_t> wrapped2(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped2_len = static_cast<int32_t>(wrapped2.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped2.data(), &wrapped2_len);
    Check(rc == HKDFGUARD_OK, "second wrap succeeds");
    Check(wrapped2[1] == provider_type, "second wrap reuses the same provider type");

    // ---- 3. hkdfguard_generate_and_wrap_dek: generates its own DEK, wraps
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

    // ---- 4. generate_and_wrap_dek argument validation. ----
    std::vector<uint8_t> gen_scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t gen_scratch_len = static_cast<int32_t>(gen_scratch.size());
    rc = hkdfguard_generate_and_wrap_dek(nullptr, gen_scratch.data(), &gen_scratch_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "generate_and_wrap rejects null service");

    std::vector<uint8_t> gen_tiny_buf(HKDFGUARD_WRAPPED_LEN - 1);
    int32_t gen_tiny_buf_len = static_cast<int32_t>(gen_tiny_buf.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, gen_tiny_buf.data(), &gen_tiny_buf_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "generate_and_wrap rejects too-small output buffer");

    // ---- 5. Invalid dek_len. ----
    int32_t bad_len = 16;
    std::vector<uint8_t> scratch(HKDFGUARD_WRAPPED_LEN);
    int32_t scratch_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), bad_len, scratch.data(), &scratch_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects wrong dek_len");

    // ---- 6. Buffer too small on wrap. ----
    // (Named `tiny_buf`/`tiny_out`, not `small`/`small_out`, because
    // <windows.h> - pulled in transitively through kek_store.h - #defines
    // the plain identifier `small` as a legacy MIDL type; using it as a
    // variable name here would fail to compile.)
    std::vector<uint8_t> tiny_buf(HKDFGUARD_WRAPPED_LEN - 1);
    int32_t tiny_buf_len = static_cast<int32_t>(tiny_buf.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), tiny_buf.data(), &tiny_buf_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "wrap rejects too-small output buffer");

    // ---- 7. Buffer too small on unwrap. ----
    std::vector<uint8_t> tiny_out(HKDFGUARD_DEK_LEN - 1);
    int32_t tiny_out_len = static_cast<int32_t>(tiny_out.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, tiny_out.data(), &tiny_out_len);
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "unwrap rejects too-small output buffer");

    // ---- 8. Malformed payload (truncated). ----
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

    // ---- 9. Corrupted ciphertext -> authentication failure, output zeroed. ----
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

    // ---- 10. Corrupted tag -> authentication failure, output zeroed. ----
    std::vector<uint8_t> corrupted_tag = wrapped;
    corrupted_tag[wrapped_len - 1] ^= 0xFF; // inside the tag region (the payload's very last byte)
    std::vector<uint8_t> out_for_tag(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t tag_out_len = static_cast<int32_t>(out_for_tag.size());
    rc = hkdfguard_unwrap_dek(kService, corrupted_tag.data(), static_cast<int32_t>(corrupted_tag.size()),
                              out_for_tag.data(), &tag_out_len);
    Check(rc == HKDFGUARD_ERR_AUTH_FAILED, "unwrap rejects corrupted tag");
    Check(AllZero(out_for_tag.data(), out_for_tag.size()), "output buffer zeroed after tag failure");

    // ---- 11. Invalid service (null / empty) is rejected. ----
    int32_t null_service_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(nullptr, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &null_service_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects null service");

    int32_t empty_service_out_len = static_cast<int32_t>(scratch.size());
    // `""` is a valid, non-null pointer to a single '\0' byte - a distinct
    // case from `nullptr` above, and this checks the length-based rejection
    // (strnlen returns 0) rather than the null-pointer rejection.
    rc = hkdfguard_wrap_dek("", dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &empty_service_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects empty service");

    // ---- 12. A different service gets its own independent KEK, and a ----
    //          payload wrapped under one service cannot be unwrapped under
    //          another.
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

    // ---- 13. Null-pointer argument validation, wrap side. ----
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

    // ---- 14. Negative dek_len is rejected the same way as any other wrong ----
    //          length (not just a too-small positive one) - a signed/unsigned
    //          confusion here could otherwise let a negative length slip past
    //          the `!= HKDFGUARD_DEK_LEN` check.
    int32_t neg_len_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(kService, dek.data(), -1, scratch.data(), &neg_len_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects negative dek_len");

    // ---- 15. Service name length boundary: exactly 128 bytes (the documented ----
    //          maximum) succeeds; 129 bytes fails. Uses its own dedicated
    //          service names so cleanup doesn't collide with the KEKs created
    //          above.
    const std::string service128(128, 'a');
    const std::string service129(129, 'a');
    std::vector<uint8_t> wrapped_128(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_128_len = static_cast<int32_t>(wrapped_128.size());
    rc = hkdfguard_wrap_dek(
        service128.c_str(), dek.data(), static_cast<int32_t>(dek.size()), wrapped_128.data(), &wrapped_128_len);
    Check(rc == HKDFGUARD_OK, "wrap accepts a service name exactly at the 128-byte maximum");
    bool service128_wrapped = (rc == HKDFGUARD_OK);

    int32_t service129_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        service129.c_str(), dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &service129_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects a service name one byte over the 128-byte maximum");

    // ---- 16. Invalid UTF-8 in the service name is rejected. ----
    // 0x80 alone is a bare UTF-8 continuation byte with no preceding lead
    // byte - never valid at that position in any well-formed UTF-8 string.
    const char kInvalidUtf8Service[] = "\x80\x80";
    int32_t invalid_utf8_out_len = static_cast<int32_t>(scratch.size());
    rc = hkdfguard_wrap_dek(
        kInvalidUtf8Service, dek.data(), static_cast<int32_t>(dek.size()), scratch.data(), &invalid_utf8_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "wrap rejects a service name that is not valid UTF-8");

    // ---- 17. A multi-byte UTF-8 service name round-trips correctly. ----
    // Exercises the actual UTF-8 -> UTF-16 conversion path (kek_store.cpp's
    // KeyName) with real multi-byte characters, not just the plain-ASCII
    // service names used everywhere else in this file.
    // UTF-8 bytes for U+00E9 (e-acute), U+65E5 (a CJK character), U+1F511
    // (the "key" emoji, outside the Basic Multilingual Plane - requires a
    // UTF-16 surrogate pair once converted). Written as hex escapes, not
    // literal source characters, so this doesn't depend on the compiler's
    // assumed source-file encoding - the wide form used below for cleanup
    // is computed from these same bytes at runtime via Utf8ToWide, not
    // hand-typed separately.
    constexpr char kUnicodeService[] = "hkdfguardwin-test-\xC3\xA9\xE6\x97\xA5\xF0\x9F\x94\x91";
    std::vector<uint8_t> wrapped_unicode(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_unicode_len = static_cast<int32_t>(wrapped_unicode.size());
    rc = hkdfguard_wrap_dek(
        kUnicodeService, dek.data(), static_cast<int32_t>(dek.size()), wrapped_unicode.data(), &wrapped_unicode_len);
    Check(rc == HKDFGUARD_OK, "wrap accepts a multi-byte UTF-8 service name");
    bool unicode_wrapped = (rc == HKDFGUARD_OK);
    uint8_t unicode_provider_type = unicode_wrapped ? wrapped_unicode[1] : 0;

    std::vector<uint8_t> unicode_unwrapped(HKDFGUARD_DEK_LEN);
    int32_t unicode_unwrapped_len = static_cast<int32_t>(unicode_unwrapped.size());
    rc = hkdfguard_unwrap_dek(
        kUnicodeService, wrapped_unicode.data(), wrapped_unicode_len, unicode_unwrapped.data(), &unicode_unwrapped_len);
    Check(rc == HKDFGUARD_OK, "unwrap succeeds for the multi-byte UTF-8 service name");
    Check(
        std::memcmp(dek.data(), unicode_unwrapped.data(), HKDFGUARD_DEK_LEN) == 0,
        "unwrapped DEK matches original for the multi-byte UTF-8 service name");

    // ---- 18. Null-pointer argument validation, unwrap side. ----
    int32_t null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, unwrapped.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null out_len");

    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), wrapped_len, nullptr, &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null out");

    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, nullptr, wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null wrapped");

    // ---- 19. Invalid service (null / empty) is rejected on the unwrap side too. ----
    // Section 11 above only checked this for wrap; unwrap validates `service`
    // through the exact same ValidateAndConvertService helper, but that's an
    // implementation detail this test shouldn't assume - each public entry
    // point gets its own check.
    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(nullptr, wrapped.data(), wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects null service");

    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek("", wrapped.data(), wrapped_len, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "unwrap rejects empty service");

    // ---- 20. Negative wrapped_len is rejected as malformed, not treated as ----
    //          an enormous unsigned length - ParseWrappedDek checks the sign
    //          explicitly before ever casting it to size_t (see
    //          wire_format.cpp), and this is what proves that check is live.
    null_unwrap_out_len = static_cast<int32_t>(unwrapped.size());
    rc = hkdfguard_unwrap_dek(kService, wrapped.data(), -1, unwrapped.data(), &null_unwrap_out_len);
    Check(rc == HKDFGUARD_ERR_MALFORMED, "unwrap rejects negative wrapped_len");

    // ---- 21. Corrupted Version byte is rejected as malformed. ----
    std::vector<uint8_t> corrupted_version = wrapped;
    corrupted_version[0] ^= 0xFF; // Version is byte offset 0 (see wire_format.h)
    std::vector<uint8_t> out_for_version(HKDFGUARD_DEK_LEN, 0xAA);
    int32_t version_out_len = static_cast<int32_t>(out_for_version.size());
    rc = hkdfguard_unwrap_dek(
        kService, corrupted_version.data(), static_cast<int32_t>(corrupted_version.size()),
        out_for_version.data(), &version_out_len);
    Check(rc == HKDFGUARD_ERR_MALFORMED, "unwrap rejects a corrupted version byte");
    Check(AllZero(out_for_version.data(), out_for_version.size()), "output buffer zeroed after corrupted-version failure");

    // ---- 22. Corrupted ProviderType byte is rejected as malformed. ----
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

    // ---- 23. Null-pointer argument validation, generate_and_wrap_dek. ----
    int32_t gen_null_out_len = static_cast<int32_t>(gen_scratch.size());
    rc = hkdfguard_generate_and_wrap_dek(kService, nullptr, &gen_null_out_len);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "generate_and_wrap rejects null out");

    rc = hkdfguard_generate_and_wrap_dek(kService, gen_scratch.data(), nullptr);
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "generate_and_wrap rejects null out_len");

    // ---- Cleanup. ----
    // Remove the KEKs this test run created so they don't accumulate in the
    // user's key storage across repeated runs.
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
    if (unicode_wrapped) {
        CleanupKek(Utf8ToWide(kUnicodeService).c_str(), unicode_provider_type, "multi-byte UTF-8 service name test service");
    }

    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
