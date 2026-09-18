// This file is the boundary between the public C ABI (hkdfguard.h) and this
// project's internal C++ implementation. Everything here has one job:
// validate arguments, orchestrate the internal helpers in the right order,
// and translate C++ exceptions into the plain integer status codes the ABI
// promises - nothing crypto-specific happens directly in this file.
#include "../include/hkdfguard.h"

#include "aes_gcm.h"
#include "ecdh_hkdf.h"
#include "errors.h"
#include "kek_store.h"
#include "secure_buffer.h"
#include "wire_format.h"

// windows.h: MultiByteToWideChar, CP_UTF8, MB_ERR_INVALID_CHARS (used by
// ValidateAndConvertService below). cstring: strnlen. string: std::wstring.
#include <windows.h>
#include <cstring>
#include <string>

// `using namespace hkdfguard;` brings every name declared inside `namespace
// hkdfguard { ... }` (SecureBuffer, ResolvedKek, HkdfGuardError, the
// kEphemeralPubLen/kNonceLen/... constants, AesGcmEncrypt, and so on) into
// scope here without needing the `hkdfguard::` prefix on each one. This is
// a deliberate, narrow use of the directive: it's placed in a .cpp file
// (never in a header, where it would leak into every file that includes
// that header) and this file is small enough that the risk of an
// accidental name collision is low.
using namespace hkdfguard;

// Anonymous namespace: ValidateAndConvertService below is only used inside
// this file (see aes_gcm.cpp's OpenAesKey for the fuller explanation of
// what this construct does).
namespace {

constexpr size_t kMaxServiceLen = 128; // bytes, excluding the null terminator

// Validates and converts the caller's UTF-8 service name into the wide
// string used as part of the persisted KEK's name. Throws
// HkdfGuardError(HKDFGUARD_ERR_INVALID_ARG) if `service` is null, empty,
// too long, or not valid UTF-8.
std::wstring ValidateAndConvertService(const char* service) {
    if (service == nullptr) {
        throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARG, "service is null");
    }
    // strnlen behaves like the familiar strlen (walk forward until a '\0'
    // byte, return how many bytes were seen) but stops early and returns
    // `kMaxServiceLen + 1` if no '\0' turns up within that many bytes
    // first - this bounds how far into `service` we ever read, in case the
    // caller passed a pointer to a buffer that isn't actually
    // null-terminated within any reasonable length (a defensive measure
    // against a misbehaving caller, since this is a boundary the ABI has no
    // other way to validate: `service` is just a raw pointer with no length
    // parameter alongside it, by design, since it's meant to be an ordinary
    // C string).
    size_t len = strnlen(service, kMaxServiceLen + 1);
    if (len == 0 || len > kMaxServiceLen) {
        throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARG, "service is empty or too long");
    }

    // Converting UTF-8 (`service`, as documented in hkdfguard.h) to UTF-16
    // (the std::wstring every NCrypt key-name parameter ultimately needs)
    // is, like several other Windows APIs already seen in this project, a
    // two-call "ask for the size, then convert for real" operation.
    // MB_ERR_INVALID_CHARS makes the call fail outright (returning 0)
    // rather than silently substituting a placeholder character if
    // `service` isn't actually valid UTF-8.
    int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, service, static_cast<int>(len), nullptr, 0);
    if (wide_len <= 0) {
        throw HkdfGuardError(HKDFGUARD_ERR_INVALID_ARG, "service is not valid UTF-8");
    }
    // `std::wstring wide(static_cast<size_t>(wide_len), L'\0')` constructs a
    // wide string of exactly `wide_len` characters, every one initially
    // L'\0' - i.e. pre-allocates the right amount of storage for
    // MultiByteToWideChar's second call to write its real output into via
    // `wide.data()`.
    std::wstring wide(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, service, static_cast<int>(len), wide.data(), wide_len);
    return wide;
}

} // namespace

// `extern "C"` here (repeated at each function, rather than wrapping both
// in one block) matches how hkdfguard.h declared them, and is required for
// the same reason explained there: it gives these two functions the plain,
// unmangled names ("hkdfguard_wrap_dek"/"hkdfguard_unwrap_dek") that other
// languages' FFI layers look up by exact string. HKDFGUARD_API expands to
// __declspec(dllexport) here specifically because CMakeLists.txt defines
// HKDFGUARD_EXPORTS only while compiling this DLL's own sources (see
// hkdfguard.h's comment on that macro).
extern "C" HKDFGUARD_API int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int32_t dek_len,
    uint8_t* out, int32_t* out_len) {
    // The entire body lives inside one `try` block: this is what makes it
    // possible for every internal helper (ValidateAndConvertService,
    // ResolveOrCreateKekForWrap, DeriveWrappingKeyForWrap, AesGcmEncrypt,
    // ...) to simply `throw HkdfGuardError(...)` the moment something goes
    // wrong, instead of every one of them returning a code that this
    // function would otherwise have to check after every single call. Two
    // `catch` clauses below turn whatever came out of the `try` block back
    // into a plain `int32_t` for the ABI - which is the one and only place
    // in this whole codebase a C++ exception is allowed to stop, per the
    // "no exception crosses the ABI" requirement.
    try {
        // Basic null-pointer validation before touching any of the
        // pointers. `dek_len`/`out_len` themselves are validated next.
        if (dek == nullptr || out == nullptr || out_len == nullptr) {
            return HKDFGUARD_ERR_INVALID_ARG;
        }
        if (dek_len != HKDFGUARD_DEK_LEN) {
            return HKDFGUARD_ERR_INVALID_ARG;
        }
        // `*out_len` dereferences the pointer to read the caller-supplied
        // buffer capacity (the "in" half of this in/out parameter - see
        // hkdfguard.h's note on this pattern). Checked before doing any
        // real work, so a too-small buffer fails fast.
        if (*out_len < HKDFGUARD_WRAPPED_LEN) {
            return HKDFGUARD_ERR_BUFFER_TOO_SMALL;
        }

        std::wstring service_name = ValidateAndConvertService(service);

        // Resolve (create if necessary) the current user's persistent KEK
        // for this service, preferring the TPM/vTPM-backed Platform Crypto
        // Provider and falling back to the Software Key Storage Provider
        // automatically.
        ResolvedKek kek = ResolveOrCreateKekForWrap(service_name);

        // Ephemeral ECDH + HKDF-SHA256 -> 32-byte AES wrapping key. Only the
        // KEK's public key is needed here, so this never touches the TPM.
        uint8_t ephemeral_pub[kEphemeralPubLen];
        // `nonce`/`ciphertext`/`tag` are declared here, *outside* the nested
        // block below, because they're needed again afterward (by
        // SerializeWrappedDek) - none of the three is secret (they're all
        // meant to become part of the public wrapped payload), so there's
        // no reason to scope them any more tightly than that.
        uint8_t nonce[kNonceLen];
        uint8_t ciphertext[kCiphertextLen];
        uint8_t tag[kTagLen];
        {
            // `wrapping_key` - the actual AES-256 key material derived for
            // this one wrap call - is deliberately declared inside this
            // nested `{ ... }` block rather than alongside the buffers
            // above, and used for nothing outside of it. That means its
            // destructor (SecureBuffer's SecureZeroMemory wipe - see
            // secure_buffer.h) fires the instant this block ends, i.e.
            // immediately after AesGcmEncrypt's done with it, rather than
            // only at the end of the whole hkdfguard_wrap_dek function
            // (which would otherwise leave it sitting around, unused but
            // unwiped, for the length of SerializeWrappedDek and the
            // `return` below). This is the same "shrink the scope to
            // shrink the lifetime" technique used for `prk` inside
            // ecdh_hkdf.cpp's HkdfSha256.
            SecureBuffer<32> wrapping_key;
            DeriveWrappingKeyForWrap(kek.key.get(), ephemeral_pub, wrapping_key);

            // AES-256-GCM directly from the caller's dek pointer - no
            // intermediate plaintext staging buffer.
            AesGcmEncrypt(wrapping_key.data(), dek, static_cast<unsigned long>(dek_len), nonce, ciphertext, tag);
        } // <- wrapping_key's destructor (zeroing it) runs here, right now.

        // Assemble the final 132-byte payload directly into the caller's
        // buffer, and report how many bytes were written back through the
        // out-parameter.
        SerializeWrappedDek(kek.provider_type, kek.key_id, ephemeral_pub, nonce, ciphertext, tag, out);
        *out_len = static_cast<int32_t>(kTotalLen);
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError& e) {
        // The expected/"normal" failure path: one of our own helpers threw
        // a specific, meaningful status code - just hand it straight back
        // to the caller.
        return e.code();
    } catch (...) {
        // `catch (...)` is C++'s "catch absolutely anything" handler - it
        // matches even exception types this code has never heard of (a
        // standard library exception like std::bad_alloc from a failed
        // heap allocation, for instance). This is the final safety net that
        // makes the ABI's "no exception ever crosses this boundary"
        // guarantee unconditionally true, not just true for the specific
        // exception type this project happens to throw itself.
        return HKDFGUARD_ERR_INTERNAL;
    }
}

extern "C" HKDFGUARD_API int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int32_t wrapped_len,
    uint8_t* out, int32_t* out_len) {
    // out_len must be checked before anything else - every other line in
    // this function (including the `fail` helper defined just below) needs
    // to be able to dereference it safely.
    if (out_len == nullptr) {
        return HKDFGUARD_ERR_INVALID_ARG;
    }

    // Captured once, up front, before any chance of `*out_len` being
    // overwritten - `capacity` is what the caller originally promised about
    // the size of `out`, and it's what `fail` below uses to know how many
    // bytes it's safe to zero.
    const int32_t capacity = *out_len;
    // A *lambda expression*: an anonymous, inline function value. `[&]`
    // is the "capture clause" - it says this lambda may refer to any local
    // variable from the enclosing function (here, `out` and `capacity`) *by
    // reference*, i.e. it sees their live values at the moment it's called,
    // not a snapshot taken when the lambda was created. `(int32_t code)` is
    // its parameter list, and the body is the same as an ordinary function.
    // `fail` is then called, below, from several different places as a
    // single shared "on any failure, do this, then return that code" helper
    // - avoiding repeating the zero-then-return logic at every one of those
    // call sites.
    auto fail = [&](int32_t code) {
        // On any failure path, wipe whatever the caller declared as the
        // buffer's capacity, since AES-GCM decryption can write
        // unauthenticated plaintext into `out` even when it ultimately
        // fails (e.g. a tag mismatch) - no stale plaintext may remain.
        if (out != nullptr && capacity > 0) {
            SecureZero(out, static_cast<size_t>(capacity));
        }
        return code;
    };

    try {
        if (out == nullptr || wrapped == nullptr) {
            return fail(HKDFGUARD_ERR_INVALID_ARG);
        }
        if (capacity < HKDFGUARD_DEK_LEN) {
            return fail(HKDFGUARD_ERR_BUFFER_TOO_SMALL);
        }

        std::wstring service_name = ValidateAndConvertService(service);

        // Validates the payload's shape/version and hands back pointers
        // into `wrapped` for each field (see wire_format.h/.cpp) - throws
        // HKDFGUARD_ERR_MALFORMED on anything that doesn't look like a
        // genuine WrappedDekV1 payload.
        ParsedWrappedDek parsed = ParseWrappedDek(wrapped, wrapped_len);

        // Open (never create) the exact KEK that produced this payload.
        ResolvedKek kek = OpenKekForUnwrap(service_name, parsed.provider_type, parsed.key_id);

        {
            // Same reasoning as the wrap side above: `wrapping_key` is
            // scoped to only the two statements that need it, so it's
            // wiped the moment this block ends - immediately after
            // AesGcmDecrypt is done with it - rather than lingering,
            // unused, until the function returns.
            SecureBuffer<32> wrapping_key;
            // ECDH against the KEK's private key (may execute inside a
            // TPM/vTPM) + HKDF-SHA256 -> the same 32-byte wrapping key
            // derived at wrap time.
            DeriveWrappingKeyForUnwrap(kek.provider.get(), kek.key.get(), parsed.ephemeral_pub, wrapping_key);

            // Decrypt directly into the caller's buffer - no intermediate
            // plaintext staging buffer.
            AesGcmDecrypt(
                wrapping_key.data(), parsed.nonce, parsed.ciphertext,
                static_cast<unsigned long>(kCiphertextLen), parsed.tag, out);
        } // <- wrapping_key's destructor (zeroing it) runs here, right now.

        // Success: `out` now holds the recovered plaintext DEK (its one
        // and only copy - this function never staged it anywhere else),
        // and the caller is told exactly how many bytes that is.
        *out_len = HKDFGUARD_DEK_LEN;
        return HKDFGUARD_OK;
    } catch (const HkdfGuardError& e) {
        // Note this correctly covers the auth-failure case too:
        // AesGcmDecrypt throws HkdfGuardError(HKDFGUARD_ERR_AUTH_FAILED) on
        // a tag mismatch, which unwinds out through the nested block above
        // (wiping wrapping_key via its destructor along the way, same as
        // any other exit) and is caught right here, where `fail(e.code())`
        // then zeroes `out` before this function returns - satisfying "no
        // stale plaintext may remain" even though some unauthenticated
        // bytes may have been written into `out` by BCryptDecrypt before it
        // detected the mismatch (see aes_gcm.cpp's comment on that).
        return fail(e.code());
    } catch (...) {
        return fail(HKDFGUARD_ERR_INTERNAL);
    }
}
