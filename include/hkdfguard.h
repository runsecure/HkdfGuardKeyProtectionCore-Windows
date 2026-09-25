// #ifndef / #define / #endif below is an "include guard": if this header
// gets #include'd more than once while compiling a single .cpp file (which
// happens easily once several of your own headers include each other), the
// guard makes every #include after the first one expand to nothing, so the
// compiler never sees the declarations twice.
#ifndef HKDFGUARD_H
#define HKDFGUARD_H

// stdint.h (the C header; <cstdint> is the C++-flavored equivalent) gives us
// fixed-width integer types like uint8_t (unsigned, exactly 8 bits) and
// int32_t (signed, exactly 32 bits). Windows' own type names (BYTE, DWORD,
// ...) intentionally do NOT appear anywhere in this file - the whole point
// of this header is to be usable from C, C#, Python, Java, Go, etc., none of
// which know what a DWORD is.
#include <stdint.h>

// __declspec(dllexport) / __declspec(dllimport) are MSVC-specific keywords
// that control whether a function's symbol is written into (export) or read
// from (import) a DLL's symbol table. The convention used here - define
// HKDFGUARD_API to dllexport while *building* the DLL, and to dllimport for
// anyone who *consumes* it - is the standard Windows way to share one header
// between the library's own .cpp files and its callers. HKDFGUARD_EXPORTS is
// defined only by this project's own build (see CMakeLists.txt); nobody
// #include-ing this header from outside the project defines it, so they
// automatically get the "import" branch.
#if defined(_WIN32)
#  if defined(HKDFGUARD_EXPORTS)
#    define HKDFGUARD_API __declspec(dllexport)
#  else
#    define HKDFGUARD_API __declspec(dllimport)
#  endif
#else
// Non-Windows platforms don't have dllexport/dllimport at all, so the macro
// just disappears (this branch exists only so the header doesn't hard-fail
// if some tool ever parses it on another OS; the library itself is
// Windows-only, see CMakeLists.txt).
#  define HKDFGUARD_API
#endif

// extern "C" tells the C++ compiler: "compile everything inside these braces
// using C linkage rules, not C++ ones." Without it, C++ would "mangle" the
// function names (encoding parameter types into the symbol name, e.g.
// hkdfguard_wrap_dek becomes something like ?hkdfguard_wrap_dek@@YAHPEBEH...)
// so that overloaded functions can coexist. A mangled name is compiler- and
// version-specific, so no other language's FFI (C#'s P/Invoke, Python's
// ctypes, Go's cgo, ...) could reliably call it. extern "C" pins the name to
// the plain, predictable string "hkdfguard_wrap_dek", which is what makes
// this a *stable C ABI*. __cplusplus is only defined when a C++ compiler is
// processing the file, so a plain C compiler (which has no notion of linkage
// specifications) skips this block entirely and just sees ordinary
// declarations.
#ifdef __cplusplus
extern "C" {
#endif

/*
 * HkdfGuardWin - Windows-native DEK wrapper.
 *
 * Wraps and unwraps a 32-byte Data Encryption Key (DEK) using a persistent,
 * machine-wide-scoped, non-exportable P-256 Key Encryption Key (KEK) held by
 * the Microsoft Platform Crypto Provider (TPM/vTPM) when available, or the
 * Microsoft Software Key Storage Provider otherwise. All Windows-specific
 * details (CNG/NCrypt handles, COM, provider selection) are fully contained
 * behind this ABI. No exception ever crosses this boundary; every function
 * returns one of the HKDFGUARD_* status codes below.
 */

// #define here creates a plain, untyped preprocessor macro: every later
// occurrence of the name HKDFGUARD_DEK_LEN in this file (and any file that
// #includes it) is textually replaced with 32 before the compiler proper
// ever runs. This is the traditional C way of naming a constant so it can
// also be used where the language requires a compile-time literal.
#define HKDFGUARD_DEK_LEN     32
#define HKDFGUARD_WRAPPED_LEN 132 /* fixed size of a WrappedDekV1 payload */

// Status codes. HKDFGUARD_OK is 0 (following the common C convention that
// "0 means success"); every failure is a distinct *negative* number, so a
// caller can cheaply test "did this fail?" with `if (rc < 0)` without having
// to know the individual codes, while still being able to branch on the
// exact one if they care. The parentheses around the negative numbers, e.g.
// (-1), are just defensive style: they stop the macro from being
// misinterpreted if it's ever substituted next to another operator in a
// caller's expression, e.g. `x - HKDFGUARD_ERR_INVALID_ARG` — with no
// parens that would textually become `x - -1`.
#define HKDFGUARD_OK                    0
#define HKDFGUARD_ERR_INVALID_ARG      (-1) /* null pointer, wrong dek length, bad service, etc. */
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL (-2) /* *out_len on input is too small for the result */
#define HKDFGUARD_ERR_PROVIDER         (-3) /* KEK provider/key open or create failed */
#define HKDFGUARD_ERR_CRYPTO           (-4) /* ECDH/HKDF/AES operation failed (non-auth) */
#define HKDFGUARD_ERR_AUTH_FAILED      (-5) /* AES-GCM authentication tag verification failed */
#define HKDFGUARD_ERR_MALFORMED        (-6) /* wrapped payload is not a valid WrappedDekV1 */
#define HKDFGUARD_ERR_INTERNAL         (-7) /* unexpected internal failure */
#define HKDFGUARD_ERR_SERVICE_NAME_INVALID (-8) /* Service Name is malformed or invalid */
#define HKDFGUARD_ERR_INVALID_POLICY   (-9) /* Invalid Key Storage Policy Flag */

HKDFGUARD_API int32_t hkdfguard_ensure_kek(
    const char* service,
    const char* groups_csv);

/*
 * Wraps a 32-byte DEK into a self-contained, versioned payload.
 *
 * service   - null-terminated UTF-8 string identifying which persistent KEK
 *             to use (e.g. an application or tenant name). Different service
 *             names get independent, non-interoperable KEKs. The same
 *             service name must be passed to hkdfguard_unwrap_dek to unwrap
 *             a payload produced with it; the service name itself is not
 *             recorded in the wrapped payload. Must be non-null, non-empty,
 *             and at most 128 bytes (excluding the null terminator).
 * dek       - pointer to exactly HKDFGUARD_DEK_LEN bytes of plaintext DEK.
 * dek_len   - must equal HKDFGUARD_DEK_LEN.
 * out       - caller-owned output buffer.
 * out_len   - in: capacity of out, in bytes.
 *             out: on success, the number of bytes written (always
 *             HKDFGUARD_WRAPPED_LEN).
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 * On failure, no partial output is left in the caller's buffer.
*/

HKDFGUARD_API int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int32_t dek_len,
    uint8_t* out, int32_t* out_len);

/*
 * Unwraps a payload produced by hkdfguard_wrap_dek back into a 32-byte DEK.
 *
 * service     - must be the same service name passed to hkdfguard_wrap_dek
 *               when this payload was produced; see hkdfguard_wrap_dek.
 * wrapped     - pointer to the wrapped payload.
 * wrapped_len - length of the wrapped payload in bytes.
 * out         - caller-owned output buffer.
 * out_len     - in: capacity of out, in bytes (must be >= HKDFGUARD_DEK_LEN).
 *               out: on success, the number of plaintext bytes written
 *               (always HKDFGUARD_DEK_LEN).
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 * On any failure (including authentication failure), the output buffer is
 * zeroed before returning; no plaintext is left behind.
 */
HKDFGUARD_API int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int32_t wrapped_len,
    uint8_t* out, int32_t* out_len);

HKDFGUARD_API int32_t hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out, int32_t* out_len);

// Closes the extern "C" block opened above.
#ifdef __cplusplus
}
#endif

// Closes the include guard opened at the top of the file.
#endif /* HKDFGUARD_H */
