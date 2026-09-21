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
 * user-scoped, non-exportable P-256 Key Encryption Key (KEK) held by the
 * Microsoft Platform Crypto Provider (TPM/vTPM) when available, or the
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
// Reading the declaration itself: HKDFGUARD_API expands to dllexport/
// dllimport as explained above. int32_t is the return type. `const uint8_t*
// dek` is a pointer to bytes the function will only ever read (const), never
// write, through that pointer - a documentation-and-compiler-enforced
// promise to the caller. `int32_t* out_len` is a pointer to a single
// int32_t that acts as *both* an input (the caller writes the buffer's
// capacity into it before calling) and an output (the function overwrites
// it with the actual result length on success) - this "in/out parameter"
// pattern is how C APIs return more than one value without needing a struct
// or multiple return values.
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

/*
 * Direct AES-GCM encrypt/decrypt under a caller-supplied key (typically a
 * DEK already recovered via hkdfguard_unwrap_dek above), rather than a
 * Secure Enclave/TPM-backed KEK. `key_len` must be 16, 24, or 32
 * (AES-128/192/256). Unlike hkdfguard_wrap_dek/hkdfguard_unwrap_dek above,
 * these two do NOT use the out_len in/out-capacity convention: a
 * non-negative return is the number of bytes written to `result`; a
 * negative return is one of the HKDFGUARD_ERR_* codes above. This matches
 * the calling convention used by this project's macOS and Linux
 * implementations for the same four functions (this pair, plus the two
 * "_with_wrapped_dek" functions further below).
 *
 * Payload layout, both what hkdfguard_encrypt writes and what
 * hkdfguard_decrypt expects to read:
 *   [12-byte nonce][ciphertext, same length as the plaintext][16-byte tag]
 *
 * `key` is NOT const in either function below: both zero it in place (all
 * `key_len` bytes) before returning, on every exit path except an invalid
 * `key_len` (nothing has been validated as safe to touch on that path).
 * Callers must not reuse that buffer as key material afterward.
 */

/*
 * `result` must have capacity for at least `plaintext_len + 28` bytes.
 * `aad`/`aad_len` may be NULL/0 for no additional authenticated data.
 */
HKDFGUARD_API int32_t hkdfguard_encrypt(
    uint8_t* key, int32_t key_len,
    const uint8_t* plaintext, int32_t plaintext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

/*
 * `ciphertext` must be a `nonce || ciphertext || tag` payload produced by
 * hkdfguard_encrypt (at least 28 bytes - an empty original plaintext still
 * produces a 28-byte payload). `result` must have capacity for at least
 * `ciphertext_len - 28` bytes. `aad`/`aad_len` must match what was passed
 * to hkdfguard_encrypt, or decryption fails with HKDFGUARD_ERR_AUTH_FAILED.
 *
 * On any failure, every byte of the caller's originally-declared `result`
 * capacity is zeroed before returning - unlike hkdfguard_encrypt, since
 * BCryptDecrypt (the underlying CNG call) can write unauthenticated
 * plaintext into `result` even when it ultimately fails.
 */
HKDFGUARD_API int32_t hkdfguard_decrypt(
    uint8_t* key, int32_t key_len,
    const uint8_t* ciphertext, int32_t ciphertext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

/*
 * Combines hkdfguard_unwrap_dek and hkdfguard_encrypt/hkdfguard_decrypt
 * above into a single call: given a wrapped DEK (as produced by
 * hkdfguard_wrap_dek) and the same `service` it was wrapped under, these
 * unwrap it under the persistent KEK and immediately use the recovered DEK
 * for AES-GCM encryption/decryption. The raw DEK never crosses this
 * boundary at all - it exists only inside this library, for the duration
 * of one call, and is zeroed before returning.
 *
 * Return value: same convention as hkdfguard_encrypt/hkdfguard_decrypt - a
 * non-negative return is the byte count written to `result`; a negative
 * return is one of the HKDFGUARD_ERR_* codes above, from whichever stage
 * (unwrapping, or the AES-GCM operation) failed first.
 *
 * `result` must have capacity for at least `plaintext_len + 28` bytes.
 * `aad`/`aad_len` may be NULL/0 for no additional authenticated data.
 */
HKDFGUARD_API int32_t hkdfguard_encrypt_with_wrapped_dek(
    const char* service,
    const uint8_t* wrapped_dek, int32_t wrapped_dek_len,
    const uint8_t* plaintext, int32_t plaintext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

/*
 * `ciphertext` must be a `nonce || ciphertext || tag` payload produced by
 * hkdfguard_encrypt or hkdfguard_encrypt_with_wrapped_dek (at least 28
 * bytes). `result` must have capacity for at least `ciphertext_len - 28`
 * bytes. `aad`/`aad_len` must match what was passed at encryption time, or
 * decryption fails with HKDFGUARD_ERR_AUTH_FAILED. On any failure, every
 * byte of the caller's originally-declared `result` capacity is zeroed
 * before returning.
 */
HKDFGUARD_API int32_t hkdfguard_decrypt_with_wrapped_dek(
    const char* service,
    const uint8_t* wrapped_dek, int32_t wrapped_dek_len,
    const uint8_t* ciphertext, int32_t ciphertext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

// Closes the extern "C" block opened above.
#ifdef __cplusplus
}
#endif

// Closes the include guard opened at the top of the file.
#endif /* HKDFGUARD_H */
