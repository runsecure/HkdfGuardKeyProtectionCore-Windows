#include "direct_aead.h"
#include "errors.h"
#include "handle_traits.h" // ScopedBCryptAlg, ScopedBCryptKey
#include <windows.h>
#include <bcrypt.h>

// See aes_gcm.cpp's identical definition/comment - both files need this
// same NTSTATUS constant, and each defines its own copy behind the same
// `#ifndef` guard rather than sharing a third header, to avoid the
// ntstatus.h conflicts documented there.
#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace hkdfguard {

namespace {

// Same idea as aes_gcm.cpp's (file-private) OpenAesKey, but takes a
// runtime key length (16, 24, or 32 bytes - AES-128/192/256) instead of a
// hardcoded 32: this file backs the generic caller-supplied-key
// encrypt/decrypt functions, not the fixed-32-byte-wrapping-key path
// aes_gcm.cpp serves. CNG's AES implementation needs no separate algorithm
// selection per key size - BCryptGenerateSymmetricKey infers AES-128/192/
// 256 purely from `key_len`, the same way it always has for the 32-byte
// case in aes_gcm.cpp; the only actual difference here is not hardcoding
// that length.
ScopedBCryptKey OpenAesKeyVariable(ScopedBCryptAlg& alg, const uint8_t* key, size_t key_len) {
    NTSTATUS status = BCryptOpenAlgorithmProvider(alg.put(), BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptOpenAlgorithmProvider(AES) failed");
    }

    status = BCryptSetProperty(
        alg.get(), BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptSetProperty(GCM) failed");
    }

    ScopedBCryptKey aes_key;
    status = BCryptGenerateSymmetricKey(
        alg.get(), aes_key.put(), nullptr, 0,
        const_cast<PUCHAR>(key), static_cast<ULONG>(key_len), 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptGenerateSymmetricKey failed");
    }
    return aes_key;
}

} // namespace

void DirectAesGcmEncrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, unsigned long plaintext_len,
    const uint8_t* aad, unsigned long aad_len,
    uint8_t nonce_out[kDirectAeadNonceLen],
    uint8_t* ciphertext_out,
    uint8_t tag_out[kDirectAeadTagLen]) {
    ScopedBCryptAlg alg;
    ScopedBCryptKey aes_key = OpenAesKeyVariable(alg, key, key_len);

    NTSTATUS status = BCryptGenRandom(
        nullptr, nonce_out, static_cast<ULONG>(kDirectAeadNonceLen), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptGenRandom(nonce) failed");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce_out;
    auth_info.cbNonce = static_cast<ULONG>(kDirectAeadNonceLen);
    auth_info.pbTag = tag_out;
    auth_info.cbTag = static_cast<ULONG>(kDirectAeadTagLen);
    // Unlike aes_gcm.cpp's fixed wrap/unwrap use (which never has AAD),
    // this function's callers may supply additional authenticated data -
    // wired straight through to CNG's own pbAuthData/cbAuthData fields,
    // which accept null/0 for "no AAD" just as readily as a real buffer.
    auth_info.pbAuthData = const_cast<PUCHAR>(aad);
    auth_info.cbAuthData = aad_len;

    ULONG result_len = 0;
    status = BCryptEncrypt(
        aes_key.get(), const_cast<PUCHAR>(plaintext), plaintext_len, &auth_info,
        nullptr, 0, ciphertext_out, plaintext_len, &result_len, 0);
    if (!BCRYPT_SUCCESS(status) || result_len != plaintext_len) {
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptEncrypt failed");
    }
    // `alg`/`aes_key` close themselves automatically here as this function
    // returns (see handle_traits.h). The plaintext was read directly from
    // the caller's pointer and never copied into a local buffer.
}

void DirectAesGcmDecrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t nonce[kDirectAeadNonceLen],
    const uint8_t* ciphertext, unsigned long ciphertext_len,
    const uint8_t* aad, unsigned long aad_len,
    const uint8_t tag[kDirectAeadTagLen],
    uint8_t* plaintext_out) {
    ScopedBCryptAlg alg;
    ScopedBCryptKey aes_key = OpenAesKeyVariable(alg, key, key_len);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    // Nonce/tag/AAD are *inputs* CNG reads here, not outputs it writes -
    // const_cast strips the const-ness purely because
    // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO's fields are typed as
    // non-const PUCHAR even for input-only data (see aes_gcm.cpp's
    // identical note on AesGcmDecrypt).
    auth_info.pbNonce = const_cast<PUCHAR>(nonce);
    auth_info.cbNonce = static_cast<ULONG>(kDirectAeadNonceLen);
    auth_info.pbTag = const_cast<PUCHAR>(tag);
    auth_info.cbTag = static_cast<ULONG>(kDirectAeadTagLen);
    auth_info.pbAuthData = const_cast<PUCHAR>(aad);
    auth_info.cbAuthData = aad_len;

    ULONG result_len = 0;
    NTSTATUS status = BCryptDecrypt(
        aes_key.get(), const_cast<PUCHAR>(ciphertext), ciphertext_len, &auth_info,
        nullptr, 0, plaintext_out, ciphertext_len, &result_len, 0);

    // BCryptDecrypt in GCM mode can still write unauthenticated plaintext
    // into plaintext_out even when it reports a tag mismatch - see
    // aes_gcm.cpp's identical note on AesGcmDecrypt. The ABI layer
    // (hkdfguard.cpp's hkdfguard_decrypt) is what actually zeroes the
    // caller's output buffer on any failure; this function's only job is
    // to report the failure correctly.
    if (status == STATUS_AUTH_TAG_MISMATCH) {
        throw HkdfGuardError(HKDFGUARD_ERR_AUTH_FAILED, "AES-GCM authentication failed");
    }
    if (!BCRYPT_SUCCESS(status) || result_len != ciphertext_len) {
        throw HkdfGuardError(HKDFGUARD_ERR_CRYPTO, "BCryptDecrypt failed");
    }
}

} // namespace hkdfguard
