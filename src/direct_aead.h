#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t

// Direct AES-GCM encrypt/decrypt under a caller-supplied key.
//
// Unlike aes_gcm.h's AesGcmEncrypt/AesGcmDecrypt (which seal a *wrapping
// key* derived internally by ecdh_hkdf.cpp - always exactly 32 bytes, and
// always authenticated with the fixed `service` string as AAD, never
// caller-supplied AAD), the two functions declared here back
// hkdfguard_encrypt/hkdfguard_decrypt in hkdfguard.cpp: they operate on a
// key the *caller* provides directly (typically a DEK already recovered
// via hkdfguard_unwrap_dek), of any of the three AES key sizes, with AAD
// the caller supplies and controls. This project's macOS and Linux
// implementations keep this exact same split (HkdfGuardAesGcm.swift /
// direct_aead.rs, separate from the wrap/unwrap-specific AEAD code), so
// this file mirrors that structure rather than extending aes_gcm.h/.cpp in
// place.
//
// Payload layout - both what hkdfguard_encrypt writes and what
// hkdfguard_decrypt expects to read:
//
//   [12-byte nonce][ciphertext, same length as the plaintext][16-byte tag]

namespace hkdfguard {

constexpr size_t kDirectAeadNonceLen = 12; // AES-GCM's standard 96-bit nonce
constexpr size_t kDirectAeadTagLen = 16;   // AES-GCM's standard 128-bit authentication tag
constexpr size_t kDirectAeadOverhead = kDirectAeadNonceLen + kDirectAeadTagLen; // fixed bytes added around the plaintext/ciphertext by every payload

// Encrypts `plaintext_len` bytes from `plaintext` with AES-GCM under `key`
// (`key_len` bytes - must be 16, 24, or 32, i.e. AES-128/192/256), and
// authenticates `aad_len` bytes of `aad` alongside it without encrypting
// them (`aad` may be null iff `aad_len` is 0). Generates a fresh random
// nonce into `nonce_out` (kDirectAeadNonceLen bytes) and writes the
// ciphertext (same length as the plaintext) into `ciphertext_out` and the
// kDirectAeadTagLen-byte authentication tag into `tag_out`. Throws
// HkdfGuardError on failure.
void DirectAesGcmEncrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, unsigned long plaintext_len,
    const uint8_t* aad, unsigned long aad_len,
    uint8_t nonce_out[kDirectAeadNonceLen],
    uint8_t* ciphertext_out,
    uint8_t tag_out[kDirectAeadTagLen]);

// Decrypts and authenticates `ciphertext_len` bytes from `ciphertext` with
// AES-GCM under `key` (`key_len` bytes - must match the key used to
// encrypt, and be 16, 24, or 32), `nonce` (kDirectAeadNonceLen bytes), and
// `tag` (kDirectAeadTagLen bytes), authenticating `aad_len` bytes of `aad`
// alongside it (`aad` may be null iff `aad_len` is 0, and must match what
// was passed to DirectAesGcmEncrypt or authentication fails). Writes the
// plaintext directly into `plaintext_out`. Throws
// HkdfGuardError(HKDFGUARD_ERR_AUTH_FAILED) if the tag does not verify, or
// HkdfGuardError(HKDFGUARD_ERR_CRYPTO) on any other failure. Callers must
// not trust the contents of `plaintext_out` unless this function returns
// normally - see aes_gcm.h's identical note on AesGcmDecrypt for why
// (BCryptDecrypt can write unauthenticated bytes into the output buffer
// even when it ultimately reports a tag mismatch).
void DirectAesGcmDecrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t nonce[kDirectAeadNonceLen],
    const uint8_t* ciphertext, unsigned long ciphertext_len,
    const uint8_t* aad, unsigned long aad_len,
    const uint8_t tag[kDirectAeadTagLen],
    uint8_t* plaintext_out);

} // namespace hkdfguard
