#pragma once

#include "handle_traits.h" // NCRYPT_KEY_HANDLE etc. (via bcrypt.h/ncrypt.h) and Scoped* RAII types
#include "secure_buffer.h" // SecureBuffer<N>
#include "wire_format.h"   // kEphemeralPubLen
#include <cstdint>

namespace hkdfguard {

// Wrap-side key agreement: generates a fresh ephemeral P-256 key pair,
// exports the KEK's public key from `kek_key` (always permitted for ECC
// regardless of export policy), performs ECDH entirely in software (the KEK
// private key/TPM is never touched - only its public part is needed), and
// derives a 32-byte AES wrapping key via HKDF-SHA512. Writes the ephemeral
// public key bytes (64 bytes, raw X||Y) into `ephemeral_pub_out` for
// inclusion in the wrapped payload. The ECDH shared secret and all
// intermediate buffers are destroyed/zeroized before returning.
//
// `SecureBuffer<32>& wrapping_key_out` is an *output parameter passed by
// reference*: rather than this function creating its own SecureBuffer and
// returning it by value, the caller (hkdfguard.cpp) owns the SecureBuffer
// and just hands this function a reference to write the result into. That
// keeps the wrapping key's one-and-only copy under the caller's control, so
// the caller decides exactly how long it stays alive (see hkdfguard.cpp's
// nested `{ ... }` block, scoped as tightly as possible around its use).
void DeriveWrappingKeyForWrap(
    NCRYPT_KEY_HANDLE kek_key,
    uint8_t ephemeral_pub_out[kEphemeralPubLen],
    SecureBuffer<32>& wrapping_key_out);

// Unwrap-side key agreement: imports the payload's ephemeral public key,
// performs ECDH against the persistent KEK's private key (`kek_key`, opened
// on `provider` - this is the step that may execute inside a TPM/vTPM), and
// derives the 32-byte AES wrapping key via HKDF-SHA512 using the same
// construction as the wrap side. The ECDH shared secret and all
// intermediate buffers are destroyed/zeroized before returning.
void DeriveWrappingKeyForUnwrap(
    NCRYPT_PROV_HANDLE provider,
    NCRYPT_KEY_HANDLE kek_key,
    const uint8_t ephemeral_pub[kEphemeralPubLen],
    SecureBuffer<32>& wrapping_key_out);

} // namespace hkdfguard
