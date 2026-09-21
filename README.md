# HkdfGuardWin

Windows-native equivalent of a Secure Enclave-backed DEK (Data Encryption Key) wrapper.
Wraps and unwraps a 32-byte key using a persistent, machine-wide scoped, non-exportable
P-256 ECDH Key Encryption Key (KEK), preferring a TPM/vTPM via the Microsoft Platform
Crypto Provider and falling back automatically to the Microsoft Software Key Storage
Provider when no TPM is available (bare servers, VMs without a vTPM, containers).

**Deployment model**: the KEK is created with `NCRYPT_MACHINE_KEY_FLAG`, not tied to
the account that created it. This is intended for a specific split: a deployment-time
utility (running elevated) calls `hkdfguard_wrap_dek` once per service, which creates
the KEK on first use; a separate, lower-privileged service account later calls
`hkdfguard_unwrap_dek` to recover the DEK, without ever needing to create anything
itself. Creating the KEK for the first time requires the calling process to be
elevated - opening/using an already-created one does not, subject to the key's ACL
(left at NCrypt's own default for a machine key; tighten it further via Group Policy
or `NCryptSetProperty`/`NCRYPT_SECURITY_DESCR_PROPERTY` if you need to restrict which
accounts can use a given service's KEK). This is a deliberate trade-off: every local
account that can reach the key is able to use it, in exchange for wrap and unwrap not
needing to be the same account. If you need per-user isolation instead, that means
leaving `NCRYPT_MACHINE_KEY_FLAG` unset (current-user scope) - not offered as a build
option here, since this project targets the shared-service deployment model above.

The library exposes a small, stable C ABI (`include/hkdfguard.h`) with six functions.
No Windows handle, CNG/NCrypt type, or COM interface crosses that boundary, and no C++
exception ever escapes it - every call returns an integer status code.

```c
int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int32_t dek_len,
    uint8_t* out, int32_t* out_len);

int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int32_t wrapped_len,
    uint8_t* out, int32_t* out_len);
```

`service` is a null-terminated UTF-8 string (non-empty, at most 128 bytes) identifying
which persistent KEK to use - e.g. an application or tenant name. Different service names
get independent, non-interoperable KEKs; the same service name must be passed to both
wrap and unwrap a given payload, since it is not itself recorded in the wrapped bytes.

`dek_len` must be exactly 32 (`HKDFGUARD_DEK_LEN`). A wrapped payload is always exactly
132 bytes (`HKDFGUARD_WRAPPED_LEN`) - a fixed size regardless of which KEK provider
produced it - so callers can allocate output buffers without a size-query round trip.
See `include/hkdfguard.h` for the full set of `HKDFGUARD_ERR_*` status codes.

### Encrypting/decrypting data, not just the DEK

Four more functions (`src/direct_aead.h`/`.cpp` for the crypto, wired up as ABI entry
points in `src/hkdfguard.cpp`) cover the next step: actually using a DEK to protect
data, not just wrapping the DEK itself.

```c
int32_t hkdfguard_encrypt(
    uint8_t* key, int32_t key_len,
    const uint8_t* plaintext, int32_t plaintext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

int32_t hkdfguard_decrypt(
    uint8_t* key, int32_t key_len,
    const uint8_t* ciphertext, int32_t ciphertext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

int32_t hkdfguard_encrypt_with_wrapped_dek(
    const char* service,
    const uint8_t* wrapped_dek, int32_t wrapped_dek_len,
    const uint8_t* plaintext, int32_t plaintext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);

int32_t hkdfguard_decrypt_with_wrapped_dek(
    const char* service,
    const uint8_t* wrapped_dek, int32_t wrapped_dek_len,
    const uint8_t* ciphertext, int32_t ciphertext_len,
    const uint8_t* aad, int32_t aad_len,
    uint8_t* result, int32_t result_len);
```

`hkdfguard_encrypt`/`hkdfguard_decrypt` run AES-GCM directly under a caller-supplied
key (`key_len` must be 16, 24, or 32 - AES-128/192/256), producing/consuming a
`nonce || ciphertext || tag` payload (12-byte nonce, 16-byte tag - a fixed 28-byte
overhead around the plaintext). The `_with_wrapped_dek` variants combine that with an
`hkdfguard_unwrap_dek` call, so a caller holding only a *wrapped* DEK and a `service`
string can do both in one call - the raw DEK never crosses back out to the caller in
that path, and never leaves the DLL's process memory beyond the duration of that one
call.

These four use a different return convention than `hkdfguard_wrap_dek`/
`hkdfguard_unwrap_dek` above: no `out_len` in/out parameter - a non-negative return is
the number of bytes written to `result`, a negative return is one of the
`HKDFGUARD_ERR_*` codes. `key` is not `const` in `hkdfguard_encrypt`/`hkdfguard_decrypt`:
both zero it in place before returning, on every exit path except an invalid `key_len`.
This mirrors the equivalent four functions in this project's macOS implementation
function-for-function, including the wire payload layout. See the comment block above
each declaration in `include/hkdfguard.h` for the exact contract, including a
Windows-specific note on `hkdfguard_decrypt`: because the underlying `BCryptDecrypt`
call can write unauthenticated plaintext into `result` even when it ultimately fails,
`result` is zeroed on *any* decrypt failure - not just when something was actually
written - the same policy `hkdfguard_unwrap_dek` already uses for the same reason.

## Building

Requires CMake 3.20+, a Windows 10/11 SDK, and an MSVC C++17 toolchain (Visual Studio
2022 Build Tools with the "Desktop development with C++" workload, or equivalent).

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

**Run `ctest` from an elevated (Administrator) shell.** Both test executables wrap a
DEK, which creates a machine-wide KEK (`NCRYPT_MACHINE_KEY_FLAG`) on first use - see
"Deployment model" above - and that creation step fails outright without elevation.
This is a change from before this KEK became machine-scoped, when tests ran fine
un-elevated.

This produces `build/hkdfguard.dll` (+ `hkdfguard.lib` import library) and runs two
test executables via `ctest`:

- `test_roundtrip` exercises: a basic wrap/unwrap roundtrip, KEK reuse across
  repeated calls, invalid-argument and buffer-too-small handling, that the output
  buffer is zeroed on malformed-payload / authentication-failure paths, and that
  different `service` names get independent KEKs (a payload wrapped under one
  service cannot be unwrapped under another).
- `test_direct_aead` exercises `hkdfguard_encrypt`/`hkdfguard_decrypt`/
  `hkdfguard_encrypt_with_wrapped_dek`/`hkdfguard_decrypt_with_wrapped_dek`: a
  round trip at all three AES key sizes (128/192/256), empty-plaintext and
  no-AAD edge cases, that the key buffer is zeroed on every success/failure path
  (except an invalid `key_len` itself), buffer-too-small handling, wrong-key/
  tampered-ciphertext/wrong-AAD authentication failures (with `result` zeroed
  afterward), null-pointer/negative-length argument validation, and the
  wrapped-DEK chained functions' round trip plus their unwrap-stage failure
  paths.

Both test executables delete any KEKs they create once they finish (via an
internal, non-ABI helper in `kek_store.cpp`), so repeated runs don't accumulate
persisted keys in the user's key storage.

The test suite was run on a machine with an active TPM (`provider_type` resolves to 1,
the Platform Crypto Provider), which exercises the full TPM-backed ECDH + HKDF path.
The Software Key Storage Provider fallback path (`provider_type` 2) shares the same
code apart from which NCrypt provider name is opened, but has not been separately
exercised on a TPM-less machine (e.g. a container or a VM without a vTPM) - worth
verifying there before relying on it in production.

## Design

- **Crypto**: ephemeral ECDH (P-256) + HKDF-SHA512 + AES-256-GCM, matching the macOS
  Secure Enclave implementation's pattern. See `src/ecdh_hkdf.cpp` for the derivation
  design note - wrap-side and unwrap-side both extract the *raw* ECDH shared secret
  (`BCRYPT_KDF_RAW_SECRET`, works identically via `BCryptDeriveKey` and
  `NCryptDeriveKey`) and then run one shared, self-contained HKDF-SHA512
  implementation, rather than relying on two separately-implemented KDF code paths
  inside BCrypt and NCrypt. The AES-256-GCM step authenticates the caller's `service`
  string as additional authenticated data (`src/aes_gcm.cpp`'s `AesGcmEncrypt`/
  `AesGcmDecrypt`, called from `src/hkdfguard.cpp`) - binding a wrapped payload to the
  exact service it was wrapped for, matching this project's macOS and Linux
  implementations, which use the identical AAD for the identical reason.
- **Wire format**: `src/wire_format.h` documents the exact 132-byte `WrappedDekV1`
  layout (version, provider type, key id, ephemeral public key, AES-GCM nonce/
  ciphertext/tag), serialized field-by-field rather than via a packed C struct so the
  format has no dependency on compiler struct-packing rules.
- **KEK lifecycle**: `src/kek_store.cpp` resolves/creates the KEK (Platform Crypto
  Provider first, falling back to Software KSP) at wrap time, and opens the exact
  provider/key recorded in a payload (never creating) at unwrap time. Every
  create/open/delete call passes `NCRYPT_MACHINE_KEY_FLAG` - see the Deployment model
  note above.
- **Memory security**: `src/secure_buffer.h` (RAII `SecureZeroMemory` wrapper) and
  `src/handle_traits.h` (RAII closers for every NCrypt/BCrypt handle type) ensure key
  material and handles are wiped/closed on every exit path, including exceptions. All
  six ABI entry points in `src/hkdfguard.cpp` catch every exception; `hkdfguard_unwrap_dek`
  and `hkdfguard_decrypt` additionally zero the caller's output buffer on any failure
  (both call into CNG functions - `BCryptDecrypt` - that can write unauthenticated
  plaintext before reporting a tag mismatch), and `hkdfguard_encrypt`/`hkdfguard_decrypt`
  zero the caller's key buffer on every exit path via a small RAII guard
  (`KeyZeroGuard` in `src/hkdfguard.cpp`) once `key_len` has been validated.
- **Direct AEAD**: `src/direct_aead.h`/`.cpp` implements AES-GCM encrypt/decrypt under
  a caller-supplied key of any of the three standard sizes (128/192/256), with optional
  additional authenticated data - kept separate from `src/aes_gcm.h`/`.cpp` (which only
  ever seals a fixed 32-byte wrapping key with no AAD) rather than extending it in
  place, matching the same separation this project's macOS and Linux implementations
  use.

## Consuming from other languages

This repository only implements the native Windows library and its C ABI. To call it
from C#, Python, Java, Go, or Node, build `hkdfguard.dll` and bind to it with the
platform's standard FFI mechanism, e.g.:

- **C#**: `[DllImport("hkdfguard.dll")]` (P/Invoke)
- **Python**: `ctypes.WinDLL("hkdfguard.dll")`
- **Java**: JNA (`Native.load("hkdfguard", ...)`) or a thin JNI shim
- **Go**: `cgo` linking against `hkdfguard.lib`, or `syscall`/`golang.org/x/sys/windows`
  dynamic loading
- **Node**: `ffi-napi`/`koffi`, or a native addon (N-API) linking `hkdfguard.lib`

All five bindings map directly onto the six exported functions and the status codes in
`include/hkdfguard.h`; none of them need to know anything about TPMs, CNG, or NCrypt.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
