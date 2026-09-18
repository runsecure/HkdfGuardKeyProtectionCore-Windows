# HkdfGuardWin

Windows-native equivalent of a Secure Enclave-backed DEK (Data Encryption Key) wrapper.
Wraps and unwraps a 32-byte key using a persistent, current-user-scoped, non-exportable
P-256 ECDH Key Encryption Key (KEK), preferring a TPM/vTPM via the Microsoft Platform
Crypto Provider and falling back automatically to the Microsoft Software Key Storage
Provider when no TPM is available (bare servers, VMs without a vTPM, containers).

The library exposes a small, stable C ABI (`include/hkdfguard.h`) with two functions.
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

## Building

Requires CMake 3.20+, a Windows 10/11 SDK, and an MSVC C++17 toolchain (Visual Studio
2022 Build Tools with the "Desktop development with C++" workload, or equivalent).

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

This produces `build/hkdfguard.dll` (+ `hkdfguard.lib` import library) and runs
`test_roundtrip`, which exercises: a basic wrap/unwrap roundtrip, KEK reuse across
repeated calls, invalid-argument and buffer-too-small handling, that the output buffer
is zeroed on malformed-payload / authentication-failure paths, and that different
`service` names get independent KEKs (a payload wrapped under one service cannot be
unwrapped under another). `test_roundtrip` deletes any KEKs it creates once it
finishes (via an internal, non-ABI helper in `kek_store.cpp`), so repeated runs don't
accumulate persisted keys in the user's key storage.

The test suite was run on a machine with an active TPM (`provider_type` resolves to 1,
the Platform Crypto Provider), which exercises the full TPM-backed ECDH + HKDF path.
The Software Key Storage Provider fallback path (`provider_type` 2) shares the same
code apart from which NCrypt provider name is opened, but has not been separately
exercised on a TPM-less machine (e.g. a container or a VM without a vTPM) - worth
verifying there before relying on it in production.

## Design

- **Crypto**: ephemeral ECDH (P-256) + HKDF-SHA256 + AES-256-GCM, matching the macOS
  Secure Enclave implementation's pattern. See `src/ecdh_hkdf.cpp` for the derivation
  design note - wrap-side and unwrap-side both extract the *raw* ECDH shared secret
  (`BCRYPT_KDF_RAW_SECRET`, works identically via `BCryptDeriveKey` and
  `NCryptDeriveKey`) and then run one shared, self-contained HKDF-SHA256
  implementation, rather than relying on two separately-implemented KDF code paths
  inside BCrypt and NCrypt.
- **Wire format**: `src/wire_format.h` documents the exact 132-byte `WrappedDekV1`
  layout (version, provider type, key id, ephemeral public key, AES-GCM nonce/
  ciphertext/tag), serialized field-by-field rather than via a packed C struct so the
  format has no dependency on compiler struct-packing rules.
- **KEK lifecycle**: `src/kek_store.cpp` resolves/creates the KEK (Platform Crypto
  Provider first, falling back to Software KSP) at wrap time, and opens the exact
  provider/key recorded in a payload (never creating) at unwrap time.
- **Memory security**: `src/secure_buffer.h` (RAII `SecureZeroMemory` wrapper) and
  `src/handle_traits.h` (RAII closers for every NCrypt/BCrypt handle type) ensure key
  material and handles are wiped/closed on every exit path, including exceptions. Both
  ABI entry points in `src/hkdfguard.cpp` catch every exception and, on any unwrap
  failure, zero the caller's output buffer before returning.

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

All five bindings map directly onto the two exported functions and the status codes in
`include/hkdfguard.h`; none of them need to know anything about TPMs, CNG, or NCrypt.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
