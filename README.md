# HkdfGuardWin

Windows-native equivalent of a Secure Enclave-backed DEK (Data Encryption Key) wrapper.
Wraps and unwraps a 32-byte key using a persistent, machine-wide scoped, non-exportable
P-256 ECDH Key Encryption Key (KEK) held by a TPM/vTPM via the Microsoft Platform Crypto
Provider, or by the Microsoft Software Key Storage Provider - which one is machine
policy (see "Key storage policy" below); the default prefers the TPM and falls back to
software when no TPM is available (bare servers, VMs without a vTPM, containers).

**Key storage policy**: the `REG_DWORD` value `HKLM\Software\Policies\HkdfGuard\KeyStoragePolicy`
selects the provider: `0` = `PreferTpm` (the default when the value is absent - TPM if
available, otherwise software), `1` = `RequireTpm` (TPM or fail; never falls back),
`2` = `SoftwareOnly`. It is read on every call, so it also governs which provider an
existing KEK is *looked for* on. Under `RequireTpm` a payload that routes to a
software-backed KEK is refused on unwrap as well (`VerifyKeyProperties` demands
hardware backing), so the policy is enforced end to end, not just at creation. A value
that is present but not one of `0`/`1`/`2` (or not a `REG_DWORD`) is a configuration
error and fails every call with `HKDFGUARD_ERR_INVALID_POLICY` - it is deliberately
*not* treated as the default, since a typo'd value most likely intended the stricter
setting. The `PreferTpm` fallback is intentional and administrator-chosen: the
`provider_type` byte in every payload records which provider actually protected it,
so a consumer that needs to know can check.

**Deployment model**: the KEK is created with `NCRYPT_MACHINE_KEY_FLAG`, not tied to
the account that created it, and is meant to be long-lived - there is no key-rotation
mechanism. This is intended for a specific split: a deployment-time utility (running
elevated) calls `hkdfguard_create_kek` once per service, provisioning that service's KEK
if it doesn't already exist (safe to call again on every later deployment - it verifies
rather than re-creating); a separate, lower-privileged service account later calls
`hkdfguard_unwrap_dek` to recover a DEK, without ever needing to create anything itself.
`hkdfguard_wrap_dek` never creates a KEK - it fails with `HKDFGUARD_ERR_KEK_NOT_FOUND` if
`hkdfguard_create_kek` hasn't provisioned one yet; `hkdfguard_kek_exists` lets a caller
check first without side effects. The DEKs actually protected are expected to be re-minted
on every release (bi-weekly/monthly) and wrapped fresh under the same, stable service
name; if a genuinely new KEK is ever wanted, that's done by versioning the *service name*
itself (e.g. `myapp.v2`), not by rotating anything under the existing one.

Creating a KEK for the first time requires the calling process to be elevated -
opening/using an already-created one does not. Who else may use it is machine policy,
not something either the creating tool or a caller chooses: SYSTEM and
`BUILTIN\Administrators` always get full control, and every entry of the `REG_MULTI_SZ`
registry value `HKLM\Software\Policies\HkdfGuard\KeyUseGroups` is granted use (unwrap)
access when the KEK is created - each entry must resolve to a real, host-local group
(this machine's own SAM, `BUILTIN`, `NT AUTHORITY`, or `NT SERVICE`; domain groups are
rejected even on a domain-joined machine, and broad principals like `Everyone` or
`BUILTIN\Users` are refused outright) - see `include/hkdfguard.h` for the exact rules.
This is a deliberate trade-off: any principal an administrator has explicitly listed is
able to use the key, in exchange for wrap and unwrap not needing to be the same account.
If you need per-user isolation instead, that means leaving `NCRYPT_MACHINE_KEY_FLAG`
unset (current-user scope) - not offered as a build option here, since this project
targets the shared-service deployment model above.

The library exposes a small, stable C ABI (`include/hkdfguard.h`) with five functions.
No Windows handle, CNG/NCrypt type, or COM interface crosses that boundary, and no C++
exception ever escapes it - every call returns an integer status code.

```c
int32_t hkdfguard_kek_exists(
    const char* service,
    int32_t* out_exists);

int32_t hkdfguard_create_kek(
    const char* service);

int32_t hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek, int32_t dek_len,
    uint8_t* out, int32_t* out_len);

int32_t hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped, int32_t wrapped_len,
    uint8_t* out, int32_t* out_len);

int32_t hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out, int32_t* out_len);
```

`service` is a null-terminated UTF-8 string (non-empty, at most 128 bytes, ASCII letters/
digits/`.` only) identifying which persistent KEK to use - e.g. an application or tenant
name. It's case-insensitive (normalized to lowercase internally, so `"MyApp"` and
`"myapp"` are the same service everywhere). Different service names get independent,
non-interoperable KEKs; the same service name must be passed to both wrap and unwrap a
given payload, since it is not itself recorded in the wrapped bytes (a SHA-256
fingerprint of the KEK's public key is, though - see the Design section below).

`dek_len` must be exactly 32 (`HKDFGUARD_DEK_LEN`). A wrapped payload is always exactly
164 bytes (`HKDFGUARD_WRAPPED_LEN`) - a fixed size regardless of which KEK provider
produced it - so callers can allocate output buffers without a size-query round trip.
See `include/hkdfguard.h` for the full set of `HKDFGUARD_ERR_*` status codes.

`hkdfguard_generate_and_wrap_dek` generates its own cryptographically random 32-byte DEK
(via `BCryptGenRandom`) and wraps it in one call, for callers minting a brand new
Ephemeral Data Protection Key - the plaintext DEK never crosses back out to the caller;
it's zeroed internally the moment it's wrapped. Recover it later via
`hkdfguard_unwrap_dek` on the resulting payload, with the same `service`.

## Building

Requires CMake 3.20+, a Windows 10/11 SDK, and an MSVC C++17 toolchain (Visual Studio
2022 Build Tools with the "Desktop development with C++" workload, or equivalent).

**Recommended: `scripts\run-build-test-verify.bat`.** Double-click it, or run it from
any shell - it self-elevates (UAC prompt) if not already Administrator, locates the
MSVC/CMake/Ninja toolchain from the Visual Studio Build Tools install, configures,
builds, runs the full `ctest` suite, and does an additional end-to-end check that wraps
a random DEK with the CLI tool and independently unwraps it via a direct call into the
built DLL. Elevation is required up front because both `ctest` (below) and the
end-to-end check create machine-wide KEKs.

Or manually, from an already-elevated shell:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

**`ctest` must run from an elevated (Administrator) shell.** `hkdfguard_create_kek`
creates a machine-wide KEK (`NCRYPT_MACHINE_KEY_FLAG`) the first time a given service
name is used, and that creation step fails outright without elevation - see "Deployment
model" above.

This produces `build/HkdfGuard.Kms.Windows.v1.dll` (+ its `.lib` import library) and
`build/tools/hkdfguard-v1-initialize.exe`, and registers two tests with `ctest`:

- `roundtrip` (`tests/test_roundtrip.cpp`) exercises the public ABI end to end: KEK
  provisioning (`hkdfguard_kek_exists`/`hkdfguard_create_kek`, including that wrap fails
  with `KEK_NOT_FOUND` before a KEK is provisioned), a basic wrap/unwrap roundtrip and
  KEK reuse across repeated calls, case-insensitive service names, the `KeyUseGroups`
  policy (rejecting over-broad/non-local/non-group entries before touching the key
  store), all three `KeyStoragePolicy` values (`RequireTpm`/`SoftwareOnly`/`PreferTpm`,
  forced via an internal test-only seam so this doesn't depend on the machine's real
  registry policy or TPM availability), invalid-argument and buffer-too-small handling,
  that the output buffer is zeroed on every malformed-payload/authentication-failure/
  KEK-mismatch path, and `hkdfguard_generate_and_wrap_dek`.
- `cli` (`tests/test_cli.ps1`) exercises `hkdfguard-v1-initialize.exe`'s own argument
  parsing, validation, and file-handling - including, when elevated, a full
  provision-then-wrap-then-`--force`-overwrite run through the real CLI.

Both tests delete any KEKs they create once they finish, so repeated runs don't
accumulate persisted keys in the machine's key storage.

Run the full suite elevated on a machine with an active TPM to exercise the
`RequireTpm`/`PreferTpm` policy checks against the real TPM-backed ECDH + HKDF path
(`provider_type` resolves to 1, the Platform Crypto Provider) rather than just the
software fallback. The Software Key Storage Provider path (`provider_type` 2) shares the
same code apart from which NCrypt provider name is opened, and is exercised by the same
suite's `SoftwareOnly` policy check regardless of whether a TPM is present.

## Design

- **Crypto**: ephemeral ECDH (P-256) + HKDF-SHA512 + AES-256-GCM, matching the macOS
  Secure Enclave implementation's pattern. See `src/ecdh_hkdf.cpp` for the derivation
  design note - wrap-side and unwrap-side both extract the *raw* ECDH shared secret
  (`BCRYPT_KDF_RAW_SECRET`, works identically via `BCryptDeriveKey` and
  `NCryptDeriveKey`) and then run one shared, self-contained HKDF-SHA512
  implementation, rather than relying on two separately-implemented KDF code paths
  inside BCrypt and NCrypt. The AES-256-GCM step authenticates the normalized `service`
  name followed by a SHA-256 fingerprint of the KEK's public key as additional
  authenticated data (`src/aes_gcm.cpp`'s `AesGcmEncrypt`/`AesGcmDecrypt`, called from
  `src/hkdfguard.cpp`) - binding a wrapped payload to both the exact service and the
  specific KEK it was wrapped under. The fingerprint also travels in the payload and is
  checked against the opened KEK before any ECDH or decryption, so "wrong KEK"
  (`HKDFGUARD_ERR_KEK_MISMATCH`) is distinguishable from tampering
  (`HKDFGUARD_ERR_AUTH_FAILED`). Matches the construction this project's macOS and
  Linux implementations use.
- **Wire format**: `src/wire_format.h` documents the exact 164-byte `WrappedDekV1`
  layout (version, provider type, key id, ephemeral public key, AES-GCM nonce/
  ciphertext/tag, KEK fingerprint), serialized field-by-field rather than via a packed
  C struct so the format has no dependency on compiler struct-packing rules.
- **KEK lifecycle**: `src/kek_store.cpp` creates the KEK (Platform Crypto Provider first,
  falling back to Software KSP under `PreferTpm`) only via `hkdfguard_create_kek`, which
  also applies the `KeyUseGroups`-driven ACL and is idempotent - safe to call again for
  an already-provisioned service, which just re-verifies it. `hkdfguard_wrap_dek` and
  `hkdfguard_unwrap_dek` only ever *open* an existing KEK, never create one; unwrap opens
  the exact provider/key recorded in the payload. Every create/open/delete call passes
  `NCRYPT_MACHINE_KEY_FLAG` (and `NCRYPT_SILENT_FLAG`, so a key with an unexpected
  UI-requiring protection policy fails instead of prompting) - see the Deployment model
  note above. If a `PreferTpm` creation attempt fails after partially succeeding on the
  TPM, any orphaned TPM key is best-effort deleted before the software fallback runs, so
  a later wrap can't silently end up using a key that was never fully verified.
- **Memory security**: `src/secure_buffer.h` (RAII `SecureZeroMemory` wrapper) and
  `src/handle_traits.h` (RAII closers for every NCrypt/BCrypt handle type) ensure key
  material and handles are wiped/closed on every exit path, including exceptions. All
  five ABI entry points in `src/hkdfguard.cpp` catch every exception; `hkdfguard_unwrap_dek`
  additionally zeros the caller's output buffer on any failure (it calls into a CNG
  function - `BCryptDecrypt` - that can write unauthenticated plaintext before reporting
  a tag mismatch).

## Consuming from other languages

This repository only implements the native Windows library and its C ABI. To call it
from C#, Python, Java, Go, or Node, build `HkdfGuard.Kms.Windows.v1.dll` (see
`CMakeLists.txt`'s `OUTPUT_NAME`) and bind to it with the platform's standard FFI
mechanism.

**Load it by its full, known path - never by a bare filename.** Every binding below that
accepts just a name (`"hkdfguard.dll"`, `Native.load("hkdfguard", ...)`, a bare-name
`[DllImport]`, ...) resolves it through the operating system's standard DLL search order,
which - depending on the host process's configuration - can include the current working
directory or other locations a lower-privileged or otherwise unexpected file could
occupy. Since this library exists specifically to protect a Data Encryption Key, a
process that can get a different DLL loaded in its place has effectively compromised
whatever secret the real library would have protected, however carefully the real
library guards it. Resolve the absolute path to the exact copy you built or were given
(next to your application is fine; relying on `PATH` search is not) and load *that*, and
prefer an explicit, non-searching load API over a bare-name one wherever the binding
layer offers one (e.g. .NET's `NativeLibrary.Load(absolutePath)` over a bare-name
`[DllImport]`; `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` over a bare
`LoadLibrary`). For any deployment where the host filesystem isn't already fully
trusted, also sign the shipped DLL (Authenticode) and verify that signature before
loading it.

- **C#**: `[DllImport(@"<absolute-path>\HkdfGuard.Kms.Windows.v1.dll")]`, or (preferred)
  `NativeLibrary.Load(<absolute-path>)` plus `GetExport`/delegates, which never performs
  a name-based search at all
- **Python**: `ctypes.WinDLL(r"<absolute-path>\HkdfGuard.Kms.Windows.v1.dll")`
- **Java**: JNA's `NativeLibrary.getInstance("<absolute-path>")`, or a thin JNI shim that
  calls `LoadLibraryW` with an absolute path
- **Go**: `cgo` linking against `HkdfGuard.Kms.Windows.v1.lib` (resolved at link time, not
  a runtime search - the safest option of all here), or, for dynamic loading,
  `golang.org/x/sys/windows.LoadLibraryEx(absPath, 0,
  LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`
- **Node**: `ffi-napi`/`koffi` given an absolute path, or a native addon (N-API) linking
  `HkdfGuard.Kms.Windows.v1.lib`

All five bindings map directly onto the five exported functions
(`hkdfguard_kek_exists`, `hkdfguard_create_kek`, `hkdfguard_wrap_dek`,
`hkdfguard_unwrap_dek`, `hkdfguard_generate_and_wrap_dek`) and the status codes in
`include/hkdfguard.h`; none of them need to know anything about TPMs, CNG, or NCrypt.

## License

Apache License 2.0 - see [LICENSE](LICENSE).
