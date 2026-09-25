# Security Assumptions

Assumptions have been tested locally, but not well documented publicly by vendor

# Key Blob Import Rejects Malformed Public Key Input

HkdfGuard relies on Windows CNG to validate imported
ECC P-256 public keys.

This assumption was verified experimentally against:

BCryptImportKeyPair(ECCPUBLICBLOB)

using:

valid public keys
all-zero coordinates
all-0xFF coordinates
random coordinates
single-bit mutations of valid public keys
100 fuzzed valid public keys

Observed behavior:

valid points imported successfully
malformed points rejected during import
no malformed mutated point imported successfully

As a result, no additional application-level P-256
point validation is currently performed.