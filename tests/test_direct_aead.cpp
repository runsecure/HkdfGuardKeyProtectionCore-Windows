// Hand-rolled test program (same style as test_roundtrip.cpp - see that
// file's header comment for why: no testing framework dependency, just a
// plain main() that runs checks and reports pass/fail for each). Covers
// hkdfguard_encrypt/hkdfguard_decrypt (direct AES-GCM under a
// caller-supplied key) and hkdfguard_encrypt_with_wrapped_dek/
// hkdfguard_decrypt_with_wrapped_dek (the same, chained onto
// hkdfguard_unwrap_dek).
#include "hkdfguard.h"  // the public ABI under test
#include "kek_store.h"  // DeleteKek, kCurrentKeyId - internal helpers, used only for cleanup below

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <string>

namespace {

int g_failures = 0;

void Check(bool condition, const char* what) {
    if (condition) {
        std::printf("[PASS] %s\n", what);
    } else {
        std::printf("[FAIL] %s\n", what);
        ++g_failures;
    }
}

bool AllZero(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != 0) return false;
    }
    return true;
}

// Fills `buf` with a simple, deterministic, distinct-byte pattern seeded
// by `seed` - like test_roundtrip.cpp's MakeDek, but parameterized so
// different calls (different key sizes, different plaintexts) don't all
// produce identical-looking bytes.
std::vector<uint8_t> MakePattern(size_t len, uint8_t seed) {
    std::vector<uint8_t> buf(len);
    for (size_t i = 0; i < len; ++i) {
        buf[i] = static_cast<uint8_t>(seed + i * 7 + 11);
    }
    return buf;
}

constexpr char kService[] = "hkdfguardwin-test-direct-aead-service";
constexpr wchar_t kServiceWide[] = L"hkdfguardwin-test-direct-aead-service";
constexpr char kServiceOther[] = "hkdfguardwin-test-direct-aead-service-other";

void CleanupKek(const wchar_t* service_wide, uint8_t provider_type, const char* label) {
    try {
        hkdfguard::DeleteKek(std::wstring(service_wide), provider_type, hkdfguard::kCurrentKeyId);
        std::printf("[INFO] cleaned up KEK for %s\n", label);
    } catch (const std::exception& e) {
        std::printf("[WARN] failed to clean up KEK for %s: %s\n", label, e.what());
    }
}

// ---- hkdfguard_encrypt / hkdfguard_decrypt ----

void TestEncryptDecryptRoundTripAllKeySizes() {
    for (int32_t key_len : {16, 24, 32}) {
        std::vector<uint8_t> key = MakePattern(static_cast<size_t>(key_len), 0x42);
        std::vector<uint8_t> key_copy = key; // hkdfguard_encrypt zeroes `key` in place; keep a copy to re-derive the decrypt key from
        std::vector<uint8_t> plaintext = MakePattern(20, 0x10);
        std::vector<uint8_t> aad = MakePattern(8, 0x99);
        std::vector<uint8_t> sealed(plaintext.size() + 28);

        int32_t n = hkdfguard_encrypt(
            key.data(), key_len,
            plaintext.data(), static_cast<int32_t>(plaintext.size()),
            aad.data(), static_cast<int32_t>(aad.size()),
            sealed.data(), static_cast<int32_t>(sealed.size()));
        Check(n == static_cast<int32_t>(sealed.size()), "encrypt returns plaintext_len + 28");
        Check(AllZero(key.data(), key.size()), "encrypt zeroes the key buffer");

        std::vector<uint8_t> recovered(plaintext.size());
        int32_t m = hkdfguard_decrypt(
            key_copy.data(), key_len,
            sealed.data(), static_cast<int32_t>(sealed.size()),
            aad.data(), static_cast<int32_t>(aad.size()),
            recovered.data(), static_cast<int32_t>(recovered.size()));
        Check(m == static_cast<int32_t>(plaintext.size()), "decrypt returns the original plaintext length");
        Check(recovered == plaintext, "decrypt recovers the original plaintext");
        Check(AllZero(key_copy.data(), key_copy.size()), "decrypt zeroes the key buffer");
    }
}

void TestEncryptDecryptEmptyPlaintextAndNoAad() {
    std::vector<uint8_t> key = MakePattern(32, 0x11);
    std::vector<uint8_t> sealed(28); // just nonce + tag

    int32_t n = hkdfguard_encrypt(
        key.data(), 32,
        nullptr, 0, // plaintext_len == 0, so a null plaintext pointer is legitimate
        nullptr, 0, // aad_len == 0, so a null aad pointer is legitimate
        sealed.data(), static_cast<int32_t>(sealed.size()));
    Check(n == 28, "encrypt of empty plaintext with no AAD produces a 28-byte payload");

    std::vector<uint8_t> key2 = MakePattern(32, 0x11);
    int32_t m = hkdfguard_decrypt(
        key2.data(), 32,
        sealed.data(), static_cast<int32_t>(sealed.size()),
        nullptr, 0,
        nullptr, 0); // result_len == 0 (empty plaintext), so a null result pointer is legitimate
    Check(m == 0, "decrypt of an empty-plaintext payload returns 0");
}

void TestEncryptRejectsInvalidKeyLengthWithoutZeroing() {
    std::vector<uint8_t> key(20, 0xAA); // not 16, 24, or 32
    std::vector<uint8_t> key_before = key;
    std::vector<uint8_t> plaintext = MakePattern(4, 0x22);
    std::vector<uint8_t> result(32);

    int32_t rc = hkdfguard_encrypt(
        key.data(), 20,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "encrypt rejects an invalid key_len");
    Check(key == key_before, "key buffer is untouched when key_len itself is invalid");
}

void TestEncryptZeroesKeyEvenWhenLaterArgumentInvalid() {
    std::vector<uint8_t> key = MakePattern(32, 0x55);
    std::vector<uint8_t> result(4);

    // plaintext_len > 0 but the pointer is null - invalid, but only after
    // key_len has already passed validation.
    int32_t rc = hkdfguard_encrypt(
        key.data(), 32,
        nullptr, 5,
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "encrypt rejects a null plaintext with plaintext_len > 0");
    Check(AllZero(key.data(), key.size()), "key is still zeroed once key_len validated, even on a later failure");
}

void TestEncryptBufferTooSmall() {
    std::vector<uint8_t> key = MakePattern(32, 0x66);
    std::vector<uint8_t> plaintext = MakePattern(12, 0x33);
    std::vector<uint8_t> tiny(4, 0xFF);

    int32_t rc = hkdfguard_encrypt(
        key.data(), 32,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        tiny.data(), static_cast<int32_t>(tiny.size()));
    Check(rc == HKDFGUARD_ERR_BUFFER_TOO_SMALL, "encrypt rejects a too-small result buffer");
    Check(tiny == std::vector<uint8_t>(4, 0xFF), "encrypt must not write on BUFFER_TOO_SMALL");
}

void TestDecryptRejectsInvalidKeyLength() {
    std::vector<uint8_t> key(20, 0);
    std::vector<uint8_t> ciphertext(28, 0);
    std::vector<uint8_t> result(8);
    int32_t rc = hkdfguard_decrypt(
        key.data(), 20,
        ciphertext.data(), static_cast<int32_t>(ciphertext.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "decrypt rejects an invalid key_len");
}

void TestDecryptRejectsTooShortCiphertext() {
    std::vector<uint8_t> key = MakePattern(32, 0x77);
    std::vector<uint8_t> too_short(27, 0); // one byte short of the 28-byte nonce+tag overhead
    std::vector<uint8_t> result(8);
    int32_t rc = hkdfguard_decrypt(
        key.data(), 32,
        too_short.data(), static_cast<int32_t>(too_short.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "decrypt rejects a ciphertext shorter than the fixed overhead");
}

void TestDecryptWrongKeyFailsAuthenticationAndZeroesResult() {
    std::vector<uint8_t> key = MakePattern(32, 0x11);
    std::vector<uint8_t> plaintext = MakePattern(14, 0x44);
    std::vector<uint8_t> sealed(plaintext.size() + 28);
    hkdfguard_encrypt(
        key.data(), 32,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        sealed.data(), static_cast<int32_t>(sealed.size()));

    std::vector<uint8_t> wrong_key = MakePattern(32, 0x22);
    std::vector<uint8_t> result(plaintext.size(), 0xAA);
    int32_t rc = hkdfguard_decrypt(
        wrong_key.data(), 32,
        sealed.data(), static_cast<int32_t>(sealed.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_AUTH_FAILED, "decrypt with the wrong key fails authentication");
    Check(AllZero(result.data(), result.size()), "result is zeroed after an authentication failure");
}

void TestDecryptTamperedCiphertextFailsAuthentication() {
    std::vector<uint8_t> key = MakePattern(32, 0x33);
    std::vector<uint8_t> plaintext = MakePattern(9, 0x55);
    std::vector<uint8_t> sealed(plaintext.size() + 28);
    hkdfguard_encrypt(
        key.data(), 32,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        sealed.data(), static_cast<int32_t>(sealed.size()));
    sealed.back() ^= 0xFF; // flip a bit in the tag

    std::vector<uint8_t> key2 = MakePattern(32, 0x33);
    std::vector<uint8_t> result(plaintext.size());
    int32_t rc = hkdfguard_decrypt(
        key2.data(), 32,
        sealed.data(), static_cast<int32_t>(sealed.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_AUTH_FAILED, "decrypt rejects a tampered ciphertext/tag");
}

void TestDecryptWrongAadFailsAuthentication() {
    std::vector<uint8_t> key = MakePattern(32, 0x44);
    std::vector<uint8_t> plaintext = MakePattern(10, 0x66);
    std::vector<uint8_t> aad = MakePattern(6, 0x77);
    std::vector<uint8_t> sealed(plaintext.size() + 28);
    hkdfguard_encrypt(
        key.data(), 32,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        aad.data(), static_cast<int32_t>(aad.size()),
        sealed.data(), static_cast<int32_t>(sealed.size()));

    std::vector<uint8_t> key2 = MakePattern(32, 0x44);
    std::vector<uint8_t> wrong_aad = MakePattern(6, 0x88);
    std::vector<uint8_t> result(plaintext.size());
    int32_t rc = hkdfguard_decrypt(
        key2.data(), 32,
        sealed.data(), static_cast<int32_t>(sealed.size()),
        wrong_aad.data(), static_cast<int32_t>(wrong_aad.size()),
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_AUTH_FAILED, "decrypt with mismatched AAD fails authentication");
}

void TestSamePlaintextEncryptedTwiceYieldsDifferentCiphertexts() {
    std::vector<uint8_t> key_a = MakePattern(32, 0x99);
    std::vector<uint8_t> key_b = MakePattern(32, 0x99);
    std::vector<uint8_t> plaintext = MakePattern(16, 0xAB);
    std::vector<uint8_t> sealed_a(plaintext.size() + 28);
    std::vector<uint8_t> sealed_b(plaintext.size() + 28);
    hkdfguard_encrypt(key_a.data(), 32, plaintext.data(), static_cast<int32_t>(plaintext.size()), nullptr, 0, sealed_a.data(), static_cast<int32_t>(sealed_a.size()));
    hkdfguard_encrypt(key_b.data(), 32, plaintext.data(), static_cast<int32_t>(plaintext.size()), nullptr, 0, sealed_b.data(), static_cast<int32_t>(sealed_b.size()));
    Check(sealed_a != sealed_b, "the same plaintext encrypted twice yields different ciphertexts (random nonce)");
}

void TestNullPointerEdgeCases() {
    std::vector<uint8_t> plaintext = MakePattern(4, 0x11);
    std::vector<uint8_t> result(32);

    int32_t rc = hkdfguard_encrypt(
        nullptr, 32, // valid key_len, so the null check on the pointer itself is what's under test
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "encrypt rejects a null key pointer");

    std::vector<uint8_t> key = MakePattern(32, 0x22);
    rc = hkdfguard_encrypt(
        key.data(), 32,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 5, // aad_len > 0 but the pointer is null
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "encrypt rejects a null aad pointer when aad_len > 0");

    std::vector<uint8_t> key2 = MakePattern(32, 0x33);
    rc = hkdfguard_encrypt(
        key2.data(), 32,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        nullptr, 9999); // capacity claims room, but there's nowhere to write
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "encrypt rejects a null result pointer with nonzero capacity");

    std::vector<uint8_t> key3 = MakePattern(32, 0x44);
    std::vector<uint8_t> decrypt_result(8);
    rc = hkdfguard_decrypt(
        key3.data(), 32,
        nullptr, 28, // claims a valid length, but the pointer itself is null
        nullptr, 0,
        decrypt_result.data(), static_cast<int32_t>(decrypt_result.size()));
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "decrypt rejects a null ciphertext pointer");

    std::vector<uint8_t> key4 = MakePattern(32, 0x55);
    std::vector<uint8_t> nonempty_plaintext = MakePattern(8, 0x66);
    std::vector<uint8_t> sealed(nonempty_plaintext.size() + 28);
    hkdfguard_encrypt(key4.data(), 32, nonempty_plaintext.data(), static_cast<int32_t>(nonempty_plaintext.size()), nullptr, 0, sealed.data(), static_cast<int32_t>(sealed.size()));
    std::vector<uint8_t> key5 = MakePattern(32, 0x55);
    rc = hkdfguard_decrypt(
        key5.data(), 32,
        sealed.data(), static_cast<int32_t>(sealed.size()),
        nullptr, 0,
        nullptr, 9999); // plaintext_len > 0 here, so unlike the empty-plaintext case a null result is invalid
    Check(rc == HKDFGUARD_ERR_INVALID_ARG, "decrypt rejects a null result pointer when the recovered plaintext is nonempty");
}

// ---- hkdfguard_encrypt_with_wrapped_dek / hkdfguard_decrypt_with_wrapped_dek ----

void TestWrappedDekEncryptDecryptRoundTrip(uint8_t& out_provider_type) {
    std::vector<uint8_t> dek(HKDFGUARD_DEK_LEN);
    for (int i = 0; i < HKDFGUARD_DEK_LEN; ++i) dek[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 3 + 5);

    std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_len = static_cast<int32_t>(wrapped.size());
    int32_t rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrapped_len);
    Check(rc == HKDFGUARD_OK, "wrap (for the wrapped-DEK chained tests) succeeds");
    out_provider_type = wrapped[1];

    std::vector<uint8_t> plaintext = MakePattern(24, 0xCC);
    std::vector<uint8_t> aad = MakePattern(5, 0xDD);
    std::vector<uint8_t> sealed(plaintext.size() + 28);
    int32_t n = hkdfguard_encrypt_with_wrapped_dek(
        kService, wrapped.data(), wrapped_len,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        aad.data(), static_cast<int32_t>(aad.size()),
        sealed.data(), static_cast<int32_t>(sealed.size()));
    Check(n == static_cast<int32_t>(sealed.size()), "encrypt_with_wrapped_dek returns plaintext_len + 28");

    std::vector<uint8_t> recovered(plaintext.size());
    int32_t m = hkdfguard_decrypt_with_wrapped_dek(
        kService, wrapped.data(), wrapped_len,
        sealed.data(), static_cast<int32_t>(sealed.size()),
        aad.data(), static_cast<int32_t>(aad.size()),
        recovered.data(), static_cast<int32_t>(recovered.size()));
    Check(m == static_cast<int32_t>(plaintext.size()), "decrypt_with_wrapped_dek returns the original plaintext length");
    Check(recovered == plaintext, "decrypt_with_wrapped_dek recovers the original plaintext");
}

void TestWrappedDekEncryptWrongServiceFailsAtUnwrapStage() {
    std::vector<uint8_t> dek(HKDFGUARD_DEK_LEN, 0x21);
    std::vector<uint8_t> wrapped(HKDFGUARD_WRAPPED_LEN);
    int32_t wrapped_len = static_cast<int32_t>(wrapped.size());
    int32_t rc = hkdfguard_wrap_dek(kService, dek.data(), static_cast<int32_t>(dek.size()), wrapped.data(), &wrapped_len);
    Check(rc == HKDFGUARD_OK, "wrap (for the wrong-service chained test) succeeds");

    std::vector<uint8_t> plaintext = MakePattern(4, 0xEE);
    std::vector<uint8_t> sealed(plaintext.size() + 28, 0);
    rc = hkdfguard_encrypt_with_wrapped_dek(
        kServiceOther, // deliberately wrong service
        wrapped.data(), wrapped_len,
        plaintext.data(), static_cast<int32_t>(plaintext.size()),
        nullptr, 0,
        sealed.data(), static_cast<int32_t>(sealed.size()));
    Check(rc == HKDFGUARD_ERR_PROVIDER || rc == HKDFGUARD_ERR_AUTH_FAILED,
          "encrypt_with_wrapped_dek with the wrong service fails at the unwrap stage");
    Check(AllZero(sealed.data(), sealed.size()), "nothing written when unwrap fails first");
}

void TestWrappedDekDecryptMalformedWrappedDekFailsAtUnwrapStage() {
    std::vector<uint8_t> garbage(8, 0); // not a valid wrapped payload at all
    std::vector<uint8_t> ciphertext(28, 0); // syntactically valid-length AEAD payload, irrelevant since unwrap fails first
    std::vector<uint8_t> result(8);
    int32_t rc = hkdfguard_decrypt_with_wrapped_dek(
        kService,
        garbage.data(), static_cast<int32_t>(garbage.size()),
        ciphertext.data(), static_cast<int32_t>(ciphertext.size()),
        nullptr, 0,
        result.data(), static_cast<int32_t>(result.size()));
    Check(rc == HKDFGUARD_ERR_MALFORMED, "decrypt_with_wrapped_dek rejects a malformed wrapped_dek at the unwrap stage");
}

} // namespace

int main() {
    TestEncryptDecryptRoundTripAllKeySizes();
    TestEncryptDecryptEmptyPlaintextAndNoAad();
    TestEncryptRejectsInvalidKeyLengthWithoutZeroing();
    TestEncryptZeroesKeyEvenWhenLaterArgumentInvalid();
    TestEncryptBufferTooSmall();
    TestDecryptRejectsInvalidKeyLength();
    TestDecryptRejectsTooShortCiphertext();
    TestDecryptWrongKeyFailsAuthenticationAndZeroesResult();
    TestDecryptTamperedCiphertextFailsAuthentication();
    TestDecryptWrongAadFailsAuthentication();
    TestSamePlaintextEncryptedTwiceYieldsDifferentCiphertexts();
    TestNullPointerEdgeCases();

    uint8_t provider_type = 0;
    TestWrappedDekEncryptDecryptRoundTrip(provider_type);
    TestWrappedDekEncryptWrongServiceFailsAtUnwrapStage();
    TestWrappedDekDecryptMalformedWrappedDekFailsAtUnwrapStage();

    // ---- Cleanup. ----
    CleanupKek(kServiceWide, provider_type, "direct-aead primary test service");

    if (g_failures == 0) {
        std::printf("\nAll checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
