#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <vector>

#include "crypto/crypto.hpp"

namespace {

using crypto::u8;

std::mt19937_64& rng() {
    static std::mt19937_64 engine(0xC0FFEEULL);
    return engine;
}

std::vector<u8> random_bytes(size_t n) {
    std::vector<u8> out(n);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : out) {
        b = static_cast<u8>(dist(rng()));
    }
    return out;
}

std::array<u8, 32> random_key() {
    std::array<u8, 32> key{};
    auto bytes = random_bytes(key.size());
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
}

} // namespace

class AesGcmSivTest : public ::testing::Test {
protected:
    std::array<u8, 32> key = random_key();
    std::vector<u8> aad = {'h', 'e', 'a', 'd', 'e', 'r'};
};

TEST_F(AesGcmSivTest, RoundTripBasicMessage) {
    std::vector<u8> plaintext = {'h', 'e', 'l', 'l', 'o'};

    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(AesGcmSivTest, RoundTripEmptyMessage) {
    std::vector<u8> plaintext;

    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    EXPECT_TRUE(encrypted.ciphertext.empty());

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_TRUE(decrypted->empty());
}

TEST_F(AesGcmSivTest, RoundTripEmptyAad) {
    std::vector<u8> plaintext = {'n', 'o', ' ', 'a', 'a', 'd'};
    std::vector<u8> empty_aad;

    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, empty_aad);
    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, empty_aad
    );

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(AesGcmSivTest, RoundTripEmptyMessageWithAad) {
    std::vector<u8> plaintext;

    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_TRUE(decrypted->empty());
}

class AesGcmSivSizeTest : public AesGcmSivTest,
                           public ::testing::WithParamInterface<size_t> {};

TEST_P(AesGcmSivSizeTest, RoundTripVariousSizes) {
    auto plaintext = random_bytes(GetParam());

    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    EXPECT_EQ(encrypted.ciphertext.size(), plaintext.size());

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

INSTANTIATE_TEST_SUITE_P(
    PlaintextSizes,
    AesGcmSivSizeTest,
    ::testing::Values(
        0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 1024, 65536
    )
);

TEST_F(AesGcmSivTest, HandlesLargeMessage) {
    auto plaintext = random_bytes(1 << 20);

    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(AesGcmSivTest, NoncesAreRandomizedAcrossEncryptions) {
    std::vector<u8> plaintext = {'s', 'a', 'm', 'e'};

    auto first = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    auto second = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    EXPECT_NE(first.nonce, second.nonce);
    EXPECT_NE(first.ciphertext, second.ciphertext);
}

TEST_F(AesGcmSivTest, RejectsModifiedFirstByteOfCiphertext) {
    std::vector<u8> plaintext = {'s', 'e', 'c', 'r', 'e', 't', ' ', 'm', 's', 'g'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    ASSERT_FALSE(encrypted.ciphertext.empty());

    auto tampered = encrypted.ciphertext;
    tampered[0] ^= 0x01;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, tampered, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsModifiedLastByteOfCiphertext) {
    std::vector<u8> plaintext = {'s', 'e', 'c', 'r', 'e', 't', ' ', 'm', 's', 'g'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    ASSERT_FALSE(encrypted.ciphertext.empty());

    auto tampered = encrypted.ciphertext;
    tampered.back() ^= 0x01;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, tampered, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsTruncatedCiphertext) {
    auto plaintext = random_bytes(64);
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);
    ASSERT_GT(encrypted.ciphertext.size(), 1u);

    std::vector<u8> truncated(
        encrypted.ciphertext.begin(),
        encrypted.ciphertext.end() - 1
    );

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, truncated, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsExtendedCiphertext) {
    auto plaintext = random_bytes(64);
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto extended = encrypted.ciphertext;
    extended.push_back(0x42);

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, extended, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsEmptyCiphertextForNonEmptyPlaintext) {
    auto plaintext = random_bytes(32);
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    std::vector<u8> empty_ciphertext;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, empty_ciphertext, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsFlippedTagBit) {
    std::vector<u8> plaintext = {'t', 'a', 'g', ' ', 't', 'e', 's', 't'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto tampered_tag = encrypted.tag;
    tampered_tag[0] ^= 0x80;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, tampered_tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsFlippedLastTagBit) {
    std::vector<u8> plaintext = {'t', 'a', 'g', ' ', 't', 'e', 's', 't'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto tampered_tag = encrypted.tag;
    tampered_tag.back() ^= 0x01;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, tampered_tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsZeroedTag) {
    std::vector<u8> plaintext = {'z', 'e', 'r', 'o', ' ', 't', 'a', 'g'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    std::array<u8, 16> zero_tag{};
    ASSERT_NE(zero_tag, encrypted.tag);

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, zero_tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsWrongKey) {
    std::vector<u8> plaintext = {'w', 'r', 'o', 'n', 'g', ' ', 'k', 'e', 'y'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto wrong_key = random_key();
    ASSERT_NE(wrong_key, key);

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        wrong_key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsSingleBitFlippedKey) {
    std::vector<u8> plaintext = {'b', 'i', 't', ' ', 'f', 'l', 'i', 'p'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto almost_right_key = key;
    almost_right_key[31] ^= 0x01;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        almost_right_key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsWrongNonce) {
    std::vector<u8> plaintext = {'w', 'r', 'o', 'n', 'g', ' ', 'n', 'o', 'n', 'c', 'e'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto wrong_nonce = encrypted.nonce;
    wrong_nonce[0] ^= 0x01;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, wrong_nonce, encrypted.ciphertext, encrypted.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsAadMismatch) {
    std::vector<u8> plaintext = {'a', 'a', 'd', ' ', 'c', 'h', 'e', 'c', 'k'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    std::vector<u8> different_aad = {'d', 'i', 'f', 'f', 'e', 'r', 'e', 'n', 't'};

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, different_aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsUnexpectedAadWhenEncryptedWithNone) {
    std::vector<u8> plaintext = {'n', 'o', ' ', 'a', 'a', 'd', ' ', 'h', 'e', 'r', 'e'};
    std::vector<u8> empty_aad;
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, empty_aad);

    std::vector<u8> unexpected_aad = {'u', 'n', 'e', 'x', 'p', 'e', 'c', 't', 'e', 'd'};

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, unexpected_aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsMissingAadWhenEncryptedWithSome) {
    std::vector<u8> plaintext = {'e', 'x', 'p', 'e', 'c', 't', 'e', 'd', ' ', 'a', 'a', 'd'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    std::vector<u8> empty_aad;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, empty_aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsTruncatedAad) {
    std::vector<u8> plaintext = {'a', 'a', 'd', ' ', 't', 'r', 'u', 'n', 'c'};
    std::vector<u8> full_aad = {'f', 'u', 'l', 'l', '-', 'h', 'e', 'a', 'd', 'e', 'r'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, full_aad);

    std::vector<u8> truncated_aad(full_aad.begin(), full_aad.end() - 1);

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, truncated_aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsAadWithSingleFlippedByte) {
    std::vector<u8> plaintext = {'a', 'a', 'd', ' ', 'f', 'l', 'i', 'p'};
    std::vector<u8> original_aad = {'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'};
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, original_aad);

    auto flipped_aad = original_aad;
    flipped_aad[0] ^= 0x01;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, encrypted.ciphertext, encrypted.tag, flipped_aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsCrossMessageTagSwap) {
    auto plaintext_a = random_bytes(16);
    auto plaintext_b = random_bytes(16);

    auto encrypted_a = crypto::aes_256_gcm_siv_encrypt(key, plaintext_a, aad);
    auto encrypted_b = crypto::aes_256_gcm_siv_encrypt(key, plaintext_b, aad);

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted_a.nonce, encrypted_a.ciphertext, encrypted_b.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, RejectsCrossMessageCiphertextWithMatchingTag) {
    auto plaintext_a = random_bytes(32);
    auto plaintext_b = random_bytes(32);

    auto encrypted_a = crypto::aes_256_gcm_siv_encrypt(key, plaintext_a, aad);
    auto encrypted_b = crypto::aes_256_gcm_siv_encrypt(key, plaintext_b, aad);

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted_a.nonce, encrypted_b.ciphertext, encrypted_a.tag, aad
    );

    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmSivTest, DecryptionFailureDoesNotReturnPartialPlaintext) {
    std::vector<u8> plaintext(32, 0xAB);
    auto encrypted = crypto::aes_256_gcm_siv_encrypt(key, plaintext, aad);

    auto tampered = encrypted.ciphertext;
    tampered[0] ^= 0xFF;

    auto decrypted = crypto::aes_256_gcm_siv_decrypt(
        key, encrypted.nonce, tampered, encrypted.tag, aad
    );

    ASSERT_FALSE(decrypted.has_value());
}
