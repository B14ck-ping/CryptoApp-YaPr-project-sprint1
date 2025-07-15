#include "crypto_guard_ctx.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <iostream>
#include <sstream>
#include <string>

using namespace CryptoGuard;

const std::string testData("Test data for encryption.");
const std::string testDataSHA256Hash("9aa2b2c0d1ed2fa5dea5b3af401e4a9046a02288dd1461865e4329912f1a758d");
const std::string testPwd1("securepassword");
const std::string testPwd2("securepassword2");

TEST(EncryptionTest, EncryptedDataIsNotEmptyTest) {
    std::stringstream input(testData);
    std::stringstream output;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input, output, testPwd1);

    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, testData);
}

TEST(EncryptionTest, DifferentPasswordsGiveDifferentCiphertexts) {
    std::stringstream input1(testData);
    std::stringstream input2(testData);
    std::stringstream output1;
    std::stringstream output2;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input1, output1, std::string(testPwd1));
    cryptoCtx.EncryptFile(input2, output2, std::string(testPwd2));

    EXPECT_NE(output1.str(), output2.str());
}

TEST(EncryptionTest, TestBadOutputStreamThrowsException) {
    std::stringstream input{};
    std::stringstream output;
    output.setstate(std::ios::badbit);

    CryptoGuardCtx cryptoCtx;
    ASSERT_THAT([&]() { cryptoCtx.EncryptFile(input, output, testPwd1); },
                testing::ThrowsMessage<std::runtime_error>(testing::HasSubstr("Output stream error")));
}

TEST(EncryptionTest, TestInputAndOutputStreamsIsEqualThrowsException) {
    std::stringstream input;

    CryptoGuardCtx cryptoCtx;
    ASSERT_THAT([&]() { cryptoCtx.EncryptFile(input, input, testPwd1); },
                ThrowsMessage<std::runtime_error>(testing::HasSubstr("Output and input streams must be different")));
}

TEST(DecryptionTest, TestBadOutputStreamThrowsException) {
    std::stringstream input{};
    std::stringstream output;
    output.setstate(std::ios::badbit);

    CryptoGuardCtx cryptoCtx;
    ASSERT_THAT([&]() { cryptoCtx.DecryptFile(input, output, testPwd1); },
                testing::ThrowsMessage<std::runtime_error>(testing::HasSubstr("Output stream error")));
}

TEST(DecryptionTest, DecryptedDataMatchesOriginalTest) {
    std::stringstream input(testData);
    std::stringstream encryptedOutput;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input, encryptedOutput, testPwd1);

    std::stringstream decryptedInput(encryptedOutput.str());
    std::stringstream decryptedOutput;

    cryptoCtx.DecryptFile(decryptedInput, decryptedOutput, testPwd1);

    EXPECT_EQ(decryptedOutput.str(), testData);
}

TEST(DecryptionTest, DifferentPasswordsThrowException) {
    std::stringstream input(testData);
    std::stringstream encryptedOutput;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input, encryptedOutput, testPwd1);

    std::stringstream decryptedInput(encryptedOutput.str());
    std::stringstream decryptedOutput;

    ASSERT_THAT([&]() { cryptoCtx.DecryptFile(decryptedInput, decryptedOutput, testPwd2); },
                testing::ThrowsMessage<std::runtime_error>(testing::HasSubstr("Cipher final error.")));
}

TEST(DecryptionTest, TestInputAndOutputStreamsIsEqualThrowsException) {
    std::stringstream input{};

    CryptoGuardCtx cryptoCtx;
    ASSERT_THAT(
        [&]() { cryptoCtx.DecryptFile(input, input, testPwd2); },
        testing::ThrowsMessage<std::runtime_error>(testing::HasSubstr("Output and input streams must be different")));
}

TEST(DecryptionTest, DecryptionOfGarbageDataThrows) {
    std::string garbageData = "this is not encrypted";
    std::stringstream input(garbageData);
    std::stringstream output;

    CryptoGuardCtx cryptoCtx;
    ASSERT_THAT([&]() { cryptoCtx.DecryptFile(input, output, testPwd1); },
                testing::ThrowsMessage<std::runtime_error>(testing::HasSubstr("Cipher final error.")));
}
TEST(ChecksumTest, ChecksumIsCorrect) {
    std::stringstream input(testData);
    CryptoGuardCtx cryptoCtx;

    std::string checksum = cryptoCtx.CalculateChecksum(input);
    std::string expectedChecksum(testDataSHA256Hash);
    EXPECT_EQ(checksum, expectedChecksum);  // SHA-256 produces a 64-character hex string
}

TEST(ChecksumTest, ChecksumDataAndDecryptedDataAreEqual) {
    std::stringstream input(testData);
    std::stringstream encryptedOutput;

    CryptoGuardCtx cryptoCtx;
    std::string dataChecksum = cryptoCtx.CalculateChecksum(input);
    input.clear();
    input.seekg(0);

    cryptoCtx.EncryptFile(input, encryptedOutput, testPwd1);

    std::stringstream decryptedInput(encryptedOutput.str());
    std::stringstream decryptedOutput;

    cryptoCtx.DecryptFile(decryptedInput, decryptedOutput, testPwd1);
    std::string decryptedChecksum = cryptoCtx.CalculateChecksum(decryptedOutput);

    EXPECT_EQ(dataChecksum, decryptedChecksum);  // SHA-256 produces a 64-character hex string
}
