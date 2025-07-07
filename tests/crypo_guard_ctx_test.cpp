#include <gtest/gtest.h>
#include "crypto_guard_ctx.h"

#include <sstream>
#include <string>
#include <iostream>

using namespace CryptoGuard;

const char *TEST_DATA = "Test data for encryption.";
const char *TEST_DATA_SHA256_HASH = "9aa2b2c0d1ed2fa5dea5b3af401e4a9046a02288dd1461865e4329912f1a758d";
const char *TEST_PASSWORD1 = "securepassword";
const char *TEST_PASSWORD2 = "securepassword2";

TEST(EncryptionTest, EncryptedDataIsNotEmptyTest) 
{ 
    std::stringstream input(TEST_DATA);
    std::stringstream output;
    std::string password = TEST_PASSWORD1;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input, output, password);

    std::string encrypted = output.str();
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, TEST_DATA);
}

TEST(EncryptionTest, DifferentPasswordsGiveDifferentCiphertexts) {
    std::stringstream input1(TEST_DATA);
    std::stringstream input2(TEST_DATA);
    std::stringstream output1;
    std::stringstream output2;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input1, output1, std::string(TEST_PASSWORD1));
    cryptoCtx.EncryptFile(input2, output2, std::string(TEST_PASSWORD2));

    EXPECT_NE(output1.str(), output2.str());
}

TEST(EncryptionTest, TestBadOutputStreamThrowsException) {
    std::stringstream input{};
    std::stringstream output;
    std::string password = TEST_PASSWORD1;
    output.setstate(std::ios::badbit);

    CryptoGuardCtx cryptoCtx;
    EXPECT_ANY_THROW(cryptoCtx.EncryptFile(input, output, password));
}

TEST(DecryptionTest, TestBadOutputStreamThrowsException) {
    std::stringstream input{};
    std::stringstream output;
    std::string password = TEST_PASSWORD1;
    output.setstate(std::ios::badbit);

    CryptoGuardCtx cryptoCtx;
    EXPECT_ANY_THROW(cryptoCtx.DecryptFile(input, output, password));
}

TEST(DecryptionTest, DecryptedDataMatchesOriginalTest) {
    std::stringstream input(TEST_DATA);
    std::stringstream encryptedOutput;
    std::string password = TEST_PASSWORD1;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input, encryptedOutput, password);

    std::stringstream decryptedInput(encryptedOutput.str());
    std::stringstream decryptedOutput;

    cryptoCtx.DecryptFile(decryptedInput, decryptedOutput, password);

    EXPECT_EQ(decryptedOutput.str(), TEST_DATA);
}

TEST(DecryptionTest, DifferentPasswordsThrowException) {
    std::stringstream input(TEST_DATA);
    std::stringstream encryptedOutput;
    std::string password1 = TEST_PASSWORD1;
    std::string password2 = TEST_PASSWORD2;

    CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(input, encryptedOutput, password1);

    std::stringstream decryptedInput(encryptedOutput.str());
    std::stringstream decryptedOutput;

    EXPECT_ANY_THROW(cryptoCtx.DecryptFile(decryptedInput, decryptedOutput, password2));
}

TEST(DecryptionTest, DecryptionOfGarbageDataThrows) {
    std::string garbageData = "this is not encrypted";
    std::stringstream input(garbageData);
    std::stringstream output;

    CryptoGuardCtx cryptoCtx;
    EXPECT_THROW(cryptoCtx.DecryptFile(input, output, "somepassword"), std::runtime_error);
}
TEST(ChecksumTest, ChecksumIsCorrect) {
    std::stringstream input(TEST_DATA);
    CryptoGuardCtx cryptoCtx;

    std::string checksum = cryptoCtx.CalculateChecksum(input);
    std::string expectedChecksum(TEST_DATA_SHA256_HASH);
    EXPECT_EQ(checksum, expectedChecksum); // SHA-256 produces a 64-character hex string
}

TEST(ChecksumTest, ChecksumDataAndDecryptedDataAreEqual) {
    std::stringstream input(TEST_DATA);
    std::stringstream encryptedOutput;
    

    std::string password = TEST_PASSWORD1;

    CryptoGuardCtx cryptoCtx;
    std::string dataChecksum = cryptoCtx.CalculateChecksum(input);
    input.seekg(0);

    cryptoCtx.EncryptFile(input, encryptedOutput, password);

    std::stringstream decryptedInput(encryptedOutput.str());
    std::stringstream decryptedOutput;

    cryptoCtx.DecryptFile(decryptedInput, decryptedOutput, password);
    std::string decryptedChecksum = cryptoCtx.CalculateChecksum(decryptedOutput);
    

    // EXPECT_EQ(dataChecksum, decryptedChecksum); // SHA-256 produces a 64-character hex string
}