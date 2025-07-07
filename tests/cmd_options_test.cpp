#include <../include/cmd_options.h>
#include <gtest/gtest.h>

TEST(ProgramOptions, TestParamsParsing) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt",    "--input", "123.txt",
                          "--output",    "456.txt",   "--password", "123"};
    int argc = 9;

    CryptoGuard::ProgramOptions po;
    po.Parse(argc, const_cast<char **>(argv));

    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(po.GetInputFile(), "123.txt");
    EXPECT_EQ(po.GetOutputFile(), "456.txt");
    EXPECT_EQ(po.GetPassword(), "123");
}

TEST(ProgramOptions, TestUnknownCommand) {
    const char *argv[] = {"CryptoGuard", "--command", "abc"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedEncryptInputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedDecryptInputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "decrypt"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedChecksumInputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "checksum"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedEncryptOutputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt", "--input", "123.txt"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedDecryptOutputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "decrypt", "--input", "123.txt"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedEncryptPassword) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt", "--input", "123.txt", "--output", "456.txt"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}

TEST(ProgramOptions, TestSkippedDecryptPassword) {
    const char *argv[] = {"CryptoGuard", "--command", "decrypt", "--input", "123.txt", "--output", "456.txt"};
    int argc = 3;

    CryptoGuard::ProgramOptions po;
    EXPECT_ANY_THROW(po.Parse(argc, const_cast<char **>(argv)));
}