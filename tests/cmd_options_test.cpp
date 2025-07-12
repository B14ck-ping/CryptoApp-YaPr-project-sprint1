#include <../include/cmd_options.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

TEST(ProgramOptions, TestParamsParsing) {
    static constexpr std::array args = {"CryptoGuard", "--command", "encrypt",    "--input", "123.txt",
                          "--output",    "456.txt",   "--password", "123"};

    CryptoGuard::ProgramOptions po;
    po.Parse(static_cast<int>(args.size()), args.data());

    EXPECT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(po.GetInputFile(), "123.txt");
    EXPECT_EQ(po.GetOutputFile(), "456.txt");
    EXPECT_EQ(po.GetPassword(), "123");
}

TEST(ProgramOptions, TestInputIsRequired) {
    static constexpr std::array args = {"CryptoGuard", "--command", "abc"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<boost::wrapexcept<boost::program_options::required_option>>(
                testing::HasSubstr("the option '--input' is required but missing")));
}

TEST(ProgramOptions, TestUnknownCommand) {
    static constexpr std::array args = {"CryptoGuard", "--command", "abc", "--input", "1.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Command is invalid.")));
}

TEST(ProgramOptions, TestSkippedEncryptOutputFile) {
    static constexpr std::array args = {"CryptoGuard", "--command", "encrypt", "--input", "123.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Output file is required for encrypt command!")));
}

TEST(ProgramOptions, TestSkippedDecryptOutputFile) {
    static constexpr std::array args = {"CryptoGuard", "--command", "decrypt", "--input", "123.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Output file is required for decrypt command!")));
}

TEST(ProgramOptions, TestSkippedEncryptPassword) {
    static constexpr std::array args = {"CryptoGuard", "--command", "encrypt", "--input", "123.txt", "--output", "456.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Password is required for encrypt command!")));
}

TEST(ProgramOptions, TestSkippedDecryptPassword) {
    static constexpr std::array args = {"CryptoGuard", "--command", "decrypt", "--input", "123.txt", "--output", "456.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Password is required for decrypt command!")));
}

TEST(ProgramOptions, InputAndOutputFilesAreSamePassword) {
    static constexpr std::array args = {"CryptoGuard", "--command", "decrypt", "--input", "123.txt", "--output", "123.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Input file and output file must be different!")));
}

TEST(ProgramOptions, CheckSumUnsupportedCmd) {
    static constexpr std::array args = {"CryptoGuard", "--command", "checksum", "--input", "123.txt", "--output", "123.txt"};

    CryptoGuard::ProgramOptions po;
    ASSERT_THAT(
        [&]() {po.Parse(static_cast<int>(args.size()), args.data());},
            testing::ThrowsMessage<std::runtime_error>(
                testing::HasSubstr("Input file and output file must be different!")));
}