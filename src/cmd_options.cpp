#include "cmd_options.h"
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : command_(ProgramOptions::COMMAND_TYPE::ERROR_TYPE), desc_("Allowed options") {
    desc_.add_options()("help,h", "Help")("command,c", po::value<std::string>()->required(),
                                          "command: encrypt, decrypt, checksum")(
        "input,i", po::value<std::string>()->required(), "path to input file")(
        "output,o", po::value<std::string>(), "path to output string")("password,p", po::value<std::string>(),
                                                                       "password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(const int argc, const char *const *argv) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        return;
    }

    try {
        command_ = commandMapping_.at(vm["command"].as<std::string>());
    } catch (const std::exception &e) {
        throw std::runtime_error("Command is invalid.");
    }

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }

    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }

    if (inputFile_ == outputFile_)
        throw std::runtime_error("Input file and output file must be different!");

    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }

    switch (command_) {
    case ProgramOptions::COMMAND_TYPE::ENCRYPT:
        if (outputFile_.empty())
            throw std::runtime_error("Output file is required for encrypt command!");

        if (password_.empty())
            throw std::runtime_error("Password is required for encrypt command!");
        break;
    case ProgramOptions::COMMAND_TYPE::DECRYPT:
        if (outputFile_.empty())
            throw std::runtime_error("Output file is required for decrypt command!");

        if (password_.empty())
            throw std::runtime_error("Password is required for decrypt command!");
        break;
    case ProgramOptions::COMMAND_TYPE::CHECKSUM:
        if (!outputFile_.empty() || !password_.empty())
            throw std::runtime_error("Unsupported parameters for checksum command.!");
        break;
    default:
        throw std::runtime_error("Command is invalid.");
        break;
    }
}

}  // namespace CryptoGuard
