#include "cmd_options.h"
#include <iostream>
#include <stdexcept>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : command_(ProgramOptions::COMMAND_TYPE::ERROR_TYPE), desc_("Allowed options") {
    desc_.add_options()("help,h", "Help")("command,c", po::value<std::string>(), "command: encrypt, decrypt, checksum")(
        "input,i", po::value<std::string>(), "path to input file")(
        "output,o", po::value<std::string>(), "path to output string")("password,p", po::value<std::string>(),
                                                                       "password for encryption/decryption");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        return;
    }

    if (vm.count("command")) {
        try {
            command_ = commandMapping_.at(vm["command"].as<std::string>());
        } catch (const std::exception &e) {
            throw std::runtime_error("Command is invalid.");
        }
    } else
        throw std::runtime_error("Parameter command is required!");

    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    } else
        throw std::runtime_error("Input file is required!");

    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    } else if (command_ == ProgramOptions::COMMAND_TYPE::DECRYPT || command_ == ProgramOptions::COMMAND_TYPE::ENCRYPT)
        throw std::runtime_error("Output file is required for encrypt and decrypt command!");

    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    } else if (command_ == ProgramOptions::COMMAND_TYPE::DECRYPT || command_ == ProgramOptions::COMMAND_TYPE::ENCRYPT)
        throw std::runtime_error("password is required for encrypt and decrypt command!");
}

}  // namespace CryptoGuard
