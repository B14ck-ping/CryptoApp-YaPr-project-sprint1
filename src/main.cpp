#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <iostream>
#include <fstream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::ifstream inStream(options.GetInputFile(), std::ios::binary);
        std::ofstream outStream(options.GetOutputFile(), std::ios::binary);

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            if (!inStream) throw std::runtime_error("Cannot open input file");
            if (!outStream) throw std::runtime_error("Cannot open output file");
            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            if (!inStream) throw std::runtime_error("Cannot open input file");
            if (!outStream) throw std::runtime_error("Cannot open output file");
            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            if (!inStream) throw std::runtime_error("Cannot open input file"); 
            std::string checksum = cryptoCtx.CalculateChecksum(inStream);
            std::print("Checksum: {}\n", checksum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}