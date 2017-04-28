/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <spcap/spcap.hpp>

int main(int argc, char* argv[])
{
    try {
        std::unordered_map< std::string, spcap::file > files;

        for (int i = 1; i < argc; ++i) {
            auto result = files.emplace(std::piecewise_construct,
                    std::forward_as_tuple(argv[i]),
                    std::forward_as_tuple(argv[i]));
            if (!result.second) {
                throw std::runtime_error("File " + std::string(argv[i]) + " already added");
            }

            auto& file = result.first->second;
            file.next();
        }

        std::cout << "Added " << files.size() << " files\n";
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
