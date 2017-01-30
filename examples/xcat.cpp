/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <iostream>
#include <stdexcept>
#include <spcap/spcap.hpp>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: xcat <PATH TO FILE[.xz,.gz]>\n";
        return EXIT_FAILURE;
    }

    try {
        spcap::input_file file(argv[1]);
        char buffer[512];

        while (file) {
            auto sz = file.read(&buffer, sizeof(buffer) - 1);
            buffer[sz] = 0;
            std::cout << buffer;
        }

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
