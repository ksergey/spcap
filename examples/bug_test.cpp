/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include "queue.hpp"

int main(int argc, char* argv[])
{
    try {
        examples::priority_queue queue(argc);

        for (int i = 1; i < argc; ++i) {
            queue.add_file(argv[i]);
        }

        while (!queue.empty()) {
            queue.pop();
        }

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
