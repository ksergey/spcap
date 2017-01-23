/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <iostream>
#include <stdexcept>
#include <spcap/spcap.hpp>

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: spcap_print <PATH TO PCAP[.xz]>\n";
        return EXIT_FAILURE;
    }

    try {
        spcap::file file(argv[1]);

        std::size_t good_packets_count{0};
        std::size_t bad_packets_count{0};
        while (true) {
            auto packet = file.next();
            if (__unlikely(!packet)) {
                break;
            }

            spcap::packet::udp udp{packet};
            if (__unlikely(!udp)) {
                bad_packets_count--;
                continue;
            }

            if (__unlikely(packet.size() != packet.original_size())) {
                bad_packets_count--;
                continue;
            }

            good_packets_count++;

            using spcap::address_v4;

            std::cout
                << address_v4{udp.src_ip()} << ':' << udp.src_port() << " -> "
                << address_v4{udp.dst_ip()} << ':' << udp.dst_port() << ' '
                << udp.payload_size() << '\n';
        }

        std::cout << "DONE, good: " << good_packets_count
            << ", bad: " << bad_packets_count << '\n';

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
