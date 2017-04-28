/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <iostream>
#include <unordered_map>
#include <stdexcept>
#include <spcap/spcap.hpp>

struct context
{
    std::size_t next_seq{0};
};

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: moex_print <PATH TO PCAP[.xz]>\n";
        return EXIT_FAILURE;
    }

    try {
        spcap::file file(argv[1]);

        std::size_t good_packets_count{0};
        std::size_t bad_packets_count{0};
        std::unordered_map< std::uint64_t, context > ctx;

        while (true) {
            auto packet = file.next();
            if (!packet) {
                break;
            }

            spcap::packet::udp udp{packet};
            if (!udp) {
                bad_packets_count++;
                continue;
            }

            if (packet.size() != packet.original_size()) {
                bad_packets_count++;
                continue;
            }

            std::uint32_t sequence{0};
            if (udp.payload_size() >= sizeof(sequence)) {
                sequence = *reinterpret_cast< const std::uint32_t* >(udp.payload());
            } else {
                bad_packets_count++;
                continue;
            }

            using spcap::address_v4;
            using spcap::timestamp;

            const std::uint64_t stream_id = (udp.dst_port() << 4) | udp.dst_ip();
            auto& c = ctx[stream_id];
            if (c.next_seq != sequence) {
                if (c.next_seq != 0) {
                    std::cout
                        << timestamp{udp.timestamp()} << ' '
                        << address_v4{udp.dst_ip()} << ':' << udp.dst_port() << ' '
                        << "gap, expected " << c.next_seq << " got=" << sequence << '\n';
                }
                c.next_seq = sequence + 1;
            } else {
                c.next_seq++;
            }

            good_packets_count++;
            std::cout
                << timestamp{udp.timestamp()} << ' '
                << address_v4{udp.dst_ip()} << ':' << udp.dst_port() << ' '
                << sequence << '\n';
        }

        std::cout << "DONE, good: " << good_packets_count
            << ", bad: " << bad_packets_count << '\n';

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
