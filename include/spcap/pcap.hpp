/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_pcap_230117111144
#define KSERGEY_pcap_230117111144

#include <cstdint>
#include <net/bpf.h>
#include "compiler.hpp"

namespace spcap {

/* PCAP Global Header */
struct pcap_global_header {
    std::uint32_t magic_number;   /* Magic number */
    std::uint16_t version_major;  /* Major version number */
    std::uint16_t version_minor;  /* Minor version number */
    std::int32_t  thiszone;       /* GMT to local correction */
    std::uint32_t sigfigs;        /* Accuracy of timestamps */
    std::uint32_t snaplen;        /* Max length of captured packets, in octets */
    std::uint32_t network;        /* Data link type */
};

/* Tcpdump PCAP magic number */
static constexpr const std::uint32_t tcpdump_magic = 0xa1b2c3d4;
/* Tcpdump PCAP magic number, nanosecond timestamp precision */
static constexpr const std::uint32_t ns_tcpdump_magic = 0xa1b23c4d;
/* Maximum packet size */
static constexpr const std::uint32_t max_snaplen = 65536 * 4;

/* PCAP Packet Header */
struct pcap_header {
	std::uint32_t ts_sec;         /* Timestamp seconds */
	std::uint32_t ts_usec;        /* Timestamp microseconds (or nanoseconds) */
	std::uint32_t incl_len;       /* Number of octets of packet saved in file */
	std::uint32_t orig_len;       /* Actual length of packet */
};

} /* namespace spcap */

#endif /* KSERGEY_pcap_230117111144 */
