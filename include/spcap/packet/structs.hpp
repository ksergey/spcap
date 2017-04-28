/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_structs_280417114919
#define KSERGEY_structs_280417114919

#include "endian.hpp"

namespace spcap {
namespace packet {

static constexpr std::size_t eth_alen = 6;
static constexpr std::uint16_t ethertype_ip = 0x0800;
static constexpr std::uint16_t ethertype_vlan = 0x8100;
static constexpr std::uint8_t ipproto_udp = 17;

#pragma pack(push)
#pragma pack(1)

struct ethernet_header
{
    /** Address size */
    static constexpr std::size_t address_size = 6;

    /** Payloads type */
    enum : std::uint16_t
    {
        ip = 0x0800,
        vlan = 0x8100
    };

    /** Destination mac address */
    std::uint8_t dst_mac[address_size];
    /** Source mac address */
    std::uint8_t src_mac[address_size];
    /** Payload type */
    std::uint16_t payload_type;
};

static_assert( sizeof(ethernet_header) == 14, "" );

struct ip_header
{
    /** Protocols */
    enum : std::uint8_t
    {
        icmp = 1,
        igmp = 2,
        tcp = 6,
        udp = 17
    };

#if SPCAP_ENDIAN_LITTLE
    std::uint8_t ihl:4;
    std::uint8_t version:4;
#else
    std::uint8_t version:4;
    std::uint8_t ihl:4;
#endif
    std::uint8_t tos;
    std::uint16_t tot_len;
    std::uint16_t id;
    std::uint16_t frag_off;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t check;
    std::uint32_t saddr;
    std::uint32_t daddr;
};

static_assert( sizeof(ip_header) == 20, "" );

struct udp_header
{
    std::uint16_t sport;
    std::uint16_t dport;
    std::uint16_t len;
    std::uint16_t check;
};

static_assert( sizeof(udp_header) == 8, "" );

#pragma pack(pop)

} /* namespace packet */
} /* namespace spcap */

#endif /* KSERGEY_structs_280417114919 */
