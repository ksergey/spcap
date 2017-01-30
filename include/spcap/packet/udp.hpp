/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_udp_230117140236
#define KSERGEY_udp_230117140236

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "../raw_packet.hpp"

namespace spcap {
namespace packet {

class udp
{
private:
    /* UDP packet capturing time */
    std::uint64_t timestamp_{0};
    /* IP header */
    const struct iphdr* ip_{nullptr};
    /* UDP header */
    const struct udphdr* udp_{nullptr};
    /* UDP payload data */
    const char* payload_{nullptr};
    /* UDP payload size */
    std::size_t payload_size_{0};

public:
    /* Default constructor */
    udp() = default;

    /* Construct from raw packet */
    explicit udp(const raw_packet& p)
    {
        std::size_t offset = 0;
        if (__unlikely(p.size() < (offset + sizeof(ether_header)))) {
            return ;
        }
        /* Read ethernet header */
        const struct ether_header* ether = reinterpret_cast< const struct ether_header* >(p.data() + offset);

        if (ntohs(ether->ether_type) != ETHERTYPE_IP) {
            if (ntohs(ether->ether_type) != ETHERTYPE_VLAN) {
                return ;
            }
            /* Skip wlan header */
            offset += 4;
        }
        offset += sizeof(struct ether_header);

        if (__unlikely(p.size() < (offset + sizeof(struct iphdr)))) {
            return ;
        }
        ip_ = reinterpret_cast< const struct iphdr* >(p.data() + offset);
        if (__unlikely(ip_->protocol != IPPROTO_UDP)) {
            return ;
        }
        offset += sizeof(struct iphdr);

        if (__unlikely(p.size() < (offset + sizeof(struct udphdr)))) {
            return ;
        }
        udp_ = reinterpret_cast< const struct udphdr* >(p.data() + offset);
        offset += sizeof(udphdr);

        timestamp_ = p.timestamp();
        payload_ = p.data() + offset;
        payload_size_ += p.size() - offset;
    }

    /* Return true if packet valid */
    explicit operator bool() const noexcept
    { return udp_ != nullptr; }

    /* Return true if packet not valid */
    bool operator!() const noexcept
    { return udp_ == nullptr; }

    /* Return source address */
    std::uint32_t src_ip() const noexcept
    { return ip_->saddr; }

    /* Return source port */
    std::uint16_t src_port() const noexcept
    { return ntohs(udp_->source); }

    /* Return destination address */
    std::uint32_t dst_ip() const noexcept
    { return ip_->daddr; }

    /* Return destination port */
    std::uint16_t dst_port() const noexcept
    { return ntohs(udp_->dest); }

    /* Return UDP packet capturing time */
    std::uint64_t timestamp() const noexcept
    { return timestamp_; }

    /* Return UDP packet payload */
    const char* payload() const noexcept
    { return payload_; }

    /* Return UDP packet payload size */
    const std::size_t payload_size() const noexcept
    { return payload_size_; }
};

} /* namespace packet */
} /* namespace spcap */

#endif /* KSERGEY_udp_230117140236 */
