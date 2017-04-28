/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_udp_230117140236
#define KSERGEY_udp_230117140236

#include "../raw_packet.hpp"
#include "structs.hpp"

namespace spcap {
namespace packet {

class udp
{
private:
    /* UDP packet capturing time */
    std::uint64_t timestamp_{0};
    /* IP header */
    const ip_header * ip_{nullptr};
    /* UDP header */
    const udp_header * udp_{nullptr};
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
        if (p.size() < (offset + sizeof(ethernet_header))) {
            return ;
        }

        /* Read ethernet header */
        const ethernet_header* ether = reinterpret_cast< const ethernet_header* >(p.data() + offset);

        if (be_to_host(ether->payload_type) != ethernet_header::ip) {
            if (be_to_host(ether->payload_type) != ethernet_header::vlan) {
                return ;
            }
            /* Skip wlan header */
            offset += 4;
        }
        offset += sizeof(ethernet_header);

        if (p.size() < (offset + sizeof(ip_header))) {
            return ;
        }
        ip_ = reinterpret_cast< const ip_header* >(p.data() + offset);
        if (ip_->protocol != ip_header::udp) {
            return ;
        }
        offset += sizeof(ip_header);

        if (p.size() < (offset + sizeof(udp_header))) {
            return ;
        }
        udp_ = reinterpret_cast< const udp_header* >(p.data() + offset);
        offset += sizeof(udp_header);

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
    { return be_to_host(udp_->sport); }

    /* Return destination address */
    std::uint32_t dst_ip() const noexcept
    { return ip_->daddr; }

    /* Return destination port */
    std::uint16_t dst_port() const noexcept
    { return be_to_host(udp_->dport); }

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
