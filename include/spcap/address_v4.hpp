/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_address_v4_230117145109
#define KSERGEY_address_v4_230117145109

#include <cstdint>
#include <iostream>

namespace spcap {

class address_v4
{
private:
    std::uint32_t addr_{0};
public:
    address_v4() = default;

    explicit address_v4(std::uint32_t addr)
        : addr_(addr)
    {}

    std::uint32_t get() const noexcept
    { return addr_; }

    int octet(std::size_t index) const noexcept
    { return reinterpret_cast< const std::uint8_t* >(&addr_)[index]; }
};

inline std::ostream& operator<<(std::ostream& os, const address_v4& addr)
{
    return os
        << addr.octet(0) << '.'
        << addr.octet(1) << '.'
        << addr.octet(2) << '.'
        << addr.octet(3);
}

} /* namespace spcap */

#endif /* KSERGEY_address_v4_230117145109 */
