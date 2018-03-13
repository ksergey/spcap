/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_address_v4_230117145109
#define KSERGEY_address_v4_230117145109

#include <cstdint>
#include <iostream>

namespace spcap {

/// IP v4 address
class address_v4 final
{
private:
    std::uint32_t addr_{0};

public:
    constexpr address_v4() = default;

    constexpr address_v4(std::uint32_t addr)
        : addr_(addr)
    {}

    constexpr std::uint32_t get() const noexcept
    {
        return addr_;
    }

    constexpr int octet(std::size_t index) const noexcept
    {
        return reinterpret_cast< const std::uint8_t* >(&addr_)[index];
    }
};

inline std::ostream& operator<<(std::ostream& os, const address_v4& addr)
{
    return os << addr.octet(0) << '.' << addr.octet(1) << '.' << addr.octet(2) << '.' << addr.octet(3);
}

} /* namespace spcap */

#endif /* KSERGEY_address_v4_230117145109 */
