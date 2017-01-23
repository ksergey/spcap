/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_raw_packet_230117123215
#define KSERGEY_raw_packet_230117123215

#include <cstdint>

namespace spcap {

class raw_packet
{
private:
    std::uint64_t timestamp_{0};
    const char* data_{nullptr};
    std::size_t size_{0};
    std::size_t original_size_{0};

public:
    /* Construct non valid packet */
    raw_packet() = default;

    /* Construct packet */
    raw_packet(std::uint64_t timestamp, const char* data, std::size_t size,
            std::size_t original_size)
        : timestamp_(timestamp)
        , data_(data)
        , size_(size)
        , original_size_(original_size)
    {}

    /* Return true if packet is valid */
    explicit operator bool() const noexcept
    { return data_ != nullptr; }

    /* Return true if packet is not valid */
    bool operator!() const noexcept
    { return data_ == nullptr; }

    /* Return packet receiving time */
    std::uint64_t timestamp() const noexcept
    { return timestamp_; }

    /* Return packet data */
    const char* data() const noexcept
    { return data_; }

    /* Return packet size */
    std::size_t size() const noexcept
    { return size_; }

    /* Return packet original size */
    std::size_t original_size() const noexcept
    { return original_size_; }
};

} /* namespace spcap */

#endif /* KSERGEY_raw_packet_230117123215 */
