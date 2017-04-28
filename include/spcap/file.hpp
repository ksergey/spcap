/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_file_230117112348
#define KSERGEY_file_230117112348

#include <vector>
#include "pcap.hpp"
#include "input_file.hpp"
#include "raw_packet.hpp"

namespace spcap {

/* Packet file reader */
class file
{
private:
    /* Nanonseconds in second */
    static constexpr const std::uint64_t nsecs_in_sec = 1000000000ul;
    /* Nanoseconds in microsecond */
    static constexpr const std::uint64_t nsecs_in_usec = 1000ul;
    /* File path */
    const std::string path_;
    /* Input file */
    input_file input_;
    /* Timestamp precision flag */
    bool upscale_precision_{false};
    /* Timestamp correction */
    std::uint64_t timestamp_correction_{0};
    /* Buffer for new packets */
    std::vector< char > buffer_;

public:
    explicit file(const std::string& path)
        : path_(path)
        , input_(path)
    { read_header(); }

    /* Return file path */
    const std::string& path() const
    { return path_; }

    /* Return true if timestamp will be scaled to nanoseconds */
    bool upscale_timestamps() const
    { return upscale_precision_; }

    /* Return true if end of file reached */
    bool eof() const noexcept
    { return input_.eof(); }

    /* Read next packet */
    raw_packet next()
    {
        using namespace std::string_literals;

        pcap_header header;
        std::size_t count = input_.read(&header, sizeof(header));
        if (count != sizeof(header)) {
            if (count > 0) {
                throw std::runtime_error("Read "s + std::to_string(count) + " of "s
                        + std::to_string(sizeof(header)) + " bytes of PCAP header");
            }
            return raw_packet{};
        }

        if (header.incl_len > buffer_.size()) {
            throw std::runtime_error("Not enought buffer size for reading packet");
        }

        /* Read packet data */
        count = input_.read(buffer_.data(), header.incl_len);
        if (count != header.incl_len) {
            throw std::runtime_error("Read "s + std::to_string(count) + " of "s
                    + std::to_string(header.incl_len) + " bytes of PCAP packet");
        }

        /* Calculate packet timestamp */
        std::uint64_t timestamp = header.ts_sec * nsecs_in_sec + timestamp_correction_;
        if (upscale_precision_) {
            timestamp += header.ts_usec * nsecs_in_usec;
        } else {
            timestamp += header.ts_usec;
        }

        return raw_packet{timestamp, buffer_.data(), header.incl_len, header.orig_len};
    }

private:
    /* Read PCAP global header */
    void read_header()
    {
        using namespace std::string_literals;

        pcap_global_header header;
        auto count = input_.read(&header, sizeof(header));
        if (count != sizeof(header)) {
            throw std::runtime_error("Failed to read PCAP global header");
        }

        if (header.magic_number == tcpdump_magic) {
            upscale_precision_ = true;
        } else if (header.magic_number == ns_tcpdump_magic) {
            upscale_precision_ = false;
        } else {
            throw std::runtime_error("Unknown PCAP type in file "s + path_);
        }

        if (header.network != network_ethernet) {
            throw std::runtime_error("Network "s + std::to_string(header.network)
                    + " not supported (only Ethernet supported)"s);
        }

        if (header.snaplen > max_snaplen) {
            throw std::runtime_error("Invalid file capture length ("s
                    + std::to_string(header.snaplen) + ")"s);
        }

        /* Initialize buffer */
        buffer_.resize(header.snaplen);

        timestamp_correction_ = header.thiszone * nsecs_in_sec;
    }
};

} /* namespace spcap */

#endif /* KSERGEY_file_230117112348 */
