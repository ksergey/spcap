/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <cstring>

namespace spcap {
namespace detail {

inline gz_decompress_streambuffer::gz_decompress_streambuffer(std::basic_istream< char >& istr)
    : input_stream_{istr}
{
    std::memset(&z_stream_, 0, sizeof(z_stream_));

    err_ = inflateInit2(&z_stream_, MAX_WBITS | 16);

    /* The input buffer is empty to begin with */
    setg(out_buffer_ + 4, out_buffer_ + 4, out_buffer_ + 4);
}

inline gz_decompress_streambuffer::~gz_decompress_streambuffer()
{
    inflateEnd(&z_stream_);
}

inline gz_decompress_streambuffer::int_type gz_decompress_streambuffer::underflow()
{
    if (gptr() && (gptr() < egptr())) {
        return *reinterpret_cast< std::uint8_t* >(gptr());
    }

    int count = int(gptr() - eback());
    if (count > 4) {
        count = 4;
    }
    std::memcpy(out_buffer_ + (4 - count), gptr() - count, count);

    const int size = unzip_from_stream(out_buffer_ + 4, buffer_size - 4);
    if (size <= 0) {
        return traits_type::eof();
    }

    setg(out_buffer_ + (4 - count), out_buffer_ + 4, out_buffer_ + (4 + size));

    return *reinterpret_cast< std::uint8_t* >(gptr());
}

inline std::size_t gz_decompress_streambuffer::fill_in_buffer()
{
    z_stream_.next_in = reinterpret_cast< std::uint8_t* >(in_buffer_);
    input_stream_.read(in_buffer_, buffer_size);
    z_stream_.avail_in = input_stream_.gcount();
    return z_stream_.avail_in;
}

inline std::size_t gz_decompress_streambuffer::unzip_from_stream(char* buf, std::size_t size)
{
    z_stream_.next_out = reinterpret_cast< std::uint8_t* >(buf);
    z_stream_.avail_out = size;
    std::size_t count = z_stream_.avail_in;

    do {
        if (!z_stream_.avail_in) {
            count = fill_in_buffer();
        }
        if (z_stream_.avail_in) {
            err_ = inflate(&z_stream_, Z_SYNC_FLUSH);
        }
    } while (err_ == Z_OK && z_stream_.avail_out && count);

    const std::size_t read_bytes = size - z_stream_.avail_out;

    if (err_ == Z_STREAM_END) {
        if (z_stream_.avail_in) {
            input_stream_.clear(std::ios::goodbit);
            input_stream_.seekg(-off_type(z_stream_.avail_in), std::ios_base::cur);
            z_stream_.avail_in = 0;
        }
    }

    return read_bytes;
}

} /* namespace detail */
} /* namespace spcap */
