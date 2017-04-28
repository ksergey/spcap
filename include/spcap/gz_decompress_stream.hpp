/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_gz_decompress_stream_300117184757
#define KSERGEY_gz_decompress_stream_300117184757

#include <streambuf>
#include <istream>
#include <zlib.h>

namespace spcap {
namespace detail {

/* The GZ streambuffer that decompresses data */
class gz_decompress_streambuffer final
    : public std::basic_streambuf< char >
{
private:
    using off_type = std::basic_istream< char >::off_type;

    /* Size of data buffer */
    static constexpr const std::size_t buffer_size{4096};
    /* The stream to read the compressed data from */
    std::basic_istream< char >& input_stream_;
    /* Buffer for compressed data */
    char in_buffer_[buffer_size];
    /* Buffer for uncompressed data */
    char out_buffer_[buffer_size];
    /* ZLIB stream */
    z_stream z_stream_;
    /* The return value for ZLIB */
    int err_;

public:
    /* Creates a streambuffer that reads compressed data from the given stream */
    gz_decompress_streambuffer(std::basic_istream< char >& istr);
    /* Cleans the zlib compressor */
    virtual ~gz_decompress_streambuffer();

protected:
    /* If the input buffer is empty, decompress some more */
    virtual int_type underflow() override;

private:
    std::size_t fill_in_buffer();
    std::size_t unzip_from_stream(char* buf, std::size_t size);
};

} /* namespace detail */

/* A stream that reads compressed data from the underlying stream, and provides the decompressed data */
class gz_decompress_stream final
    : public std::basic_istream< char >
{
private:
    /* The streambuffer responsible for the actual decompression */
    detail::gz_decompress_streambuffer streambuffer_;

public:
    /* Creates a decompression reads compressed dat afrom the given stream, and provides decompressed data */
    explicit gz_decompress_stream(std::basic_istream< char >& istr)
        : basic_istream< char >(&streambuffer_)
        , streambuffer_(istr)
    {}
};

} /* namespace spcap */

#include "gz_decompress_stream.inc"

#endif /* KSERGEY_gz_decompress_stream_300117184757 */
