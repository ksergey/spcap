/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_xz_decompress_stream_230117103258
#define KSERGEY_xz_decompress_stream_230117103258

#include <cstdint>
#include <streambuf>
#include <istream>
#include <lzma.h>

namespace spcap {
namespace detail {

/* The XZ streambuffer that decompresses data */
class xz_decompress_streambuffer final
    : public std::basic_streambuf< char >
{
private:
    /* The size of the temporary buffers for decommpression (4 kiB) */
    static constexpr const std::size_t buffer_size{4096};
    /* The stream to read the compressed data from */
    std::basic_istream< char >& input_stream_;
    /* Buffer for compressed data */
    char in_buffer_[buffer_size];
    /* Buffer for uncompressed data */
    char out_buffer_[buffer_size];
    /* Number of bytes of the input buffer that are used */
    std::size_t in_length_{0};
    /* Number of bytes of the output buffer that are used */
    std::size_t out_length_{0};
    /* Whether an eof is encountered on the input stream */
    bool input_done_{false};
    /* Whether all output has been read */
    bool output_done_{false};
    /* The return value for XZ */
    lzma_ret xz_result_;
    /* What the decompressor should do */
    lzma_action xz_action_;
    /* The actual decompressor */
    lzma_stream xz_stream_;

public:
    /* Creates a streambuffer that reads compressed data from the given stream */
    explicit xz_decompress_streambuffer(std::basic_istream< char >& istr);
    /* Cleans the lzma compressor */
    virtual ~xz_decompress_streambuffer();

protected:
    /* If the input buffer is empty, decompress some more */
    virtual int_type underflow() override;
};

} /* namespace detail */

/* A stream that reads compressed data from the underlying stream, and provides the decompressed data */
class xz_decompress_stream final
    : public std::basic_istream< char >
{
private:
    /* The streambuffer responsible for the actual decompression */
    detail::xz_decompress_streambuffer streambuffer_;

public:
    /* Creates a decompression reads compressed dat afrom the given stream, and provides decompressed data */
    explicit xz_decompress_stream(std::basic_istream< char >& istr)
        : basic_istream< char >(&streambuffer_)
        , streambuffer_(istr)
    {}
};

} /* namespace spcap */

#include "xz_decompress_stream.inc"

#endif /* KSERGEY_xz_decompress_stream_230117103258 */
