/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#include <limits>

namespace spcap {
namespace detail {

namespace {
/* Decompression flags */
const std::uint32_t flags = LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED;
/* No memory limit */
const std::uint64_t memory_limit = std::numeric_limits< std::uint64_t >::max();
} /* namespace */

inline xz_decompress_streambuffer::xz_decompress_streambuffer(std::basic_istream< char >& istr)
    : input_stream_{istr}
{
    /* Initialise the stream */
    lzma_stream xz_stream_init = LZMA_STREAM_INIT;
    xz_stream_ = xz_stream_init;

    /* Create the compressor */
    xz_result_ = lzma_stream_decoder(&xz_stream_, memory_limit, flags);
    if (xz_result_ != LZMA_OK) {
        throw std::runtime_error("failed to initialize xz-decoder");
    }

    /* Set buffer pointers */
    setp(0, 0);
    /* The input buffer is empty to begin with */
    setg(out_buffer_, out_buffer_, out_buffer_ + 0);
}

inline xz_decompress_streambuffer::~xz_decompress_streambuffer()
{
    /* Clear the compressor */
    lzma_end(&xz_stream_);
}

inline xz_decompress_streambuffer::int_type xz_decompress_streambuffer::underflow()
{
    /* If everything has been decompressed already, it must be the end of the stream */
    if (output_done_) {
        return traits_type::eof();
    }

    out_length_ = 0;

    /* Run one iteration of decoding until there is something in the buffer */
    while (!output_done_ && out_length_ == 0) {
        if (in_length_ == 0 && !input_done_) {
            /* Attempt to read from the input buffer */
            input_stream_.read(in_buffer_, buffer_size);

            /* Retrieve the number of characters in the buffer */
            in_length_ = input_stream_.gcount();

            /* Set xz input properties */
            xz_stream_.next_in = reinterpret_cast< std::uint8_t* >(in_buffer_);
            xz_stream_.avail_in = in_length_;

            /* If done, finalise the stream (decompress the remaining data), otherwise run with more input */
            input_done_ = input_stream_.eof();
        }
        xz_action_ = input_done_ ? LZMA_FINISH : LZMA_RUN;

        /* Set xz stream properties */
        xz_stream_.next_out = reinterpret_cast< std::uint8_t* >(out_buffer_);
        xz_stream_.avail_out = buffer_size;

        /* Applies the actual decompression */
        xz_result_ = lzma_code(&xz_stream_, xz_action_);

        if ((xz_result_ != LZMA_OK) && (xz_result_ != LZMA_STREAM_END)) {
            throw std::runtime_error("Could not decompress data.");
        } else {
            /* Get how many bytes of the buffer were filled */
            out_length_ = buffer_size - xz_stream_.avail_out;

            /* Set the get pointer */
            setg(out_buffer_, out_buffer_ + 0, out_buffer_ + out_length_);

            /* Update input length, so we know when to fetch new data */
            in_length_ = xz_stream_.avail_in;
        }

        output_done_ = output_done_ || (xz_result_ == LZMA_STREAM_END);
    }

    /* Return the first character of the new buffer, or eof if the stream ends */
    if (out_length_ > 0) {
        return traits_type::to_int_type(out_buffer_[0]);
    }

    return traits_type::eof();
}

} /* namespace detail */
} /* namespace spcap */
