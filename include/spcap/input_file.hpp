/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_input_file_230117110913
#define KSERGEY_input_file_230117110913

#include <fstream>
#include <string>
#include <type_traits>
#include "xz_decompress_stream.hpp"
#include "gz_decompress_stream.hpp"
#include "utils.hpp"
#include "compiler.hpp"

namespace spcap {

/* File reader */
class input_file final
{
private:
    std::ifstream raw_stream_;
    std::istream* decoded_stream_{nullptr};

public:
    input_file()
        : decoded_stream_(&raw_stream_)
    {}

    explicit input_file(const std::string& filename)
    {
        raw_stream_.open(filename.c_str(), std::ios::in | std::ios::binary);
        if (!raw_stream_) {
            throw std::runtime_error("Failed to open file \"" + filename + '"');
        }

        if (ends_with(filename, ".xz")) {
            decoded_stream_ = new xz_decompress_stream(raw_stream_);
        } else if (ends_with(filename, ".gz")) {
            decoded_stream_ = new gz_decompress_stream(raw_stream_);
        } else {
            decoded_stream_ = &raw_stream_;
        }
    }

    ~input_file()
    {
        if (decoded_stream_ != &raw_stream_) {
            delete decoded_stream_;
        }
    }

    bool eof() const noexcept
    { return decoded_stream_->eof(); }

    explicit operator bool() const noexcept
    { return decoded_stream_->operator bool(); }

    bool operator!() const noexcept
    { return decoded_stream_->operator!(); }

    std::size_t read(void* s, std::size_t count)
    { return decoded_stream_->read(reinterpret_cast< char* >(s), count).gcount(); }
};

} /* namespace spcap */

#endif /* KSERGEY_input_file_230117110913 */
