/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_utils_230117105111
#define KSERGEY_utils_230117105111

#include <string>

namespace spcap {

/* Checks if the given string ends with the given substring */
inline bool ends_with(const std::string& str, const std::string& tail)
{
    return str.size() >= tail.size() && str.compare(str.size() - tail.size(), tail.size(), tail) == 0;
}

} /* namespace spcap */

#endif /* KSERGEY_utils_230117105111 */
