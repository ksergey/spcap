/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_timestamp_230117150005
#define KSERGEY_timestamp_230117150005

#include <cstdint>
#include <ctime>
#include <iostream>
#include <iomanip>

#if defined( _WIN32 )
#   define localtime_r(x, y) localtime_s(y, x)
#   define gmtime_r(x, y) gmtime_s(y, x)
#endif /* defined( _WIN32 ) */

namespace spcap {

class timestamp final
{
private:
    struct tm tm_{};
    unsigned nsecs_{0};

public:
    timestamp() = default;

    explicit timestamp(std::uint64_t value, bool utc = true)
        : nsecs_(value % 1000000000lu)
    {
        time_t time(value / 1000000000lu);
        if (utc) {
            gmtime_r(&time, &tm_);
        } else {
            localtime_r(&time, &tm_);
        }
    }

    const struct tm& tm() const noexcept
    {
        return tm_;
    }

    unsigned nsecs() const noexcept
    {
        return nsecs_;
    }
};

inline std::ostream& operator<<(std::ostream& os, const timestamp& t)
{
    const auto& tm = t.tm();

    std::ios::fmtflags flags(os.flags());
    os << std::setfill('0') << std::setw(4) << (tm.tm_year + 1900) << '-';
    os << std::setfill('0') << std::setw(2) << (tm.tm_mon + 1) << '-';
    os << std::setfill('0') << std::setw(2) << tm.tm_mday << ' ';
    os << std::setfill('0') << std::setw(2) << tm.tm_hour << ':';
    os << std::setfill('0') << std::setw(2) << tm.tm_min << ':';
    os << std::setfill('0') << std::setw(2) << tm.tm_sec << '.';
    os << std::setfill('0') << std::setw(9) << t.nsecs();
    os.flags(flags);

    return os;
}

} /* namespace spcap */

#endif /* KSERGEY_timestamp_230117150005 */
