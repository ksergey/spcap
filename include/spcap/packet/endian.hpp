/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_endian_280417121439
#define KSERGEY_endian_280417121439

#include <cstdint>
#include <limits>
#include <type_traits>

#if defined( _WIN32 )
#   include <cstdlib>
#   define SPCAP_ENDIAN_LITTLE 1
#   define SPCAP_ENDIAN_BIG 0
#else
#   include <endian.h>
#   define SPCAP_ENDIAN_LITTLE (__BYTE_ORDER == __LITTLE_ENDIAN)
#   define SPCAP_ENDIAN_BIG (__BYTE_ORDER == __BIG_ENDIAN)
#endif

namespace spcap {
namespace packet {
namespace detail {

inline std::uint8_t swap_byte_order(std::uint8_t value) noexcept
{ return value; }

inline std::uint16_t swap_byte_order(std::uint16_t value) noexcept
{
#if defined( _MSC_VER )
    return _byteswap_ushort(value);
#else
    return __builtin_bswap16(value);
#endif
}

inline std::uint32_t swap_byte_order(std::uint32_t value) noexcept
{
#if defined( _MSC_VER )
    return _byteswap_ulong(value);
#else
    return __builtin_bswap32(value);
#endif
}

inline std::uint64_t swap_byte_order(std::uint64_t value) noexcept
{
#if defined( _MSC_VER )
    return _byteswap_uint64(value);
#else
    return __builtin_bswap64(value);
#endif
}

template< typename T >
struct dispatch_helper
{
    static inline T dispatch(T value) noexcept
    { return swap_byte_order(value); }
};

template< std::size_t >
struct dispatcher;
template<>
struct dispatcher< 1 >
    : dispatch_helper< std::uint8_t >
{};
template<>
struct dispatcher< 2 >
    : dispatch_helper< std::uint16_t >
{};
template<>
struct dispatcher< 4 >
    : dispatch_helper< std::uint32_t >
{};
template<>
struct dispatcher< 8 >
    : dispatch_helper< std::uint64_t >
{};

} /* namespace detail */

template< class T >
inline T change_endian(T value) noexcept
{ return detail::dispatcher< sizeof(T) >::dispatch(value); }

#if SPCAP_ENDIAN_LITTLE

template< class T >
inline T host_to_be(T value) noexcept
{ return change_endian(value); }

template< class T >
inline T host_to_le(T value) noexcept
{ return value; }

template< class T >
inline T be_to_host(T value) noexcept
{ return change_endian(value); }

template< class T >
inline T le_to_host(T value) noexcept
{ return value; }

#else

template< class T >
inline T host_to_be(T value) noexcept
{ return value; }

template< class T >
inline T host_to_le(T value) noexcept
{ return change_endian(value); }

template< class T >
inline T be_to_host(T value) noexcept
{ return value; }

template< class T >
inline T le_to_host(T value) noexcept
{ return change_endian(value); }

#endif

} /* namespace packet */
} /* namespace spcap */

#endif /* KSERGEY_endian_280417121439 */
