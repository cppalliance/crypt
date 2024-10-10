// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_BIT_HPP
#define BOOST_CRYPT_UTILITY_BIT_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/limits.hpp>
#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {
namespace detail {

// Forward decls
template <typename T, typename U, boost::crypt::enable_if_t<boost::crypt::is_unsigned<U>::value, bool> = true>
constexpr T rotl(T x, U s) noexcept;
template <typename T, typename U, boost::crypt::enable_if_t<!boost::crypt::is_unsigned<U>::value, bool> = true>
constexpr T rotl(T x, U s) noexcept;

template <typename T, typename U, boost::crypt::enable_if_t<boost::crypt::is_unsigned<U>::value, bool> = true>
constexpr T rotr(T x, U s) noexcept;
template <typename T, typename U, boost::crypt::enable_if_t<!boost::crypt::is_unsigned<U>::value, bool> = true>
constexpr T rotr(T x, U s) noexcept;

// Only works for unsigned s so we can optimize away the call to rotr
template <typename T, typename U, boost::crypt::enable_if_t<boost::crypt::is_unsigned<U>::value, bool>>
constexpr T rotl(T x, U s) noexcept
{
    constexpr auto N {boost::crypt::numeric_limits<T>::digits};
    const auto r {s % N};

    if (r == 0)
    {
        return x;
    }

    return (x << r) | (x >> (N - r));
}

template <typename T, typename U, boost::crypt::enable_if_t<!boost::crypt::is_unsigned<U>::value, bool>>
constexpr T rotl(T x, U s) noexcept
{
    constexpr auto N {boost::crypt::numeric_limits<T>::digits};
    const auto r {s % N};

    if (r == 0)
    {
        return x;
    }
    else if (r < 0)
    {
        return rotr(x, -r);
    }

    return (x << r) | (x >> (N - r));
}

template <typename T, typename U, boost::crypt::enable_if_t<boost::crypt::is_unsigned<U>::value, bool>>
constexpr T rotr(T x, U s) noexcept
{
    constexpr auto N {boost::crypt::numeric_limits<T>::digits};
    const auto r {s % N};

    if (r == 0)
    {
        return x;
    }

    return (x >> r) | (x << (N - r));
}

template <typename T, typename U, boost::crypt::enable_if_t<!boost::crypt::is_unsigned<U>::value, bool>>
constexpr T rotr(T x, U s) noexcept
{
    constexpr auto N {boost::crypt::numeric_limits<T>::digits};
    const auto r {s % N};

    if (r == 0)
    {
        return x;
    }
    else if (r < 0)
    {
        return rotl(x, -r);
    }

    return (x >> r) | (x << (N - r));
}

constexpr auto swap_endian(const boost::crypt::uint32_t val) -> boost::crypt::uint32_t
{
    return ((val & 0xFF000000) >> 24U) |
           ((val & 0x00FF0000) >> 8U)  |
           ((val & 0x0000FF00) << 8U)  |
           ((val & 0x000000FF) << 24U);
}

} // namespace detail
} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_UTILITY_BIT_HPP
