// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_BYTE_HPP
#define BOOST_CRYPT_UTILITY_BYTE_HPP

#include <boost/crypt/utility/concepts.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {

class byte
{
private:
    boost::crypt::uint8_t bits_;

public:
    constexpr byte() noexcept : bits_ {} {}
    explicit constexpr byte(boost::crypt::uint8_t bits) noexcept : bits_ {bits} {}

    template <typename IntegerType>
    constexpr auto to_integer() noexcept
        BOOST_CRYPT_REQUIRES(boost::crypt::is_integral_v, IntegerType)
    {
        return static_cast<IntegerType>(bits_);
    }

    template <typename IntegerType>
    constexpr auto operator<<(IntegerType shift) noexcept
        BOOST_CRYPT_REQUIRES_RETURN(boost::crypt::is_integral_v, IntegerType, byte)
    {
        return byte{bits_ << shift};
    }

    template <typename IntegerType>
    constexpr auto operator>>(IntegerType shift) noexcept
        BOOST_CRYPT_REQUIRES_RETURN(boost::crypt::is_integral_v, IntegerType, byte)
    {
        return byte{bits_ >> shift};
    }

    constexpr auto operator|(byte rhs) const noexcept -> byte
    {
        return byte{static_cast<boost::crypt::uint8_t>(bits_ | rhs.bits_)};
    }

    constexpr auto operator&(byte rhs) const noexcept -> byte
    {
        return byte{static_cast<boost::crypt::uint8_t>(bits_ & rhs.bits_)};
    }

    constexpr auto operator^(byte rhs) const noexcept -> byte
    {
        return byte{static_cast<boost::crypt::uint8_t>(bits_ ^ rhs.bits_)};
    }

    constexpr auto operator~() const noexcept -> byte
    {
        return byte{static_cast<boost::crypt::uint8_t>(~bits_)};
    }

    template <typename IntegerType>
    constexpr auto operator<<=(IntegerType shift) noexcept
        BOOST_CRYPT_REQUIRES_RETURN(boost::crypt::is_integral_v, IntegerType, byte&)
    {
        bits_ <<= shift;
        return *this;
    }

    template <typename IntegerType>
    constexpr auto operator >>=(IntegerType shift) noexcept
        BOOST_CRYPT_REQUIRES_RETURN(boost::crypt::is_integral_v, IntegerType, byte&)
    {
        bits_ >>= shift;
        return *this;
    }

    constexpr auto operator|(byte rhs) noexcept -> byte&
    {
        bits_ = static_cast<boost::crypt::uint8_t>(bits_ | rhs.bits_);
        return *this;
    }

    constexpr auto operator&(byte rhs) noexcept -> byte&
    {
        bits_ = static_cast<boost::crypt::uint8_t>(bits_ & rhs.bits_);
        return *this;
    }

    constexpr auto operator^(byte rhs) noexcept -> byte&
    {
        bits_ = static_cast<boost::crypt::uint8_t>(bits_ ^ rhs.bits_);
        return *this;
    }

    constexpr auto operator~() noexcept -> byte&
    {
        bits_ = static_cast<boost::crypt::uint8_t>(~bits_);
        return *this;
    }
};

} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_UTILITY_BYTE_HPP
