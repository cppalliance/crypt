// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_STRLEN_HPP
#define BOOST_CRYPT_UTILITY_STRLEN_HPP

#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {
namespace utility {

template <typename ForwardIter>
constexpr auto strlen(ForwardIter str) noexcept -> boost::crypt::size_t
{
    boost::crypt::size_t len {};
    while (*(str + len) != static_cast<decltype(*str)>('\0'))
    {
        ++len;
    }

    return len;
}

} // namespace utility
} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_UTILITY_STRLEN_HPP
