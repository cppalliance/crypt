// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Since our algorithms take both pointers and iterators we need to check the nulls only for the pointers

#ifndef BOOST_CRYPT_UTILITY_NULL_HPP
#define BOOST_CRYPT_UTILITY_NULL_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/type_traits.hpp>

namespace boost {
namespace crypt {
namespace utility {

template <typename ForwardIter, boost::crypt::enable_if_t<boost::crypt::is_pointer_v<ForwardIter>, bool> = true>
BOOST_CRYPT_GPU_ENABLED constexpr auto is_null(ForwardIter iter) noexcept -> bool
{
    return iter == nullptr;
}

template <typename ForwardIter, boost::crypt::enable_if_t<!boost::crypt::is_pointer_v<ForwardIter>, bool> = true>
BOOST_CRYPT_GPU_ENABLED constexpr auto is_null(ForwardIter) noexcept -> bool
{
    return false;
}

} // namespace utility
} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_UTILITY_NULL_HPP
