// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_HASHER_STATE_HPP
#define BOOST_CRYPT_HASH_HASHER_STATE_HPP

#include <boost/crypt/utility/cstdint.hpp>

namespace boost {
namespace crypt {

enum class hasher_state : boost::crypt::uint8_t
{
    success,            // no issues
    null,               // nullptr as parameter
    input_too_long,     // input data too long (exceeded size_t)
    state_error         // added more input after get_digest without re-init
};

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_HASHER_STATE_HPP
