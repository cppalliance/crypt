// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CIPHER_MODE_HPP
#define BOOST_CIPHER_MODE_HPP

#include <boost/crypt2/detail/compat.hpp>

namespace boost::crypt {

enum class aes_cipher_mode {
    ecb,        // Electronic Codebook
    ctr,        // Counter
};

template <aes_cipher_mode c>
class aes128;

template <aes_cipher_mode c>
class aes192;

template <aes_cipher_mode c>
class aes256;

} // namespace boost::crypt

#endif //BOOST_CIPHER_MODE_HPP
