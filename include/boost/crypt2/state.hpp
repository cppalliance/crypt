// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_HASHER_STATE_HPP
#define BOOST_CRYPT_HASH_HASHER_STATE_HPP

#include <boost/crypt2/detail/config.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT enum class state
{
    success,                    // no issues
    null,                       // nullptr as parameter
    input_too_long,             // input data too long (exceeded size_t)
    insufficient_entropy,       // Entropy + Nonce length was not at least 3/2 security strength
    out_of_memory,              // Memory exhaustion reported by a function
    requires_reseed,            // The number of cycles has exceeded the specified amount
    uninitialized,              // Random bits can not be provided since the generator is uninitialized
    requested_too_many_bits,    // 2^19 bits is all that's allowed per request
    insufficient_key_length,    // The key is not of proscribed length
    insufficient_output_length, // The output will not fit in the provided container
    incorrect_message_length,   // In non-padded AES modes the message must be a multiple of 128 bits
    state_error                 // added more input after get_digest without re-init
};

} // namespace boost::crypt

#endif // BOOST_CRYPT_HASH_HASHER_STATE_HPP
