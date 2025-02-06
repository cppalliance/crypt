// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DRBG_SHA3_256_DRBG_HPP
#define BOOST_CRYPT2_DRBG_SHA3_256_DRBG_HPP

#include <boost/crypt2/drbg/detail/hash_drbg.hpp>
#include <boost/crypt2/drbg/detail/hmac_drbg.hpp>
#include <boost/crypt2/mac/hmac.hpp>
#include <boost/crypt2/hash/sha3_256.hpp>

namespace boost::crypt {

namespace drbg_detail {

template <bool prediction_resistance>
using sha3_256_hash_drbg_t = hash_drbg<sha3_256_hasher, 256U, 256U, prediction_resistance>;

template <bool prediction_resistance>
using sha3_256_hmac_drbg_t = hmac_drbg<hmac<sha3_256_hasher>, 256U, 256U, prediction_resistance>;

} // namespace drbg_detail

BOOST_CRYPT_EXPORT using sha3_256_hash_drbg = drbg_detail::sha3_256_hash_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha3_256_hash_drbg_pr = drbg_detail::sha3_256_hash_drbg_t<true>;

BOOST_CRYPT_EXPORT using sha3_256_hmac_drbg = drbg_detail::sha3_256_hmac_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha3_256_hmac_drbg_pr = drbg_detail::sha3_256_hmac_drbg_t<true>;

} // namespace boost::crypt

#endif // BOOST_CRYPT_DRBG_SHA3_256_DRBG_HPP
