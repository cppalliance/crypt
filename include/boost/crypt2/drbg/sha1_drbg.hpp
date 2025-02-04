// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DRBG_SHA1_DRBG_HPP
#define BOOST_CRYPT2_DRBG_SHA1_DRBG_HPP

#include <boost/crypt2/drbg/detail/hash_drbg.hpp>
#include <boost/crypt2/hash/sha1.hpp>

namespace boost::crypt {

namespace drbg_detail {

template <bool prediction_resistance>
using sha1_hash_drbg_t = hash_drbg<sha1_hasher, 128U, 160U, prediction_resistance>;

} // namespace drbg_detail

BOOST_CRYPT_EXPORT using sha1_hash_drbg = drbg_detail::sha1_hash_drbg_t<false>;
BOOST_CRYPT_EXPORT using sha1_hash_drbg_pr = drbg_detail::sha1_hash_drbg_t<true>;

} // namespace boost::crypt

#endif // BOOST_CRYPT2_DRBG_SHA1_DRBG_HPP
