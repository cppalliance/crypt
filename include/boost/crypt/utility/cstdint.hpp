//  Copyright (c) 2024 Matt Borland
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_CRYPT_TOOLS_CSTDINT
#define BOOST_CRYPT_TOOLS_CSTDINT

#include <boost/crypt/utility/config.hpp>

#ifdef BOOST_CRYPT_HAS_CUDA

#include <cuda/std/cstdint>

namespace boost {
namespace crypt {

using cuda::std::int8_t;
using cuda::std::int16_t;
using cuda::std::int32_t;
using cuda::std::int64_t;

using cuda::std::int_fast8_t;
using cuda::std::int_fast16_t;
using cuda::std::int_fast32_t;
using cuda::std::int_fast64_t;

using cuda::std::int_least8_t;
using cuda::std::int_least16_t;
using cuda::std::int_least32_t;
using cuda::std::int_least64_t;

using cuda::std::intmax_t;
using cuda::std::intptr_t;

using cuda::std::uint8_t;
using cuda::std::uint16_t;
using cuda::std::uint32_t;
using cuda::std::uint64_t;

using cuda::std::uint_fast8_t;
using cuda::std::uint_fast16_t;
using cuda::std::uint_fast32_t;
using cuda::std::uint_fast64_t;

using cuda::std::uint_least8_t;
using cuda::std::uint_least16_t;
using cuda::std::uint_least32_t;
using cuda::std::uint_least64_t;

using cuda::std::uintmax_t;
using cuda::std::uintptr_t;

#else

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <cstdint>
#endif

namespace boost {
namespace crypt {

using std::int8_t;
using std::int16_t;
using std::int32_t;
using std::int64_t;

using std::int_fast8_t;
using std::int_fast16_t;
using std::int_fast32_t;
using std::int_fast64_t;

using std::int_least8_t;
using std::int_least16_t;
using std::int_least32_t;
using std::int_least64_t;

using std::intmax_t;
using std::intptr_t;

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;

using std::uint_fast8_t;
using std::uint_fast16_t;
using std::uint_fast32_t;
using std::uint_fast64_t;

using std::uint_least8_t;
using std::uint_least16_t;
using std::uint_least32_t;
using std::uint_least64_t;

using std::uintmax_t;
using std::uintptr_t;

#endif

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_TOOLS_CSTDINT
