//  Copyright (c) 2024 Matt Borland
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_CRYPT_TOOLS_CSTDDEF
#define BOOST_CRYPT_TOOLS_CSTDDEF

#include <boost/crypt/utility/config.hpp>

#ifdef BOOST_CRYPT_HAS_CUDA

namespace boost {
namespace crypt {

using size_t = unsigned long;
using ptrdiff_t = long;
using nullptr_t = void;
using std::max_align_t = double;


} // namespace crypt
} // namespace boost

#else // No cude

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <cstddef>
#endif

namespace boost {
namespace crypt {

using std::size_t;
using std::ptrdiff_t;
using std::nullptr_t;
using std::max_align_t;

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HAS_CUDA

#endif //BOOST_CSTDDEF_HPP
