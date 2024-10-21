// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

// Global module fragment required for non-module preprocessing
module;

#include <memory>
#include <string>
#include <array>
#include <utility>
#include <algorithm>
#include <concepts>
#include <functional>
#include <limits>
#include <iterator>
#include <complex>
#include <string_view>
#include <span>
#include <fstream>
#include <string>
#include <ios>
#include <exception>
#include <type_traits>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <cstdint>

#define BOOST_CRYPT_BUILD_MODULE

export module boost2.crypt;

#include <boost/crypt/hash/md5.hpp>
#include <boost/crypt/hash/sha1.hpp>
