// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_CONFIG_HPP
#define BOOST_CRYPT_DETAIL_CONFIG_HPP

#ifdef __CUDACC__
#  ifndef BOOST_CRYPT_HAS_CUDA
#    define BOOST_CRYPT_HAS_CUDA
#  endif
#  define BOOST_CRYPT_GPU_ENABLED __host__ __device__
#  define BOOST_CRYPT_GPU_HOST_ENABLED __host__
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED __device__
#endif

#ifdef __CUDACC_RTC__
#  ifndef BOOST_CRYPT_HAS_CUDA
#    define BOOST_CRYPT_HAS_CUDA
#  endif
#  define BOOST_CRYPT_HAS_NVRTC
#  define BOOST_CRYPT_GPU_ENABLED __host__ __device__
#  define BOOST_CRYPT_GPU_HOST_ENABLED __host__
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED __device__
#endif

#ifndef BOOST_CRYPT_GPU_ENABLED
#  define BOOST_CRYPT_GPU_ENABLED
#endif

#ifndef BOOST_CRYPT_GPU_HOST_ENABLED
#  define BOOST_CRYPT_GPU_HOST_ENABLED
#endif

#ifndef BOOST_CRYPT_GPU_DEVICE_ENABLED
#  define BOOST_CRYPT_GPU_DEVICE_ENABLED
#endif

// ---- Constexpr arrays -----
#if defined(__cpp_inline_variables) && __cpp_inline_variables >= 201606L
#  define BOOST_CRYPT_CONSTEXPR_ARRAY inline constexpr
#  define BOOST_CRYPT_DEVICE_ARRAY inline constexpr
#  define BOOST_CRYPT_INLINE_CONSTEXPR inline constexpr
#elif defined(BOOST_CRYPT_ENABLE_CUDA)
#  define BOOST_CYPRT_CONSTEXPR_ARRAY static constexpr
#  define BOOST_CRYPT_DEVICE_ARRAY __constant__
#  define BOOST_CRYPT_INLINE_CONSTEXPR static constexpr
#else
#  define BOOST_CRYPT_CONSTEXPR_ARRAY static constexpr
#  define BOOST_CRYPT_DEVICE_ARRAY static constexpr
#  define BOOST_CRYPT_INLINE_CONSTEXPR static constexpr
#endif
// ---- Constexpr arrays -----

// ----- Assertions -----
#include <cassert>
#define BOOST_CRYPT_ASSERT(x) assert(x)
#define BOOST_CRYPT_ASSERT_MSG(expr, msg) assert((expr)&&(msg))
// ----- Assertions -----

// ----- Has CXX something -----
// C++17
#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#  if __has_include(<string_view>)
#    include <string_view>
#    if defined(__cpp_lib_string_view) && __cpp_lib_string_view >= 201606L
#      define BOOST_CRYPT_HAS_STRING_VIEW
#    endif
#  endif
#endif
// ----- Has CXX something -----

// ----- Unreachable -----
#if defined(__GNUC__) || defined(__clang__)
#  define BOOST_CRYPT_UNREACHABLE __builtin_unreachable()
#elif defined(_MSC_VER)
#  define BOOST_CRYPT_UNREACHABLE __assume(0)
#else
#  define BOOST_CRYPT_UNREACHABLE std::abort()
#endif
// ----- Unreachable -----

#endif //BOOST_CRYPT_DETAIL_CONFIG_HPP
