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

// Additional headers needed for CUDA
#ifdef BOOST_CRYPT_HAS_CUDA
#  include <cuda/std/span>
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
#ifndef BOOST_CRYPT_HAS_CUDA
#  include <cassert>
#  define BOOST_CRYPT_ASSERT(x) assert(x)
#  define BOOST_CRYPT_ASSERT_MSG(expr, msg) assert((expr)&&(msg))
#else
#  define BOOST_CRYPT_ASSERT(x)
#  define BOOST_CRYPT_ASSERT_MSG(expr, msg)
#endif
// ----- Assertions -----

// ----- Has something -----
// C++17
#ifndef BOOST_CRYPT_HAS_CUDA
#  if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#    if __has_include(<string_view>)
#      include <string_view>
#      if defined(__cpp_lib_string_view) && __cpp_lib_string_view >= 201606L
#        define BOOST_CRYPT_HAS_STRING_VIEW
#      endif // <string_view> macro check
#    endif // Has <string_view>
#  endif // C++17
#endif // BOOST_CRYPT_HAS_CUDA

// C++20
#ifndef BOOST_CRYPT_HAS_CUDA
#  if __cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)
#    if __has_include(<span>)
#      include <span>
#      if defined(__cpp_lib_span) && __cpp_lib_span >= 202002L
#        define BOOST_CRYPT_HAS_SPAN
#      endif
#    endif // Has <span>
#  endif // C++20
#endif // BOOST_CRYPT_HAS_CUDA

#if defined(__has_builtin)
#define BOOST_CRYPT_HAS_BUILTIN(x) __has_builtin(x)
#else
#define BOOST_CRYPT_HAS_BUILTIN(x) false
#endif

// ----- Has something -----

// ----- Unreachable -----
#if defined(__GNUC__) || defined(__clang__)
#  define BOOST_CRYPT_UNREACHABLE __builtin_unreachable()
#elif defined(_MSC_VER)
#  define BOOST_CRYPT_UNREACHABLE __assume(0)
#else
#  define BOOST_CRYPT_UNREACHABLE std::abort()
#endif
// ----- Unreachable -----

// ----- Unlikely -----

#if BOOST_CRYPT_HAS_BUILTIN(__builtin_expect)
#  define BOOST_CRYPT_LIKELY(x) __builtin_expect(x, 1)
#  define BOOST_CRYPT_UNLIKELY(x) __builtin_expect(x, 0)
#else
#  define BOOST_CRYPT_LIKELY(x) x
#  define BOOST_CRYPT_UNLIKELY(x) x
#endif

// ----- Unlikely -----

// ----- Build module -----
#ifdef BOOST_CRYPT_BUILD_MODULE
#  define BOOST_CRYPT_EXPORT export
#else
#  define BOOST_CRYPT_EXPORT
#endif
// ----- Build module -----

#endif //BOOST_CRYPT_DETAIL_CONFIG_HPP
