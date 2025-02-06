// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_OLD_DETAIL_CONFIG_HPP
#define BOOST_CRYPT_OLD_DETAIL_CONFIG_HPP

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
#elif defined(BOOST_CRYPT_HAS_CUDA)
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
#ifndef BOOST_CRYPT_ASSERT
#ifdef BOOST_CRYPT_NO_EXCEPTIONS
#  define BOOST_CRYPT_ASSERT(x)
#  define BOOST_CRYPT_ASSERT_MSG(expr, msg)
#else
#ifndef BOOST_CRYPT_HAS_CUDA
#  ifndef BOOST_CRYPT_BUILD_MODULE
#    include <cassert>
#  endif
#  define BOOST_CRYPT_ASSERT(x) assert(x)
#  define BOOST_CRYPT_ASSERT_MSG(expr, msg) assert((expr)&&(msg))
#else
#  define BOOST_CRYPT_ASSERT(x)
#  define BOOST_CRYPT_ASSERT_MSG(expr, msg)
#endif
#endif
#endif
// ----- Assertions -----

// ----- Has something -----
// C++17

#ifndef BOOST_CRYPT_BUILD_MODULE

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

// C++20 constexpr destructors
#if __cpp_constexpr >= 201907L
#  define BOOST_CRYPT_HAS_CXX20_CONSTEXPR
#endif

#else // We are building a module

// If someone is building the module successfully they defintiely have the above things
#  define BOOST_CRYPT_HAS_STRING_VIEW
#  define BOOST_CRYPT_HAS_SPAN

#endif // BOOST_CRYPT_BUILD_MODULE

#if defined(__has_builtin)
#define BOOST_CRYPT_HAS_BUILTIN(x) __has_builtin(x)
#else
#define BOOST_CRYPT_HAS_BUILTIN(x) false
#endif

// ----- Has something -----

// ----- Unreachable -----
#if defined(__GNUC__) || defined(__clang__) || defined(BOOST_CRYPT_HAS_CUDA)
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

// ----- Endianness -----

// See: https://docs.nvidia.com/cuda/cuda-c-programming-guide/index.html#hardware-implementation
#if defined(_WIN32) || defined(BOOST_CRYPT_HAS_CUDA)

#define BOOST_CRYPT_ENDIAN_BIG_BYTE 0
#define BOOST_CRYPT_ENDIAN_LITTLE_BYTE 1

#elif defined(__BYTE_ORDER__)

#define BOOST_CRYPT_ENDIAN_BIG_BYTE (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define BOOST_CRYPT_ENDIAN_LITTLE_BYTE (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

#else

#error Could not determine endian type. Please file an issue at https://github.com/cppalliance/crypt with your architecture

#endif // Determine endianness

// ----- Endianness -----

// ----- if constexpr -----

// NVRTC does everything at RunTime so it has no concept of if constexpr
#ifdef BOOST_CRYPT_HAS_NVRTC
#  define BOOST_CRYPT_IF_CONSTEXPR if
#elif defined(__cpp_if_constexpr) && __cpp_if_constexpr >= 201606L
#  define BOOST_CRYPT_IF_CONSTEXPR if constexpr
#else
#  define BOOST_CRYPT_IF_CONSTEXPR if
#endif

// ----- if constexpr -----

#endif //BOOST_CRYPT_OLD_DETAIL_CONFIG_HPP
