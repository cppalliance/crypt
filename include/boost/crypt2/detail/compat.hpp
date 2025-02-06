// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Here we inject std and cuda std equivalents into our own namespace
// to help resolve ADL issues with CUDA

#ifndef BOOST_CRYPT2_DETAIL_COMPAT_HPP
#define BOOST_CRYPT2_DETAIL_COMPAT_HPP

#include <boost/crypt2/detail/config.hpp>

#if !BOOST_CRYPT_HAS_CUDA
#include <boost/crypt2/detail/expected.hpp>
#endif

#if !defined(BOOST_CRYPT_BUILD_MODULE) && !BOOST_CRYPT_HAS_CUDA

#include <span>
#include <array>
#include <ranges>
#include <algorithm>
#include <type_traits>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <bit>

#elif BOOST_CRYPT_HAS_CUDA

#include <cuda/std/span>
#include <cuda/std/array>
#include <cuda/std/cstdint>
#include <cuda/std/cstddef>
#include <cuda/std/type_traits>
#include <cuda/std/concepts>
#include <cuda/std/ranges>
#include <cuda/std/utility>
#include <cuda/std/bit>
#include <cuda/std/expected>

#endif

namespace boost::crypt::compat {

// Fixed width types
#if BOOST_CRYPT_HAS_CUDA
using size_t = cuda::std::size_t;
using uint8_t = cuda::std::uint8_t;
using uint16_t = cuda::std::uint16_t;
using uint32_t = cuda::std::uint32_t;
using uint64_t = cuda::std::uint64_t;
#else
using size_t = std::size_t;
using uint8_t = std::uint8_t;
using uint16_t = std::uint16_t;
using uint32_t = std::uint32_t;
using uint64_t = std::uint64_t;
#endif

// Arrays and spans
template <typename T, compat::size_t N>
#if BOOST_CRYPT_HAS_CUDA
using array = cuda::std::array<T, N>;
#else
using array = std::array<T, N>;
#endif

#if BOOST_CRYPT_HAS_CUDA
template<typename T, cuda::std::size_t Extent = cuda::std::dynamic_extent>
using span = cuda::std::span<T, Extent>;
inline constexpr auto dynamic_extent = cuda::std::dynamic_extent;
#else
template<typename T, std::size_t Extent = std::dynamic_extent>
using span = std::span<T, Extent>;
inline constexpr auto dynamic_extent = std::dynamic_extent;
#endif

// Byte and friends
#if BOOST_CRYPT_HAS_CUDA
using byte = cuda::std::byte;
#else
using byte = std::byte;
#endif

template <typename T, compat::size_t N = dynamic_extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto as_bytes(span<T, N> s) noexcept
{
    #if BOOST_CRYPT_HAS_CUDA
    return cuda::std::as_bytes(s);
    #else
    return std::as_bytes(s);
    #endif
}

template <typename T, compat::size_t N = dynamic_extent>
BOOST_CRYPT_GPU_ENABLED constexpr auto as_writable_bytes(span<T, N> s) noexcept
{
    #if BOOST_CRYPT_HAS_CUDA
    return cuda::std::as_writable_bytes(s);
    #else
    return std::as_writable_bytes(s);
    #endif
}

// Type traits
#if BOOST_CRYPT_HAS_CUDA
template <typename T, T v>
using integral_constant = cuda::std::integral_constant<T, v>;
template <bool b>
using bool_constant = cuda::std::bool_constant<b>;
using true_type = cuda::std::true_type;
using false_type = cuda::std::false_type;
#else
template <typename T, T v>
using integral_constant = std::integral_constant<T, v>;
template <bool b>
using bool_constant = std::bool_constant<b>;
using true_type = std::true_type;
using false_type = std::false_type;
#endif

template <typename T>
inline constexpr bool is_trivially_copyable_v =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::is_trivially_copyable_v<T>;
    #else
    std::is_trivially_copyable_v<T>;
    #endif

template <typename T>
using remove_reference_t =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::remove_reference_t<T>;
    #else
    std::remove_reference_t<T>;
    #endif

template <typename T>
using remove_cvref_t =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::remove_cv_t<cuda::std::remove_reference_t<T>>;
    #else
    std::remove_cv_t<std::remove_reference_t<T>>;
    #endif

// Ranges concepts and utilities
template <typename R>
concept sized_range =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::ranges::sized_range<R>;
    #else
    std::ranges::sized_range<R>;
    #endif

template <typename R, typename T>
concept output_range =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::ranges::output_range<R, T>;
    #else
    std::ranges::output_range<R, T>;
    #endif

template <typename R>
using range_value_t =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::ranges::range_value_t<R>;
    #else
    std::ranges::range_value_t<R>;
    #endif

// Utilities
template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto forward(remove_reference_t<T>& t) noexcept -> T&&
{
    #if BOOST_CRYPT_HAS_CUDA
    return cuda::std::forward<T>(t);
    #else
    return std::forward<T>(t);
    #endif
}

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto forward(remove_reference_t<T>&& t) noexcept -> T&&
{
    #if BOOST_CRYPT_HAS_CUDA
    return cuda::std::forward<T>(cuda::std::move(t));
    #else
    return std::forward<T>(std::move(t));
    #endif
}

// Helper functions
template <typename T>
struct is_span : false_type {};

template <typename T, size_t Extent>
struct is_span<span<T, Extent>> : true_type {};

template <typename T, size_t Extent>
struct is_span<const span<T, Extent>> : true_type {};

// Helper variable template
template<typename T>
inline constexpr bool is_span_v = is_span<T>::value;

template <sized_range R>
BOOST_CRYPT_GPU_ENABLED constexpr auto make_span(R&& r)
{
    if constexpr (is_span_v<remove_cvref_t<R>>)
    {
        #if BOOST_CRYPT_HAS_CUDA
        return cuda::std::forward<R>(r);
        #else
        return std::forward<R>(r);
        #endif
    }
    else
    {
        // Since we know that this is a sized range creating the span should also be safe
        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
        #endif

        #if BOOST_CRYPT_HAS_CUDA
        return cuda::std::span{cuda::std::forward<R>(r).data(), cuda::std::forward<R>(r).size()};
        #else
        return std::span{std::forward<R>(r).data(), std::forward<R>(r).size()};
        #endif

        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
        #endif
    }
}

template <typename R>
BOOST_CRYPT_GPU_ENABLED constexpr auto make_span(R& r)
{
    if constexpr (is_span_v<remove_cvref_t<R>>)
    {
        return r;
    }
    else
    {
        #if BOOST_CRYPT_HAS_CUDA
        return cuda::std::span(r);
        #else
        return std::span(r);
        #endif
    }
}

// bit
template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto rotl(T val, int shift) noexcept
{
    // Some clangs incorrectly warn on shift being an int instead of an unsigned int
    // C++ standard says shift is to be int
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #endif

    #if BOOST_CRYPT_HAS_CUDA
    return cuda::std::rotl(val, shift);
    #else
    return std::rotl(val, shift);
    #endif

    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif
}

template <typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto rotr(T val, int shift) noexcept
{
    // Some clangs incorrectly warn on shift being an int instead of an unsigned int
    // C++ standard says shift is to be int
    #ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wsign-conversion"
    #endif

    #if BOOST_CRYPT_HAS_CUDA
    return cuda::std::rotr(val, shift);
    #else
    return std::rotr(val, shift);
    #endif

    #ifdef __clang__
    #pragma clang diagnostic pop
    #endif
}

// Expected
template <typename T, typename E>
using expected =
        #if BOOST_CRYPT_HAS_CUDA
        cuda::std::expected<T, E>;
        #else
        boost::crypt::detail::expected_impl::expected<T, E>;
        #endif

template <typename E>
using unexpected =
        #if BOOST_CRYPT_HAS_CUDA
        cuda::std::unexpected<E>;
        #else
        boost::crypt::detail::expected_impl::unexpected<E>;
        #endif

// Endian
enum class endian : int
{
    #if BOOST_CRYPT_HAS_CUDA
    little = static_cast<int>(cuda::std::endian::little),
    big = static_cast<int>(cuda::std::endian::big),
    native = static_cast<int>(cuda::std::endian::native),
    #else
    little = static_cast<int>(std::endian::little),
    big = static_cast<int>(std::endian::big),
    native = static_cast<int>(std::endian::native),
    #endif
};

template <bool B, class T = void>
using enable_if_t =
    #if BOOST_CRYPT_HAS_CUDA
    cuda::std::enable_if<B, T>::type;
    #else
    std::enable_if<B, T>::type;
    #endif

} // namespace boost::crypt::compat

#endif // BOOST_CRYPT2_DETAIL_COMPAT_HPP
