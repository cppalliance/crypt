// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_UTILITIES_ARRAY_HPP
#define BOOST_CRYPT_UTILITIES_ARRAY_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <array>
#endif

namespace boost {
namespace crypt {

template <typename T, boost::crypt::size_t N>
class array
{
public:
    using reference = T&;
    using const_reference = const T&;
    using iterator = T*;
    using const_iterator = const T*;
    using size_type = boost::crypt::size_t;
    using difference_type = boost::crypt::ptrdiff_t;
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;

    T elements[N];

    // Iterators
    BOOST_CRYPT_GPU_ENABLED constexpr auto begin() noexcept -> iterator { return elements; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto begin() const noexcept -> const_iterator { return elements; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto cbegin() const noexcept -> const_iterator { return elements; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto end() noexcept -> iterator { return elements + N; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto end() const noexcept -> const_iterator { return elements + N; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto cend() const noexcept -> const_iterator { return elements + N; }

    // Sizing
    BOOST_CRYPT_GPU_ENABLED constexpr auto size() const noexcept -> size_type { return N; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto max_size() const noexcept -> size_type { return N; }

    // Accessors
    BOOST_CRYPT_GPU_ENABLED constexpr auto operator[](size_type n) noexcept -> reference
    {
        BOOST_CRYPT_ASSERT(n < N);
        return elements[n];
    }

    BOOST_CRYPT_GPU_ENABLED constexpr auto operator[](size_type n) const noexcept -> const_reference
    {
        BOOST_CRYPT_ASSERT(n < N);
        return elements[n];
    }

    // For at instead of throwing on out of range return the last element since throwing doesn't work on device
    BOOST_CRYPT_GPU_ENABLED constexpr auto at(size_type n) noexcept -> reference
    {
        if (n >= N)
        {
            return elements[N - 1U];
        }
        return elements[n];
    }

    BOOST_CRYPT_GPU_ENABLED constexpr auto at(size_type n) const noexcept -> const_reference
    {
        if (n >= N)
        {
            return elements[N - 1U];
        }
        return elements[n];
    }

    // Front and back
    BOOST_CRYPT_GPU_ENABLED constexpr auto front() noexcept -> reference { return elements[0]; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto front() const noexcept -> const_reference { return elements[0]; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto back() noexcept -> reference { return elements[N - 1]; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto back() const noexcept -> const_reference { return elements[N - 1]; }

    BOOST_CRYPT_GPU_ENABLED constexpr auto data() noexcept -> pointer { return elements; }
    BOOST_CRYPT_GPU_ENABLED constexpr auto data() const noexcept -> const_pointer { return elements; }

    // Fill and swap
    BOOST_CRYPT_GPU_ENABLED constexpr auto fill(const value_type& v) -> void
    {
        for (size_type i {}; i < N; ++i)
        {
            elements[i] = v;
        }
    }

    BOOST_CRYPT_GPU_ENABLED constexpr auto swap(array<value_type, N>& a)
    {
        const auto temp {a};
        a = *this;
        *this = temp;
    }

    constexpr operator std::array<T, N>() noexcept
    {
        std::array<T, N> new_array{};
        for (boost::crypt::size_t i {}; i < N; ++i)
        {
            new_array[i] = elements[i];
        }

        return new_array;
    }
};

template <typename ForwardIter, typename T>
BOOST_CRYPT_GPU_ENABLED constexpr auto fill_array(ForwardIter first, ForwardIter last, T value)
{
    while (first != last)
    {
        *first++ = static_cast<decltype(*first)>(value);
    }
}

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_UTILITIES_ARRAY_HPP
