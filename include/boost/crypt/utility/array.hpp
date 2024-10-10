// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_UTILITIES_ARRAY_HPP
#define BOOST_CRYPT_UTILITIES_ARRAY_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/cstddef.hpp>

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
    constexpr auto begin() noexcept -> iterator { return elements; }
    constexpr auto cbegin() const noexcept -> const_iterator { return elements; }
    constexpr auto end() noexcept -> iterator { return elements + N; }
    constexpr auto cend() const noexcept -> const_iterator { return elements + N; }

    // Sizing
    constexpr auto size() noexcept -> size_type { return N; }
    constexpr auto max_size() noexcept -> size_type { return N; }

    // Accessors
    constexpr auto operator[](size_type n) noexcept -> reference
    {
        BOOST_CRYPT_ASSERT(n < N);
        return elements[n];
    }

    constexpr auto operator[](size_type n) const noexcept -> const_reference
    {
        BOOST_CRYPT_ASSERT(n < N);
        return elements[n];
    }

    // For at instead of throwing on out of range return the last element since throwing doesn't work on device
    constexpr auto at(size_type n) noexcept -> reference
    {
        if (n >= N)
        {
            return elements[N - 1U];
        }
        return elements[n];
    }

    constexpr auto at(size_type n) const noexcept -> const_reference
    {
        if (n >= N)
        {
            return elements[N - 1U];
        }
        return elements[n];
    }

    // Front and back
    constexpr auto front() noexcept -> reference { return elements[0]; }
    constexpr auto front() const noexcept -> const_reference { return elements[0]; }
    constexpr auto back() noexcept -> reference { return elements[N - 1]; }
    constexpr auto back() const noexcept -> const_reference { return elements[N - 1]; }

    constexpr auto data() noexcept -> pointer { return elements; }
    constexpr auto data() const noexcept -> const_pointer { return elements; }

    // Fill and swap
    constexpr auto fill(const value_type& v) -> void
    {
        for (size_type i {}; i < N; ++i)
        {
            elements[i] = v;
        }
    }

    constexpr auto swap(array<value_type, N>& a)
    {
        const auto temp {a};
        a = *this;
        *this = temp;
    }
};

template <typename ForwardIter, typename T>
constexpr auto fill_array(ForwardIter first, ForwardIter last, T value)
{
    while (first != last)
    {
        *first++ = static_cast<decltype(*first)>(value);
    }
}

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_UTILITIES_ARRAY_HPP
