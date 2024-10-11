// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_MD5_HPP
#define BOOST_CRYPT_HASH_MD5_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/bit.hpp>
#include <boost/crypt/utility/byte.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/strlen.hpp>
#include <boost/crypt/utility/cstddef.hpp>

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <string>
#include <cstdint>
#include <cstring>
#endif

namespace boost {
namespace crypt {

namespace detail {

static constexpr boost::crypt::array<boost::crypt::uint32_t, 64> S {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static constexpr boost::crypt::array<boost::crypt::uint32_t, 64> K {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

} // namespace detail

class md5_hasher
{
private:
    boost::crypt::uint32_t a0_ {0x67452301};
    boost::crypt::uint32_t b0_ {0xefcdab89};
    boost::crypt::uint32_t c0_ {0x98badcfe};
    boost::crypt::uint32_t d0_ {0x10325476};

    boost::crypt::size_t low_ {};
    boost::crypt::size_t high_ {};

    boost::crypt::array<boost::crypt::uint8_t, 64> buffer_ {};
    boost::crypt::array<boost::crypt::uint32_t, 16> blocks_ {};

    template <typename ForwardIter>
    constexpr auto md5_update(ForwardIter data, boost::crypt::size_t size) noexcept;

    constexpr auto md5_convert_buffer_to_blocks() noexcept;

    template <typename ForwardIter>
    constexpr auto md5_copy_data(ForwardIter data, boost::crypt::size_t offset, boost::crypt::size_t size) noexcept;

    constexpr auto md5_body() noexcept -> void;

public:
    constexpr auto init() noexcept -> void;

    template <typename ByteType>
    constexpr auto process_byte(ByteType byte) noexcept
        BOOST_CRYPT_REQUIRES_CONVERSION(ByteType, boost::crypt::uint8_t);

    template <typename ForwardIter>
    constexpr auto process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept;

    template <typename DigestType>
    constexpr auto get_digest(DigestType digest, boost::crypt::size_t digest_size) noexcept;
};

constexpr auto md5_hasher::init() noexcept -> void
{
    a0_ = 0x67452301U;
    b0_ = 0xefcdab89U;
    c0_ = 0x98badcfeU;
    d0_ = 0x10325476U;

    low_ = 0U;
    high_ = 0U;

    buffer_.fill(static_cast<boost::crypt::uint8_t>(0));
    blocks_.fill(0U);
}

constexpr auto md5_hasher::md5_convert_buffer_to_blocks() noexcept
{
    boost::crypt::size_t buffer_index {};
    for (auto& block : blocks_)
    {
        block = static_cast<boost::crypt::uint32_t>(
                static_cast<boost::crypt::uint32_t>(buffer_[buffer_index]) |
                (static_cast<boost::crypt::uint32_t>(buffer_[buffer_index + 1U]) << 8U) |
                (static_cast<boost::crypt::uint32_t>(buffer_[buffer_index + 2U]) << 16U) |
                (static_cast<boost::crypt::uint32_t>(buffer_[buffer_index + 3U]) << 24U)
        );

        buffer_index += 4U;
    }
}

template <typename ForwardIter>
constexpr auto md5_hasher::md5_copy_data(ForwardIter data, boost::crypt::size_t offset, boost::crypt::size_t size) noexcept
{
    for (boost::crypt::size_t i {}; i < size; ++i)
    {
        BOOST_CRYPT_ASSERT(offset + i < buffer_.size());
        buffer_[offset + i] = static_cast<boost::crypt::uint8_t>(*(data + static_cast<boost::crypt::ptrdiff_t>(i)));
    }
}

template <typename ForwardIter>
constexpr auto md5_hasher::md5_update(ForwardIter data, boost::crypt::size_t size) noexcept
{
    const auto input_bits {size << 3U}; // Convert size to bits
    const auto old_low {low_};
    low_ += input_bits;
    if (low_ < old_low)
    {
        ++high_;
    }
    high_ += size >> 29U;

    auto used {(old_low >> 3U) & 0x3F}; // Number of bytes used in buffer

    if (used)
    {
        auto available = 64U - used;
        if (size < available)
        {
            md5_copy_data(data, used, size);
            return;
        }

        md5_copy_data(data, used, available);
        md5_convert_buffer_to_blocks();
        md5_body();
        data += static_cast<boost::crypt::ptrdiff_t>(available);
        size -= available;
    }

    while (size >= 64U)
    {
        md5_copy_data(data, 0U, 64U);
        md5_convert_buffer_to_blocks();
        md5_body();
        data += 64U;
        size -= 64U;
    }

    if (size > 0)
    {
        md5_copy_data(data, 0U, size);
    }
}

template <typename DigestType>
constexpr auto md5_hasher::get_digest(DigestType digest, boost::crypt::size_t digest_size) noexcept
{
    auto used {(low_ >> 3U) & 0x3F}; // Number of bytes used in buffer
    buffer_[used++] = 0x80;
    auto available {buffer_.size() - used};

    if (available < 8U)
    {
        fill_array(buffer_.begin() + used, buffer_.end(), static_cast<boost::crypt::uint8_t>(0));
        md5_convert_buffer_to_blocks();
        md5_body();
        used = 0;
        buffer_.fill(0);
    }
    else
    {
        fill_array(buffer_.begin() + used, buffer_.end() - 8, static_cast<boost::crypt::uint8_t>(0));
    }

    uint64_t total_bits = (static_cast<uint64_t>(high_) << 32) | low_;

    // Append the length in bits as a 64-bit little-endian integer
    buffer_[56] = static_cast<boost::crypt::uint8_t>(total_bits & 0xFF);
    buffer_[57] = static_cast<boost::crypt::uint8_t>((total_bits >> 8) & 0xFF);
    buffer_[58] = static_cast<boost::crypt::uint8_t>((total_bits >> 16) & 0xFF);
    buffer_[59] = static_cast<boost::crypt::uint8_t>((total_bits >> 24) & 0xFF);
    buffer_[60] = static_cast<boost::crypt::uint8_t>((total_bits >> 32) & 0xFF);
    buffer_[61] = static_cast<boost::crypt::uint8_t>((total_bits >> 40) & 0xFF);
    buffer_[62] = static_cast<boost::crypt::uint8_t>((total_bits >> 48) & 0xFF);
    buffer_[63] = static_cast<boost::crypt::uint8_t>((total_bits >> 56) & 0xFF);

    md5_convert_buffer_to_blocks();
    md5_body();

    if (digest_size >= 4)
    {
        digest[0] = detail::swap_endian(a0_);
        digest[1] = detail::swap_endian(b0_);
        digest[2] = detail::swap_endian(c0_);
        digest[3] = detail::swap_endian(d0_);
    }
}

template <typename ByteType>
constexpr auto md5_hasher::process_byte(ByteType byte) noexcept
    BOOST_CRYPT_REQUIRES_CONVERSION(ByteType, boost::crypt::uint8_t)
{
    md5_update(&byte, 1UL);
}

template <typename ForwardIter>
constexpr auto md5_hasher::process_bytes(ForwardIter buffer, boost::crypt::size_t byte_count) noexcept
{
    md5_update(buffer, byte_count);
}

// TODO(mborland): Replace the loop with the known statements
constexpr auto md5_hasher::md5_body() noexcept -> void
{
    boost::crypt::uint32_t A {a0_};
    boost::crypt::uint32_t B {b0_};
    boost::crypt::uint32_t C {c0_};
    boost::crypt::uint32_t D {d0_};

    for (boost::crypt::uint32_t i {}; i < 64U; ++i)
    {
        boost::crypt::uint32_t F {};
        boost::crypt::uint32_t g {};

        if (i <= 15U)
        {
            F = (B & C) | ((~B) & D);
            g = i;
        }
        else if (i <= 31U)
        {
            F = (D & B) | ((~D) & C);
            g = (5U * i + 1U) % 16U;
        }
        else if (i <= 47U)
        {
            F = B ^ C ^ D;
            g = (3U * i + 5U) % 16U;
        }
        else
        {
            F = C ^ (B | (~D));
            g = (7U * i) % 16U;
        }

        BOOST_CRYPT_ASSERT(i <= 63U);

        F = F + A + detail::K[i] + blocks_[g];
        A = D;
        D = C;
        C = B;
        B = B + detail::rotl(F, detail::S[i]);
    }

    a0_ += A;
    b0_ += B;
    c0_ += C;
    d0_ += D;
}

template <typename ResultType = boost::crypt::array<boost::crypt::uint32_t, 4>, typename T>
ResultType md5(T begin, T end)
{
    if (end < begin)
    {
        return ResultType {0, 0, 0, 0};
    }
    else if (end == begin)
    {
        return ResultType{0xd41d8cd9, 0x8f00b204, 0xe9800998, 0xecf8427e};
    }

    boost::crypt::md5_hasher hasher;
    hasher.process_bytes(begin, static_cast<boost::crypt::size_t>(end - begin));
    ResultType result;
    hasher.get_digest(result.begin(), result.size());

    return result;
}

template <typename ResultType = boost::crypt::array<boost::crypt::uint32_t, 4>>
ResultType md5(const char* str)
{
    if (str == nullptr)
    {
        return ResultType {0, 0, 0, 0};
    }

    const auto message_len {std::strlen(str)};
    return md5<ResultType>(str, str + message_len);
}

template <typename ResultType = boost::crypt::array<boost::crypt::uint32_t, 4>>
ResultType md5(const std::string& str)
{
    return md5<ResultType>(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW
template <typename ResultType = boost::crypt::array<boost::crypt::uint32_t, 4>>
ResultType md5(const std::string_view& str)
{
    return md5<ResultType>(str.begin(), str.end());
}
#endif

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_MD5_HPP
