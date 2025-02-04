// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_DETAIL_SHA_1_2_HASHER_BASE_HPP
#define BOOST_CRYPT_HASH_DETAIL_SHA_1_2_HASHER_BASE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/assert.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::hash_detail {

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
class sha_1_2_hasher_base
{
public:

    static constexpr compat::size_t block_size {64U};

protected:

    // Each hasher needs to process their own message block in their own way
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR virtual auto process_message_block() noexcept -> void = 0;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto pad_message() noexcept -> void;

    compat::array<compat::uint32_t, intermediate_hash_size> intermediate_hash_ {};
    compat::array<compat::byte, block_size> buffer_ {};
    compat::size_t buffer_index_ {};
    compat::size_t low_ {};
    compat::size_t high_ {};
    bool computed_ {};
    bool corrupted_ {};

    template <compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto update(compat::span<const compat::byte, Extent> data) noexcept -> state;

    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest_impl(compat::span<compat::byte, digest_size> data) const noexcept -> state;

public:

    using return_type = compat::array<compat::byte, digest_size>;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha_1_2_hasher_base() noexcept { base_init(); }
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~sha_1_2_hasher_base() noexcept;

    template <compat::size_t Extent = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(SizedRange&& data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_byte(const compat::byte data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto finalize() noexcept -> state;

    // TODO(mborland): Allow this to take dynamic extent, check the length and then use a fixed amount. See sha512_base
    [[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest() const noexcept -> compat::expected<return_type, state>;

    template <compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest(compat::span<compat::byte, Extent> data) const noexcept -> state;

    template <concepts::writable_output_range Range>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest(Range&& data) const noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto base_init() noexcept -> void;
};

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
template <concepts::writable_output_range Range>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest(Range&& data) const noexcept -> state
{
    if (corrupted_ || !computed_)
    {
        return state::state_error;
    }

    using value_type = compat::range_value_t<Range>;

    auto data_span {compat::span<value_type>(compat::forward<Range>(data))};

    if (data_span.size() * sizeof(value_type) < digest_size)
    {
        return state::insufficient_output_length;
    }

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
    #endif

    return get_digest_impl(compat::span<compat::byte, digest_size>(
            compat::as_writable_bytes(data_span).data(),
            digest_size
    ));

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic pop
    #endif
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest_impl(compat::span<compat::byte, digest_size> data) const noexcept -> state
{
    for (compat::size_t i {}; i < data.size(); ++i)
    {
        data[i] = static_cast<compat::byte>(intermediate_hash_[i >> 2U] >> 8U * (3U - (i & 0x03U)));
    }

    return state::success;
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest(compat::span<compat::byte, Extent> data) const noexcept -> state
{
    if (corrupted_ || !computed_)
    {
        return state::state_error;
    }

    if constexpr (Extent == digest_size)
    {
        return get_digest_impl(data);
    }

    if (data.size() >= digest_size)
    {
        // We have verified the length of the span is correct so using a fixed length section of it is safe
        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
        #endif

        return get_digest_impl(compat::span<compat::byte, digest_size>(data.data(), digest_size));

        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic pop
        #endif
    }

    return state::insufficient_output_length;
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
sha_1_2_hasher_base<digest_size, intermediate_hash_size>::get_digest() const noexcept -> compat::expected<return_type, state>
{
    if (corrupted_ || !computed_)
    {
        return compat::unexpected<state>(state::state_error);
    }

    return_type digest {};
    [[maybe_unused]] const auto return_status {get_digest_impl(digest)};
    BOOST_CRYPT_ASSERT(return_status == state::success);

    return digest;
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::finalize() noexcept -> state
{
    if (corrupted_)
    {
        // Return empty message on corruption
        return state::state_error;
    }
    if (!computed_)
    {
        pad_message();

        // Overwrite whatever is in the buffer in case it is sensitive
        detail::clear_mem(buffer_);
        low_ = 0U;
        high_ = 0U;
        computed_ = true;
    }

    return state::success;
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::pad_message() noexcept -> void
{
    // 448 bits out of 512
    constexpr compat::size_t message_length_start_index {56U};

    // We don't have enough space for everything we need
    if (buffer_index_ >= message_length_start_index)
    {
        buffer_[buffer_index_++] = static_cast<compat::byte>(0x80);
        while (buffer_index_ < buffer_.size())
        {
            buffer_[buffer_index_++] = static_cast<compat::byte>(0x00);
        }

        process_message_block();

        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = static_cast<compat::byte>(0x00);
        }
    }
    else
    {
        buffer_[buffer_index_++] = static_cast<compat::byte>(0x80);
        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = static_cast<compat::byte>(0x00);
        }
    }

    // Add the message length to the end of the buffer
    // BOOST_CRYPT_ASSERT(buffer_index_ == message_length_start_index);

    buffer_[56U] = static_cast<compat::byte>(high_ >> 24U);
    buffer_[57U] = static_cast<compat::byte>(high_ >> 16U);
    buffer_[58U] = static_cast<compat::byte>(high_ >>  8U);
    buffer_[59U] = static_cast<compat::byte>(high_);
    buffer_[60U] = static_cast<compat::byte>(low_ >> 24U);
    buffer_[61U] = static_cast<compat::byte>(low_ >> 16U);
    buffer_[62U] = static_cast<compat::byte>(low_ >>  8U);
    buffer_[63U] = static_cast<compat::byte>(low_);

    process_message_block();
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::process_bytes(SizedRange&& data) noexcept -> state
{
    auto data_span {compat::make_span(compat::forward<SizedRange>(data))};
    return update(compat::as_bytes(data_span));
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state
{
    return update(data);
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::process_byte(const compat::byte data) noexcept -> state
{
    const compat::span<const compat::byte, 1> data_span {&data, 1U};
    return update(data_span);
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
template <compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::update(compat::span<const compat::byte, Extent> data) noexcept -> state
{
    if constexpr (Extent == compat::dynamic_extent)
    {
        if (data.empty())
        {
            return state::success;
        }
    }
    else if constexpr (Extent == 0U)
    {
        return state::success;
    }

    if (computed_)
    {
        corrupted_ = true;
    }
    if (corrupted_)
    {
        return state::state_error;
    }

    for (const auto val : data)
    {
        buffer_[buffer_index_++] = val;
        low_ += 8U;

        if (low_ == 0U) [[unlikely]]
        {
            // Would indicate size_t rollover which should not happen on a single data stream
            // LCOV_EXCL_START
            ++high_;
            if (high_ == 0U) [[unlikely]]
            {
                corrupted_ = true;
                return state::input_too_long;
            }
            // LCOV_EXCL_STOP
        }

        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
            buffer_index_ = 0U;
        }
    }

    return state::success;
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha_1_2_hasher_base<digest_size, intermediate_hash_size>::~sha_1_2_hasher_base() noexcept
{
    detail::clear_mem(intermediate_hash_);
    detail::clear_mem(buffer_);
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

template <compat::size_t digest_size, compat::size_t intermediate_hash_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_1_2_hasher_base<digest_size, intermediate_hash_size>::base_init() noexcept -> void
{
    intermediate_hash_.fill(0U);
    buffer_.fill(static_cast<compat::byte>(0));
    buffer_index_ = 0U;
    low_ = 0U;
    high_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

} // namespace boost::crypt::hash_detail

#endif //BOOST_CRYPT_HASH_DETAIL_SHA_1_2_HASHER_BASE_HPP
