// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_MAC_HMAC_HPP
#define BOOST_CRYPT2_MAC_HMAC_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/expected.hpp>
#include <boost/crypt2/detail/unreachable.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt {

BOOST_CRYPT_EXPORT template <typename HasherType>
class hmac
{
public:

    static constexpr compat::size_t block_size {HasherType::block_size};
    using return_type = typename HasherType::return_type;
    using key_type = compat::array<compat::byte, block_size>;

private:

    using key_span = compat::span<const compat::byte, block_size>;

    key_type inner_key_ {};
    key_type outer_key_ {};
    HasherType inner_hash_;
    HasherType outer_hash_;
    bool initialized_ {false};
    bool computed_ {false};
    bool corrupted_ {false};

    template <compat::size_t Extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init_impl(compat::span<const compat::byte, Extent> data) noexcept -> state;

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac() noexcept = default;

    template <compat::size_t Extent>
    explicit BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac(const compat::span<const compat::byte, Extent> key) noexcept { init(key); }
    
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hmac() noexcept;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init_from_keys(const key_type& inner_key,
                                                          const key_type& outer_key) noexcept -> state;

    template <compat::size_t Extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init(compat::span<const compat::byte, Extent> data) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto init(SizedRange&& data) noexcept -> state;

    template <compat::size_t Extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(SizedRange&& data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto finalize() noexcept -> state;

    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest() const noexcept -> compat::expected<return_type, state>;

    template <compat::size_t Extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    auto get_digest(compat::span<compat::byte, Extent> data) const noexcept -> state;

    template <concepts::writable_output_range Range>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED auto get_digest(Range&& data) const noexcept -> state;

    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_outer_key() const noexcept -> key_type;

    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_inner_key() const noexcept -> key_type;
};

template <typename HasherType>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hmac<HasherType>::init_impl(const compat::span<const compat::byte, Extent> data) noexcept -> state
{
    computed_ = false;
    corrupted_ = false;
    inner_hash_.init();
    outer_hash_.init();

    key_type k0 {};

    // Step 1: If the length of K = B set K0 = K. Go to step 4
    // OR
    // Step 3: If the length of K < B: append zeros to the end of K.
    if (data.size() <= block_size)
    {
        for (compat::size_t i {}; i < data.size() && i < block_size; ++i)
        {
            k0[i] = data[i];
        }
    }
    // Step 2: If the length of K > B: hash K to obtain an L byte string
    else
    {
        HasherType hasher;
        hasher.process_bytes(data);
        hasher.finalize();
        const auto res {hasher.get_digest()};
        BOOST_CRYPT_ASSERT(res.has_value());

        const auto data_hash {res.value()};
        BOOST_CRYPT_ASSERT(data_hash.size() <= k0.size());

        for (compat::size_t i {}; i < data_hash.size(); ++i)
        {
            k0[i] = data_hash[i];
        }
    }

    // Step 4: XOR k0 with ipad to produce a B-byte string K0 ^ ipad
    // Step 7: XOR k0 with opad to produce a B-byte string K0 ^ opad
    for (compat::size_t i {}; i < k0.size(); ++i)
    {
        inner_key_[i] = k0[i] ^ compat::byte{0x36};
        outer_key_[i] = k0[i] ^ compat::byte{0x5C};
    }

    const auto inner_result {inner_hash_.process_bytes(key_span{inner_key_})};
    const auto outer_result {outer_hash_.process_bytes(key_span{outer_key_})};
    
    if (inner_result == state::success && outer_result == state::success) [[likely]]
    {
        initialized_ = true;
        return state::success;
    }
    else
    {
        // If we have some weird OOM result
        // LCOV_EXCL_START
        if (inner_result != state::success)
        {
            return inner_result;
        }
        else
        {
            return outer_result;
        }
        // LCOV_EXCL_STOP
    }
}

template <typename HasherType>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hmac<HasherType>::init(const compat::span<const compat::byte, Extent> data) noexcept -> state
{
    return init_impl(data);
}

template <typename HasherType>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto hmac<HasherType>::init(SizedRange&& data) noexcept -> state
{
    const auto data_span {compat::make_span(compat::forward<SizedRange>(data))};
    return init_impl(compat::as_bytes(data_span));
}

template <typename HasherType>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hmac<HasherType>::init_from_keys(const hmac::key_type& inner_key, const hmac::key_type& outer_key) noexcept -> state
{
    computed_ = false;
    corrupted_ = false;
    inner_hash_.init();
    outer_hash_.init();

    inner_key_ = inner_key;
    outer_key_ = outer_key;

    const auto inner_result {inner_hash_.process_bytes(key_span{inner_key})};
    const auto outer_result {outer_hash_.process_bytes(key_span{outer_key})};

    if (inner_result == state::success && outer_result == state::success) [[likely]]
    {
        initialized_ = true;
        return state::success;
    }
    else
    {
        // These fail states would imply something deeply wrong with the hasher or key
        // LCOV_EXCL_START
        initialized_ = false;

        if (inner_result != state::success)
        {
            return inner_result;
        }
        else
        {
            return outer_result;
        }
        // LCOV_EXCL_STOP
    }
}

template <typename HasherType>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac<HasherType>::~hmac() noexcept
{
    // Inner and outer has will clear their own memory on destruction

    detail::clear_mem(inner_key_);
    detail::clear_mem(outer_key_);
    initialized_ = false;
    computed_ = false;
    corrupted_ = false;
}

template <typename HasherType>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hmac<HasherType>::process_bytes(const compat::span<const compat::byte, Extent> data) noexcept -> state
{
    if (!initialized_ || corrupted_)
    {
        return state::state_error;
    }

    const auto return_code {inner_hash_.process_bytes(data)};
    if (return_code == state::success)
    {
        return state::success;
    }
    else
    {
        // Cannot test 64 and 128 bit OOM
        // LCOV_EXCL_START
        switch (return_code)
        {
            case state::state_error:
                corrupted_ = true;
                return state::state_error;
            case state::input_too_long:
                corrupted_ = true;
                return state::input_too_long;
            default:
                detail::unreachable();
        }
        // LCOV_EXCL_STOP
    }
}

template <typename HasherType>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto hmac<HasherType>::process_bytes(SizedRange&& data) noexcept -> state
{
    const auto data_span {compat::make_span(compat::forward<SizedRange>(data))};
    return process_bytes(compat::as_bytes(data_span));
}

template <typename HasherType>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac<HasherType>::finalize() noexcept -> state
{
    if (computed_)
    {
        corrupted_ = true;
    }
    if (corrupted_)
    {
        return state::state_error;
    }

    computed_ = true;
    [[maybe_unused]] const auto inner_final_state {inner_hash_.finalize()};
    BOOST_CRYPT_ASSERT(inner_final_state == state::success);
    const auto r_inner {inner_hash_.get_digest()};
    BOOST_CRYPT_ASSERT(r_inner.has_value());

    compat::span<const compat::byte> r_inner_span {r_inner.value()};
    outer_hash_.process_bytes(r_inner_span);
    [[maybe_unused]] const auto outer_final_state {outer_hash_.finalize()};
    BOOST_CRYPT_ASSERT(outer_final_state == state::success);

    return state::success;
}

template <typename HasherType>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hmac<HasherType>::get_digest() const noexcept -> compat::expected<return_type, state>
{
    return outer_hash_.get_digest();
}

template <typename HasherType>
template <concepts::writable_output_range Range>
BOOST_CRYPT_GPU_ENABLED auto
hmac<HasherType>::get_digest(Range&& data) const noexcept -> state
{
    return outer_hash_.get_digest(data);
}

template <typename HasherType>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hmac<HasherType>::get_digest(compat::span<compat::byte, Extent> data) const noexcept -> state
{
    return outer_hash_.get_digest(data);
}

template <typename HasherType>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac<HasherType>::get_outer_key() const noexcept -> hmac::key_type
{
    return outer_key_;
}

template <typename HasherType>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac<HasherType>::get_inner_key() const noexcept -> hmac::key_type
{
    return inner_key_;
}

} // namespace boost::crypt

#endif //BOOST_CRYPT2_MAC_HMAC_HPP
