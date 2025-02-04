// Copyright 2024 - 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

#ifndef BOOST_CRYPT2_HASH_DETAIL_SHA3_BASE_HPP
#define BOOST_CRYPT2_HASH_DETAIL_SHA3_BASE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/assert.hpp>
#include <boost/crypt2/detail/expected.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::hash_detail {

template <compat::size_t digest_size, bool is_xof = false>
class sha3_base final {
public:

    static constexpr compat::size_t block_size {200U - 2U * digest_size};

private:

    static_assert((!is_xof && (digest_size == 28U || digest_size == 32U || digest_size == 48U || digest_size == 64U)) ||
                  is_xof,
                  "Digest size must be 28 (SHA3-224), 32 (SHA3-256), 48 (SHA3-384), or 64(SHA3-512) or this must be an xof");

    compat::array<compat::uint64_t, 25U> state_array_ {};
    compat::array<compat::byte, block_size> buffer_ {};
    compat::size_t buffer_index_ {};
    bool computed_ {};
    bool corrupted_ {};

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_message_block() noexcept -> void;

    template <compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    auto update(compat::span<const compat::byte, Extent> data) noexcept -> state;

    template <compat::size_t Extent = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    auto xof_digest_impl(compat::span<compat::byte, Extent> data, compat::size_t amount) noexcept -> void;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    auto sha_digest_impl(compat::span<compat::byte, digest_size> data) const noexcept -> void;

public:

    using return_type = compat::array<compat::byte, digest_size>;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha3_base() noexcept
    { init(); }

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~sha3_base() noexcept;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init() noexcept -> void;

    template <compat::size_t Extent = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(SizedRange&& data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_byte(const compat::byte data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto finalize() noexcept -> state;

    // SHA 3 get_digest is idempotent so make as const
    template <bool Const = !is_xof>
    [[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    compat::enable_if_t<Const, compat::expected<return_type, state>> get_digest() const noexcept;

    template <bool Const = !is_xof, compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    compat::enable_if_t<Const, state> get_digest(compat::span<compat::byte, Extent> data) const noexcept;

    template <bool Const = !is_xof, concepts::writable_output_range Range>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED
    compat::enable_if_t<Const, state> get_digest(Range&& data) const noexcept;

    // XOF get_digest is not idempotent so we need separate impls
    template <bool Const = is_xof>
    [[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    compat::enable_if_t<Const, compat::expected<return_type, state>> get_digest() noexcept;

    template <bool Const = is_xof, compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    compat::enable_if_t<Const, state> get_digest(compat::span<compat::byte, Extent> data) noexcept;

    template <bool Const = is_xof, concepts::writable_output_range Range>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED
    compat::enable_if_t<Const, state> get_digest(Range&& data) noexcept;

    template <bool Const = is_xof, compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    compat::enable_if_t<Const, state> get_digest(compat::span<compat::byte, Extent> data, std::size_t amount) noexcept;

    template <bool Const = is_xof, concepts::writable_output_range Range>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED
    compat::enable_if_t<Const, state> get_digest(Range&& data, std::size_t amount) noexcept;
};

namespace sha3_detail {

#if !BOOST_CRYPT_HAS_CUDA

inline constexpr compat::size_t num_rounds {24U};

inline constexpr compat::array<compat::uint32_t, num_rounds> rho_rotation {
        1U, 3U, 6U, 10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U, 14U,
        27U, 41U, 56U, 8U, 25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
};

inline constexpr compat::array<compat::uint32_t, num_rounds> pi_lane_number {
        10U, 7U, 11U, 17U, 18U, 3U, 5U, 16U, 8U, 21U, 24U, 4U,
        15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U, 6U, 1U
};

inline constexpr compat::array<compat::uint64_t, num_rounds> iota {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace sha3_detail

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha3_base<digest_size, is_xof>::process_message_block() noexcept -> void
{
    #if BOOST_CRYPT_HAS_CUDA

    constexpr compat::size_t num_rounds {24U};

    constexpr compat::array<compat::uint32_t, num_rounds> rho_rotation {
            1U,  3U,  6U,  10U, 15U, 21U, 28U, 36U, 45U, 55U, 2U,  14U,
            27U, 41U, 56U, 8U,  25U, 43U, 62U, 18U, 39U, 61U, 20U, 44U
    };

    constexpr compat::array<compat::uint32_t, num_rounds> pi_lane_number {
            10U, 7U,  11U, 17U, 18U, 3U, 5U,  16U, 8U,  21U, 24U, 4U,
            15U, 23U, 19U, 13U, 12U, 2U, 20U, 14U, 22U, 9U,  6U,  1U
    };

    constexpr compat::array<compat::uint64_t, num_rounds> iota {
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
    };

    #endif // BOOST_CRYPT_HAS_CUDA

    using namespace sha3_detail;

    // Prepare the state array cube
    for (compat::size_t i {}, state_i {}; i < buffer_.size() && state_i < state_array_.size(); i += 8U, ++state_i)
    {
        state_array_[state_i] =
                (static_cast<compat::uint64_t>(buffer_[i])) |
                (static_cast<compat::uint64_t>(buffer_[i + 1U]) << 8U) |
                (static_cast<compat::uint64_t>(buffer_[i + 2U]) << 16U) |
                (static_cast<compat::uint64_t>(buffer_[i + 3U]) << 24U) |
                (static_cast<compat::uint64_t>(buffer_[i + 4U]) << 32U) |
                (static_cast<compat::uint64_t>(buffer_[i + 5U]) << 40U) |
                (static_cast<compat::uint64_t>(buffer_[i + 6U]) << 48U) |
                (static_cast<compat::uint64_t>(buffer_[i + 7U]) << 56U);
    }

    // Apply Kecckaf
    compat::array<compat::uint64_t, 5U> cd {};
    for (compat::size_t round {}; round < num_rounds; ++round)
    {
        // Theta
        for (compat::size_t i {}; i < cd.size(); ++i)
        {
            cd[i] = state_array_[i] ^ state_array_[i + 5U] ^ state_array_[i + 10U] ^ state_array_[i + 15U] ^
                    state_array_[i + 20U];
        }

        for (compat::size_t i {}; i < cd.size(); ++i)
        {
            const auto temp {cd[(i + 4U) % 5U] ^ compat::rotl(cd[(i + 1U) % 5U], 1ULL)};
            for (compat::size_t j {}; j < state_array_.size(); j += 5U)
            {
                state_array_[j + i] ^= temp;
            }
        }

        // Rho and Pi
        auto temp {state_array_[1U]};
        for (compat::size_t i {}; i < num_rounds; ++i)
        {
            const auto j {pi_lane_number[i]};
            cd[0] = state_array_[j];
            state_array_[j] = compat::rotl(temp, static_cast<int>(rho_rotation[i]));
            temp = cd[0];
        }

        // Chi
        for (compat::size_t j {}; j < state_array_.size(); j += 5U)
        {
            for (compat::size_t i {}; i < cd.size(); ++i)
            {
                cd[i] = state_array_[j + i];
            }
            for (compat::size_t i {}; i < cd.size(); ++i)
            {
                state_array_[j + i] ^= (~cd[(i + 1U) % 5U]) & cd[(i + 2U) % 5U];
            }
        }

        // Iota
        state_array_[0] ^= iota[round];
    }

    // Now we need to write back into the buffer
    for (compat::size_t i {}, state_i {}; i < buffer_.size() && state_i < state_array_.size(); i += 8U, ++state_i)
    {
        const auto state_value {state_array_[state_i]};
        buffer_[i] = static_cast<compat::byte>(state_value & 0xFFU);
        buffer_[i + 1U] = static_cast<compat::byte>((state_value >> 8U) & 0xFFU);
        buffer_[i + 2U] = static_cast<compat::byte>((state_value >> 16U) & 0xFFU);
        buffer_[i + 3U] = static_cast<compat::byte>((state_value >> 24U) & 0xFFU);
        buffer_[i + 4U] = static_cast<compat::byte>((state_value >> 32U) & 0xFFU);
        buffer_[i + 5U] = static_cast<compat::byte>((state_value >> 40U) & 0xFFU);
        buffer_[i + 6U] = static_cast<compat::byte>((state_value >> 48U) & 0xFFU);
        buffer_[i + 7U] = static_cast<compat::byte>((state_value >> 56U) & 0xFFU);
    }

    // Finally, reset the buffer index
    buffer_index_ = 0U;
}

// In the fixed extent case where we check Extent == 0 this can make the rest of the code unreachable
// We consider this a good thing since this means our compile time checks are working
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4702)
#endif

template <compat::size_t digest_size, bool is_xof>
template <compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha3_base<digest_size, is_xof>::update(compat::span<const compat::byte, Extent> data) noexcept -> state
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

    for (const auto val: data)
    {
        buffer_[buffer_index_++] ^= val;

        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
        }
    }

    return state::success;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha3_base<digest_size, is_xof>::~sha3_base() noexcept
{
    detail::clear_mem(state_array_);
    detail::clear_mem(buffer_);
    buffer_index_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha3_base<digest_size, is_xof>::init() noexcept -> void
{
    state_array_.fill(0ULL);
    buffer_.fill(compat::byte {0x00});
    buffer_index_ = 0U;
    computed_ = false;
    corrupted_ = false;
}

template <compat::size_t digest_size, bool is_xof>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
sha3_base<digest_size, is_xof>::process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state
{
    return update(data);
}

template <compat::size_t digest_size, bool is_xof>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto sha3_base<digest_size, is_xof>::process_bytes(SizedRange&& data) noexcept -> state
{
    auto data_span {compat::make_span(compat::forward<SizedRange>(data))};
    return update(compat::as_bytes(data_span));
}

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha3_base<digest_size, is_xof>::process_byte(const compat::byte data) noexcept -> state
{
    const compat::span<const compat::byte, 1> data_span {&data, 1U};
    return update(data_span);
}

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha3_base<digest_size, is_xof>::finalize() noexcept -> state
{
    if (!computed_)
    {
        if constexpr (!is_xof)
        {
            buffer_[buffer_index_] ^= static_cast<compat::byte>(0x06);
            buffer_.back() ^= static_cast<compat::byte>(0x80);
        } else
        {
            buffer_[buffer_index_] ^= static_cast<compat::byte>(0x1F);
            buffer_.back() ^= static_cast<compat::byte>(0x80);
        }

        process_message_block();
        computed_ = true;
    }
    if (corrupted_)
    {
        return state::state_error;
    }

    return state::success;
}

template <compat::size_t digest_size, bool is_xof>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha3_base<digest_size, is_xof>::xof_digest_impl(compat::span<compat::byte, Extent> data, std::size_t amount) noexcept -> void
{
    static_assert(is_xof, "Calling for variable amounts of data is not allowed with non-XOF hashers");

    BOOST_CRYPT_ASSERT(data.size() >= amount);
    for (compat::size_t i {}; i < amount; ++i)
    {
        if (buffer_index_ == buffer_.size())
        {
            process_message_block();
        }

        data[i] = buffer_[buffer_index_++];
    }
}

template <compat::size_t digest_size, bool is_xof>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha3_base<digest_size, is_xof>::sha_digest_impl(compat::span<compat::byte, digest_size> data) const noexcept -> void
{
    BOOST_CRYPT_ASSERT(data.size() <= buffer_.size());
    for (compat::size_t i {}; i < data.size(); ++i)
    {
        data[i] = buffer_[i];
    }
}

template <compat::size_t digest_size, bool is_xof>
template <bool Const>
[[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
compat::enable_if_t<Const, compat::expected<typename sha3_base<digest_size, is_xof>::return_type, state>>
sha3_base<digest_size, is_xof>::get_digest() const noexcept
{
    if (!computed_ || corrupted_)
    {
        return compat::unexpected<state>(state::state_error);
    }

    return_type digest {};
    sha_digest_impl(digest);

    return digest;
}

template <compat::size_t digest_size, bool is_xof>
template <bool Const>
[[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
compat::enable_if_t<Const, compat::expected<typename sha3_base<digest_size, is_xof>::return_type, state>>
sha3_base<digest_size, is_xof>::get_digest() noexcept
{
    if (!computed_ || corrupted_)
    {
        return compat::unexpected<state>(state::state_error);
    }

    return_type digest {};
    compat::span<compat::byte, digest_size> digest_span {digest};
    xof_digest_impl(digest_span, digest_size);

    return digest;
}

// In the fixed extent case where we check Extent < digest_size this can make the rest of the code unreachable
// We consider this a good thing since this means our compile time checks are working
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4702)
#endif

template <compat::size_t digest_size, bool is_xof>
template <bool Const, compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
compat::enable_if_t<Const, state> sha3_base<digest_size, is_xof>::get_digest(compat::span<compat::byte, Extent> data) const noexcept
{
    if (!computed_ || corrupted_)
    {
        return state::state_error;
    }

    if constexpr (Extent == compat::dynamic_extent)
    {
        if (data.size() < digest_size)
        {
            return state::insufficient_output_length;
        }
    }
    else if constexpr (Extent < digest_size)
    {
        return state::insufficient_output_length;
    }

    if constexpr (Extent == digest_size)
    {
        sha_digest_impl(data);
    }
    else
    {
        // We have verified the length of the span is correct so using a fixed length section of it is safe
        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
        #endif

        sha_digest_impl(compat::span<compat::byte, digest_size>(data.data(), digest_size));

        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic pop
        #endif
    }

    return state::success;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif

template <compat::size_t digest_size, bool is_xof>
template <bool Const, compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
compat::enable_if_t<Const, state> sha3_base<digest_size, is_xof>::get_digest(compat::span<compat::byte, Extent> data) noexcept
{
    if (!computed_ || corrupted_)
    {
        return state::state_error;
    }

    // XOF will fill the entire provided span whereas SHA will only fill the digest size
    xof_digest_impl(data, data.size());

    return state::success;
}

template <compat::size_t digest_size, bool is_xof>
template <bool Const, concepts::writable_output_range Range>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED
compat::enable_if_t<Const, state> sha3_base<digest_size, is_xof>::get_digest(Range&& data) const noexcept
{
    using value_type = compat::range_value_t<Range>;

    if (!computed_ || corrupted_)
    {
        return state::state_error;
    }

    auto data_span {compat::span<value_type>(compat::forward<Range>(data))};

    if (data_span.size_bytes() < digest_size)
    {
        return state::insufficient_output_length;
    }

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
    #endif

    sha_digest_impl(
        compat::span<compat::byte, digest_size>(
            compat::as_writable_bytes(data_span).data(),
            digest_size
        )
    );

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic pop
    #endif

    return state::success;
}

template <compat::size_t digest_size, bool is_xof>
template <bool Const, concepts::writable_output_range Range>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED
compat::enable_if_t<Const, state> sha3_base<digest_size, is_xof>::get_digest(Range&& data) noexcept
{
    using value_type = compat::range_value_t<Range>;

    if (!computed_ || corrupted_)
    {
        return state::state_error;
    }

    auto data_span {compat::span<value_type>(compat::forward<Range>(data))};

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
    #endif

    xof_digest_impl(compat::span<compat::byte>(compat::as_writable_bytes(data_span).data(), data_span.size_bytes()), data_span.size_bytes());

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic pop
    #endif

    return state::success;
}

template <compat::size_t digest_size, bool is_xof>
template <bool Const, compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
compat::enable_if_t<Const, state> sha3_base<digest_size, is_xof>::get_digest(compat::span<compat::byte, Extent> data, std::size_t amount) noexcept
{
    if (!computed_ || corrupted_)
    {
        return state::state_error;
    }

    if (data.size_bytes() < amount)
    {
        return state::insufficient_output_length;
    }

    // XOF will fill the entire provided span whereas SHA will only fill the digest size
    xof_digest_impl(data, amount);

    return state::success;
}

template <compat::size_t digest_size, bool is_xof>
template <bool Const, concepts::writable_output_range Range>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED
compat::enable_if_t<Const, state> sha3_base<digest_size, is_xof>::get_digest(Range&& data, std::size_t amount) noexcept
{
    using value_type = compat::range_value_t<Range>;

    if (!computed_ || corrupted_)
    {
        return state::state_error;
    }

    auto data_span {compat::span<value_type>(compat::forward<Range>(data))};

    if (data_span.size_bytes() < amount)
    {
        return state::insufficient_output_length;
    }

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
    #endif

    xof_digest_impl(compat::span<compat::byte>(compat::as_writable_bytes(data_span).data(), amount), amount);

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic pop
    #endif

    return state::success;
}

} // namespace boost::crypt::hash_detail

#endif //BOOST_CRYPT2_HASH_DETAIL_SHA3_BASE_HPP
