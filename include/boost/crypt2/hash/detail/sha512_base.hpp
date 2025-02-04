// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc6234
// See: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=31

#ifndef BOOST_CRYPT2_HASH_DETAIL_SHA512_BASE_HPP
#define BOOST_CRYPT2_HASH_DETAIL_SHA512_BASE_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/assert.hpp>
#include <boost/crypt2/detail/expected.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::hash_detail {

template <compat::size_t digest_size>
class sha512_base final
{
public:

    using return_type = compat::array<compat::byte, digest_size>;

    static constexpr compat::size_t block_size {128U};

private:

    static_assert(digest_size == 28U || digest_size == 32U || digest_size == 48U || digest_size == 64U,
                  "Digest size must be 28 (SHA512/224), 32 (SHA512/256), 48 (SHA384), or 64 (SHA512)");

    compat::array<compat::uint64_t, 8U> intermediate_hash_ {};
    compat::array<compat::byte, 128U> buffer_ {};
    compat::size_t buffer_index_ {};
    compat::uint64_t low_ {};
    compat::uint64_t high_ {};
    bool computed_ {};
    bool corrupted_ {};

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_message_block() noexcept -> void;

    template <compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto update(compat::span<const compat::byte, Extent> data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto pad_message() noexcept -> void;

    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto get_digest_impl(compat::span<compat::byte, digest_size> data) const -> state;

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha512_base() noexcept { init(); }

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~sha512_base() noexcept;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init() noexcept -> void;

    template <compat::size_t Extent = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto process_bytes(SizedRange&& data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto process_byte(compat::byte data) noexcept -> state;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto finalize() noexcept -> state;

    [[nodiscard("Digest is the function return value")]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    auto get_digest() const noexcept -> compat::expected<return_type, state>;

    template <compat::size_t Extent = compat::dynamic_extent>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
    auto get_digest(compat::span<compat::byte, Extent> data) const noexcept -> state;

    template <concepts::writable_output_range Range>
    [[nodiscard]] BOOST_CRYPT_GPU_ENABLED auto get_digest(Range&& data) const noexcept -> state;
};

template <compat::size_t digest_size>
template <concepts::writable_output_range Range>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED
auto sha512_base<digest_size>::get_digest(Range&& data) const noexcept -> state
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

template <compat::size_t digest_size>
template <compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha512_base<digest_size>::get_digest(compat::span<compat::byte, Extent> data) const noexcept -> state
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

template <compat::size_t digest_size>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha512_base<digest_size>::get_digest() const noexcept -> compat::expected<return_type, state>
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

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::get_digest_impl(compat::span<compat::byte, digest_size> data) const -> state
{
    BOOST_CRYPT_ASSERT(data.size() == digest_size);
    BOOST_CRYPT_ASSERT(intermediate_hash_.size() >= (digest_size - 1U) >> 3U);
    for (compat::size_t i {}; i < digest_size; ++i)
    {
        data[i] = static_cast<compat::byte>(intermediate_hash_[i >> 3U] >> 8U * (7 - (i % 8U)));
    }

    return state::success;
}

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::finalize() noexcept -> state
{
    if (computed_)
    {
        corrupted_ = true;
    }
    if (corrupted_)
    {
        return state::state_error;
    }

    pad_message();

    detail::clear_mem(buffer_);
    low_ = 0UL;
    high_ = 0UL;
    computed_ = true;

    return state::success;
}

template <compat::size_t digest_size>
template <compat::size_t Extent>
[[nodiscard]] BOOST_CRYPT_GPU_ENABLED_CONSTEXPR
auto sha512_base<digest_size>::update(compat::span<const compat::byte, Extent> data) noexcept -> state
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
        }
    }

    return state::success;
}

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR sha512_base<digest_size>::~sha512_base() noexcept
{
    detail::clear_mem(intermediate_hash_);
    detail::clear_mem(buffer_);
    buffer_index_ = 0U;
    low_ = 0ULL;
    high_ = 0ULL;
    computed_ = false;
    corrupted_ = false;
};

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::init() noexcept -> void
{
    intermediate_hash_.fill(0ULL);
    buffer_.fill(compat::byte{});
    buffer_index_ = 0U;
    low_ = 0ULL;
    high_ = 0ULL;
    computed_ = false;
    corrupted_ = false;

    if constexpr (digest_size == 28U)
    {
        // Constants for SHA512/224
        intermediate_hash_[0] = 0x8C3D37C819544DA2ULL;
        intermediate_hash_[1] = 0x73E1996689DCD4D6ULL;
        intermediate_hash_[2] = 0x1DFAB7AE32FF9C82ULL;
        intermediate_hash_[3] = 0x679DD514582F9FCFULL;
        intermediate_hash_[4] = 0x0F6D2B697BD44DA8ULL;
        intermediate_hash_[5] = 0x77E36F7304C48942ULL;
        intermediate_hash_[6] = 0x3F9D85A86A1D36C8ULL;
        intermediate_hash_[7] = 0x1112E6AD91D692A1ULL;
    }
    else if constexpr (digest_size == 32U)
    {
        // Constants for SHA512/256
        intermediate_hash_[0] = 0x22312194FC2BF72CULL;
        intermediate_hash_[1] = 0x9F555FA3C84C64C2ULL;
        intermediate_hash_[2] = 0x2393B86B6F53B151ULL;
        intermediate_hash_[3] = 0x963877195940EABDULL;
        intermediate_hash_[4] = 0x96283EE2A88EFFE3ULL;
        intermediate_hash_[5] = 0xBE5E1E2553863992ULL;
        intermediate_hash_[6] = 0x2B0199FC2C85B8AAULL;
        intermediate_hash_[7] = 0x0EB72DDC81C52CA2ULL;
    }
    else if constexpr (digest_size == 48U)
    {
        // Constants for SHA384
        intermediate_hash_[0] = 0xcbbb9d5dc1059ed8ULL;
        intermediate_hash_[1] = 0x629a292a367cd507ULL;
        intermediate_hash_[2] = 0x9159015a3070dd17ULL;
        intermediate_hash_[3] = 0x152fecd8f70e5939ULL;
        intermediate_hash_[4] = 0x67332667ffc00b31ULL;
        intermediate_hash_[5] = 0x8eb44a8768581511ULL;
        intermediate_hash_[6] = 0xdb0c2e0d64f98fa7ULL;
        intermediate_hash_[7] = 0x47b5481dbefa4fa4ULL;
    }
    else
    {
        // Constants for SHA512
        intermediate_hash_[0] = 0x6a09e667f3bcc908ULL;
        intermediate_hash_[1] = 0xbb67ae8584caa73bULL;
        intermediate_hash_[2] = 0x3c6ef372fe94f82bULL;
        intermediate_hash_[3] = 0xa54ff53a5f1d36f1ULL;
        intermediate_hash_[4] = 0x510e527fade682d1ULL;
        intermediate_hash_[5] = 0x9b05688c2b3e6c1fULL;
        intermediate_hash_[6] = 0x1f83d9abfb41bd6bULL;
        intermediate_hash_[7] = 0x5be0cd19137e2179ULL;
    }
}

namespace sha512_detail {
    
#if !BOOST_CRYPT_HAS_CUDA

// On the host device we prefer this array to be static,
// but in a CUDA environment we move it into the function to make it available to host and device
inline constexpr compat::array<compat::uint64_t, 80U> sha512_k {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
    0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
    0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
    0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
    0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
    0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
    0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
    0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
    0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
    0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
    0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
    0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
    0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
    0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
    0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
    0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
    0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
    0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
    0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
    0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};
    
#endif // BOOST_CRYPT_HAS_CUDA

// See section 4.1.3
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto big_sigma0(const compat::uint64_t x) noexcept -> compat::uint64_t
{
    return compat::rotr(x, 28) ^ compat::rotr(x, 34) ^ compat::rotr(x, 39);
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto big_sigma1(const compat::uint64_t x) noexcept -> compat::uint64_t
{
    return compat::rotr(x, 14) ^ compat::rotr(x, 18) ^ compat::rotr(x, 41);
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto little_sigma0(const compat::uint64_t x) noexcept -> compat::uint64_t
{
    return compat::rotr(x, 1) ^ compat::rotr(x, 8) ^ (x >> 7);
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto little_sigma1(const compat::uint64_t x) noexcept -> compat::uint64_t
{
    return compat::rotr(x, 19) ^ compat::rotr(x, 61) ^ (x >> 6);
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_ch(const compat::uint64_t x,
                                              const compat::uint64_t y,
                                              const compat::uint64_t z) -> compat::uint64_t
{
    return (x & y) ^ ((~x) & z);
}

BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha_maj(const compat::uint64_t x,
                                               const compat::uint64_t y,
                                               const compat::uint64_t z) -> compat::uint64_t
{
    return (x & y) ^ (x & z) ^ (y & z);
}
        
} // namespace sha512_detail

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::process_message_block() noexcept -> void
{
    #if BOOST_CRYPT_HAS_CUDA

    constexpr compat::array<compat::uint64_t, 80U> sha512_k = {
            0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
            0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
            0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
            0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
            0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
            0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
            0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
            0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
            0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
            0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
            0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
            0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
            0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
            0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
            0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
            0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
            0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
            0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
            0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
            0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
            0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
            0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
            0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
            0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
            0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
            0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
            0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
    };

    #endif
    
    using namespace sha512_detail;
    
    compat::array<compat::uint64_t, 80U> W {};

    // Init the first 16 words of W
    BOOST_CRYPT_ASSERT(8U * 16U == buffer_.size());
    for (compat::size_t i {}; i < 16U; ++i)
    {
        W[i] = (static_cast<compat::uint64_t>(buffer_[i * 8U]) << 56U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 1U]) << 48U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 2U]) << 40U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 3U]) << 32U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 4U]) << 24U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 5U]) << 16U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 6U]) << 8U) |
               (static_cast<compat::uint64_t>(buffer_[i * 8U + 7U]));
    }

    // Init the last 64
    for (compat::size_t i {16U}; i < W.size(); ++i)
    {
        W[i] = little_sigma1(W[i - 2U])  + W[i - 7U] +
               little_sigma0(W[i - 15U]) + W[i - 16U];
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};
    auto F {intermediate_hash_[5]};
    auto G {intermediate_hash_[6]};
    auto H {intermediate_hash_[7]};

    BOOST_CRYPT_ASSERT(sha512_k.size() == W.size());
    for (compat::size_t i {}; i < W.size(); ++i)
    {
        const auto temp1 {H + big_sigma1(E) + sha_ch(E, F, G) + sha512_k[i] + W[i]};
        const auto temp2 {big_sigma0(A) + sha_maj(A, B, C)};
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;
    intermediate_hash_[5] += F;
    intermediate_hash_[6] += G;
    intermediate_hash_[7] += H;

    // Reset the buffer index
    buffer_index_ = 0U;
}

template <compat::size_t digest_size>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::process_bytes(compat::span<const compat::byte, Extent> data) noexcept -> state
{
    return update(data);
}

template <compat::size_t digest_size>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto sha512_base<digest_size>::process_bytes(SizedRange&& data) noexcept -> state
{
    auto data_span {compat::make_span(compat::forward<SizedRange>(data))};
    return update(compat::as_bytes(data_span));
}

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::process_byte(compat::byte data) noexcept -> state
{
    const compat::span<const compat::byte, 1> data_span {&data, 1U};
    return update(data_span);
}

template <compat::size_t digest_size>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto sha512_base<digest_size>::pad_message() noexcept -> void
{
    constexpr compat::size_t message_length_start_index {112U};

    // We don't have enough space for everything we need
    if (buffer_index_ >= message_length_start_index)
    {
        buffer_[buffer_index_++] = compat::byte{0x80};
        while (buffer_index_ < buffer_.size())
        {
            buffer_[buffer_index_++] = compat::byte{0x00};
        }

        process_message_block();

        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = compat::byte{0x00};
        }
    }
    else
    {
        buffer_[buffer_index_++] = compat::byte{0x80};
        while (buffer_index_ < message_length_start_index)
        {
            buffer_[buffer_index_++] = compat::byte{0x00};
        }
    }

    // Add the message length to the end of the buffer
    BOOST_CRYPT_ASSERT(buffer_index_ == message_length_start_index);

    buffer_[112U] = static_cast<compat::byte>(high_ >> 56U);
    buffer_[113U] = static_cast<compat::byte>(high_ >> 48U);
    buffer_[114U] = static_cast<compat::byte>(high_ >> 40U);
    buffer_[115U] = static_cast<compat::byte>(high_ >> 32U);
    buffer_[116U] = static_cast<compat::byte>(high_ >> 24U);
    buffer_[117U] = static_cast<compat::byte>(high_ >> 16U);
    buffer_[118U] = static_cast<compat::byte>(high_ >>  8U);
    buffer_[119U] = static_cast<compat::byte>(high_);

    buffer_[120U] = static_cast<compat::byte>(low_ >> 56U);
    buffer_[121U] = static_cast<compat::byte>(low_ >> 48U);
    buffer_[122U] = static_cast<compat::byte>(low_ >> 40U);
    buffer_[123U] = static_cast<compat::byte>(low_ >> 32U);
    buffer_[124U] = static_cast<compat::byte>(low_ >> 24U);
    buffer_[125U] = static_cast<compat::byte>(low_ >> 16U);
    buffer_[126U] = static_cast<compat::byte>(low_ >>  8U);
    buffer_[127U] = static_cast<compat::byte>(low_);

    // Finally we process the message block with our filled buffer
    process_message_block();
}

} // namespace boost::crypt::hash_detail

#endif //BOOST_CRYPT2_HASH_DETAIL_SHA512_BASE_HPP
