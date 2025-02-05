// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DRBG_DETAIL_HMAC_DRBG_HPP
#define BOOST_CRYPT2_DRBG_DETAIL_HMAC_DRBG_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::drbg_detail {

// Max hasher security is defined in NIST SP 800-57 Table 3:
// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
//
// 112: None
// 128: SHA-1
// 192: SHA-224, SHA-512/224, SHA3-224
// 256: SHA-256, SHA-512/256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512
//
// Outlen is defined in NIST SP 800-90A Rev 1 Section 10.1 table 2
// 160: SHA-1
// 224: SHA-224, SHA-512/224
// 256: SHA-256, SHA-512/256
// 384: SHA-384
// 512: SHA-512
template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
class hmac_drbg
{
    static_assert(max_hasher_security == 128 || max_hasher_security == 192 || max_hasher_security == 256, "Invalid value for max hasher security");
    static_assert(outlen == 160 || outlen == 224 || outlen == 256 || outlen == 384 || outlen == 512, "Invalid outlen value");

    static consteval bool valid_combinations()
    {
        switch (max_hasher_security)
        {
            case 128U:
                return outlen == 160;
            case 192U:
                return outlen == 224;
            default:
                return outlen >= 256;
        }
    }

    static_assert(valid_combinations(), "Invalid combination of values");

    static constexpr compat::size_t outlen_bytes {outlen / 8U};
    static constexpr compat::size_t max_bytes_per_request {65536U};
    static constexpr compat::size_t min_length {max_hasher_security / 8U};
    static constexpr compat::size_t min_entropy {min_length * 3U / 2U};

    static constexpr compat::uint64_t max_length {4294967296ULL}; // 2^35 / 8
    static constexpr compat::uint64_t reseed_interval {281474976710656ULL}; // 2^48

    typename HMACType::return_type key_ {};
    compat::span<const compat::byte, outlen_bytes> key_span_ {key_};
    typename HMACType::return_type value_ {};
    compat::span<const compat::byte, outlen_bytes> value_span_ {value_};
    compat::size_t reseed_counter_ {};
    bool initialized_ {};

    template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto update(compat::span<const compat::byte, Extent1> provided_data_1,
                                                  compat::span<const compat::byte, Extent2> provided_data_2,
                                                  compat::span<const compat::byte, Extent3> provided_data_3) noexcept -> state;

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac_drbg() noexcept = default;
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hmac_drbg() noexcept;

    template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init(compat::span<const compat::byte, Extent1> entropy,
                                                compat::span<const compat::byte, Extent2> nonce = compat::span<compat::byte, 0U> {},
                                                compat::span<const compat::byte, Extent3> personalization = compat::span<compat::byte, 0U>{}) noexcept -> state;
};

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::~hmac_drbg() noexcept
{
    detail::clear_mem(key_);
    detail::clear_mem(value_);
    reseed_counter_ = 0U;
    initialized_ = false;
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::update(
                                            compat::span<const compat::byte, Extent1> provided_data_1,
                                            compat::span<const compat::byte, Extent2> provided_data_2,
                                            compat::span<const compat::byte, Extent3> provided_data_3) noexcept -> state
{
    const auto provided_data_size {provided_data_1.size() + provided_data_2.size() + provided_data_3.size()};

    // Step 1: V || 0x00 || provided data
    compat::array<compat::byte, 1U> storage_gap {std::byte{0x00}};
    compat::span<const compat::byte, 1U> storage_gap_span {storage_gap};
    HMACType hmac(key_span_);
    hmac.process_bytes(value_span_);
    hmac.process_bytes(storage_gap_span);
    if constexpr (Extent1 != 0)
    {
        hmac.process_bytes(provided_data_1);
    }
    if constexpr (Extent2 != 0)
    {
        hmac.process_bytes(provided_data_2);
    }
    if constexpr (Extent3 != 0)
    {
        hmac.process_bytes(provided_data_3);
    }

    hmac.finalize();
    auto hmac_return {hmac.get_digest()};
    if (!hmac_return.has_value()) [[unlikely]]
    {
        return hmac_return.error(); // LCOV_EXCL_LINE
    }

    key_ = hmac_return.value();

    if (provided_data_size != 0U)
    {
        // Step 2: V || 0x01 || provided data
        storage_gap[0] = compat::byte{0x01};
        hmac.init(key_span_);
        hmac.process_bytes(value_span_);
        hmac.process_bytes(storage_gap_span);
        if constexpr (Extent1 != 0)
        {
            hmac.process_bytes(provided_data_1);
        }
        if constexpr (Extent2 != 0)
        {
            hmac.process_bytes(provided_data_2);
        }
        if constexpr (Extent3 != 0)
        {
            hmac.process_bytes(provided_data_3);
        }

        hmac.finalize();
        hmac_return = hmac.get_digest();
        if (!hmac_return.has_value()) [[unlikely]]
        {
            return hmac_return.error(); // LCOV_EXCL_LINE
        }

        key_ = hmac_return.value();

        // Step 3: Update value
        hmac.init(key_span_);
        hmac.process_bytes(value_span_);
        hmac.finalize();
        hmac_return = hmac.get_digest();
        if (!hmac_return.has_value()) [[unlikely]]
        {
            return hmac_return.error(); // LCOV_EXCL_LINE
        }

        value_ = hmac_return.value();
    }

    return state::success;
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(
                                            compat::span<const compat::byte, Extent1> entropy,
                                            compat::span<const compat::byte, Extent2> nonce,
                                            compat::span<const compat::byte, Extent3> personalization) noexcept -> state
{
    // Nonce is to be at least >= 0.5 * max_hasher_security
    // Unless entropy + nonce >= 1.5 * max_hasher_security
    if (entropy.size() + nonce.size() < min_entropy)
    {
        return state::insufficient_entropy;
    }

    // Key needs to be set to all 0x00
    for (auto& byte : key_)
    {
        byte = static_cast<compat::byte>(0x00);
    }
    // Value needs to be set to all 0x01
    for (auto& byte : value_)
    {
        byte = static_cast<compat::byte>(0x01);
    }

    const auto update_return {update(entropy, nonce, personalization)};
    if (update_return != state::success) [[unlikely]]
    {
        return update_return; // LCOV_EXCL_LINE
    }

    reseed_counter_ = 1U;
    initialized_ = true;
    return state::success;
}

} // namespace boost::crypt::drbg_detail

#endif // BOOST_CRYPT2_DRBG_DETAIL_HMAC_DRBG_HPP
