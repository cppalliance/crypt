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

    template <compat::size_t Extent1, compat::size_t Extent2 = 0U, compat::size_t Extent3 = 0U>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto update(compat::span<const compat::byte, Extent1> provided_data_1,
                                                  compat::span<const compat::byte, Extent2> provided_data_2 = compat::span<const compat::byte, 0U>{},
                                                  compat::span<const compat::byte, Extent3> provided_data_3 = compat::span<const compat::byte, 0U>{}) noexcept -> state;

    template <compat::size_t Extent1, compat::size_t Extent2 = 0U>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto no_pr_generate_impl(compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                               compat::span<const compat::byte, Extent2> additional_data = compat::span<const compat::byte, 0U>{}) noexcept -> state;

    template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3 = 0U>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto pr_generate_impl(compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                            compat::span<const compat::byte, Extent2> entropy,
                                                            compat::span<const compat::byte, Extent3> additional_data = compat::span<const compat::byte, 0U> {}) noexcept -> state;

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac_drbg() noexcept = default;
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hmac_drbg() noexcept;

    template <compat::size_t Extent1, compat::size_t Extent2 = 0U, compat::size_t Extent3 = 0U>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init(compat::span<const compat::byte, Extent1> entropy,
                                                compat::span<const compat::byte, Extent2> nonce = compat::span<const compat::byte, 0U> {},
                                                compat::span<const compat::byte, Extent3> personalization = compat::span<const compat::byte, 0U>{}) noexcept -> state;

    template <concepts::sized_range SizedRange1,
              concepts::sized_range SizedRange2 = compat::span<const compat::byte, 0U>,
              concepts::sized_range SizedRange3 = compat::span<const compat::byte, 0U>>
    BOOST_CRYPT_GPU_ENABLED auto init(SizedRange1&& entropy,
                                      SizedRange2&& nonce = compat::span<const compat::byte, 0U>{},
                                      SizedRange3&& personalization = compat::span<const compat::byte, 0U>{}) noexcept -> state;

    template <compat::size_t Extent1, compat::size_t Extent2 = 0U>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto reseed(compat::span<const compat::byte, Extent1> entropy,
                                                  compat::span<const compat::byte, Extent2> additional_input = compat::span<const compat::byte, 0>{}) noexcept -> state;

    template <concepts::sized_range SizedRange1,
              concepts::sized_range SizedRange2 = compat::span<const compat::byte, 0U>>
    BOOST_CRYPT_GPU_ENABLED auto reseed(SizedRange1&& entropy,
                                        SizedRange2&& additional_data = compat::span<const compat::byte, 0U>{}) noexcept -> state;

    template <compat::size_t Extent1, compat::size_t Extent2 = 0U, compat::size_t Extent3 = 0U>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto generate(compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                    compat::span<const compat::byte, Extent2> additional_data_1 = compat::span<const compat::byte, 0U>{},
                                                    compat::span<const compat::byte, Extent3> additional_data_2 = compat::span<const compat::byte, 0U>{}) noexcept -> state;

    template <concepts::sized_range SizedRange1,
              concepts::sized_range SizedRange2 = compat::span<const compat::byte, 0U>,
              concepts::sized_range SizedRange3 = compat::span<const compat::byte, 0U>>
    BOOST_CRYPT_GPU_ENABLED auto generate(SizedRange1&& return_data, compat::size_t requested_bits,
                                          SizedRange2&& additional_data_1 = compat::span<const compat::byte, 0U>{},
                                          SizedRange3&& additional_data_2 = compat::span<const compat::byte, 0U>{}) noexcept -> state;
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

    HMACType hmac;
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
    auto hmac_return {hmac.get_digest()};
    if (!hmac_return.has_value()) [[unlikely]]
    {
        return hmac_return.error(); // LCOV_EXCL_LINE
    }

    key_ = hmac_return.value();

    hmac.init(key_span_);
    hmac.process_bytes(value_span_);
    hmac.finalize();
    hmac_return = hmac.get_digest();
    if (!hmac_return.has_value()) [[unlikely]]
    {
        return hmac_return.error(); // LCOV_EXCL_LINE
    }
    value_ = hmac_return.value();

    #ifdef _MSC_VER
    #pragma warning(push)
    #pragma warning(disable : 4127) // Conditional expression is constant
    #endif

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

    #ifdef _MSC_VER
    #pragma warning(pop)
    #endif

    return state::success;
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1, compat::size_t Extent2>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::no_pr_generate_impl(
    compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
    compat::span<const compat::byte, Extent2> additional_data) noexcept -> state
{
    if (reseed_counter_ > reseed_interval)
    {
        return state::requires_reseed; // LCOV_EXCL_LINE
    }
    if (!initialized_)
    {
        return state::uninitialized;
    }

    const auto requested_bytes {requested_bits / 8U};
    if (requested_bytes > max_bytes_per_request)
    {
        return state::requested_too_many_bits;
    }

    if constexpr (Extent2 != 0)
    {
        if (!additional_data.empty())
        {
            // If we are on a different 32 bit or smaller platform and using clang ignore the warning
            #ifdef __clang__
            #  pragma clang diagnostic push
            #  pragma clang diagnostic ignored "-Wtautological-constant-out-of-range-compare"
            #endif

            #if !defined(__i386__) && !defined(_M_IX86)
            if (additional_data.size() > max_length)
            {
                return state::input_too_long; // LCOV_EXCL_LINE
            }
            #endif // 32-bit platforms

            #ifdef __clang__
            #  pragma clang diagnostic pop
            #endif

            const auto update_return {update(additional_data)};
            if (update_return != state::success) [[unlikely]]
            {
                return update_return; // LCOV_EXCL_LINE
            }
        }
    }

    compat::size_t bytes {};
    HMACType hmac;
    while (bytes < requested_bytes)
    {
        hmac.init(key_span_);
        hmac.process_bytes(value_span_);
        hmac.finalize();
        const auto hmac_return {hmac.get_digest()};
        if (!hmac_return.has_value()) [[unlikely]]
        {
            return hmac_return.error(); // LCOV_EXCL_LINE
        }

        value_ = hmac_return.value();

        if (bytes + value_.size() < requested_bytes)
        {
            for (const auto val : value_span_)
            {
                return_data[bytes++] = val;
            }
        }
        else
        {
            for (compat::size_t i {}; bytes < requested_bytes && i < value_.size(); ++i)
            {
                return_data[bytes++] = value_span_[i];
            }
        }
    }

    const auto update_return {update(additional_data)};
    if (update_return != state::success) [[unlikely]]
    {
        return update_return; // LCOV_EXCL_LINE
    }

    ++reseed_counter_;
    return state::success;
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::pr_generate_impl(
    compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
    compat::span<const compat::byte, Extent2> entropy,
    compat::span<const compat::byte, Extent3> additional_data) noexcept -> state
{
    // 9.3.3 Reseed using the entropy and the additional data, then set additional data to NULL
    if (reseed_counter_ > reseed_interval)
    {
        return state::requires_reseed; // LCOV_EXCL_LINE
    }
    if (!initialized_)
    {
        return state::uninitialized;
    }

    const auto requested_bytes {requested_bits / 8U};
    if (requested_bytes > max_bytes_per_request)
    {
        return state::requested_too_many_bits;
    }

    const auto reseed_return {reseed(entropy, additional_data)};
    if (reseed_return != state::success) [[unlikely]]
    {
        return reseed_return; // LCOV_EXCL_LINE
    }

    return no_pr_generate_impl(return_data, requested_bits);
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

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <concepts::sized_range SizedRange1, concepts::sized_range SizedRange2, concepts::sized_range SizedRange3>
BOOST_CRYPT_GPU_ENABLED auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::init(
                                            SizedRange1&& entropy,
                                            SizedRange2&& nonce,
                                            SizedRange3&& personalization) noexcept -> state
{
    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
    #endif

    // Since these are sized ranges we can safely convert them into spans
    auto entropy_span {compat::make_span(compat::forward<SizedRange1>(entropy))};
    auto nonce_span {compat::make_span(compat::forward<SizedRange2>(nonce))};
    auto personalization_span {compat::make_span(compat::forward<SizedRange3>(personalization))};

    return init(compat::as_bytes(entropy_span),
                compat::as_bytes(nonce_span),
                compat::as_bytes(personalization_span));

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic pop
    #endif
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1, compat::size_t Extent2>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::reseed(
    compat::span<const compat::byte, Extent1> entropy,
    compat::span<const compat::byte, Extent2> additional_input) noexcept -> state
{
    constexpr auto min_reseed_entropy {max_hasher_security / 8U};

    if (entropy.size() < min_reseed_entropy)
    {
        return state::insufficient_entropy;
    }

    const auto update_return {update(entropy, additional_input)};
    if (update_return != state::success) [[unlikely]]
    {
        return update_return; // LCOV_EXCL_LINE
    }

    reseed_counter_ = 1U;
    return state::success;
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <concepts::sized_range SizedRange1, concepts::sized_range SizedRange2>
BOOST_CRYPT_GPU_ENABLED auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::reseed(
                                            SizedRange1&& entropy,
                                            SizedRange2&& additional_input) noexcept -> state
{
    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
    #endif

    // Since these are sized ranges we can safely convert them into spans
    auto entropy_span {compat::make_span(compat::forward<SizedRange1>(entropy))};
    auto additional_input_span {compat::make_span(compat::forward<SizedRange2>(additional_input))};

    return reseed(compat::as_bytes(entropy_span),
                  compat::as_bytes(additional_input_span));

    #if defined(__clang__) && __clang_major__ >= 19
    #pragma clang diagnostic pop
    #endif
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1, compat::size_t Extent2, compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(
    compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
    compat::span<const compat::byte, Extent2> additional_data_1,
    compat::span<const compat::byte, Extent3> additional_data_2) noexcept -> state
{
    if constexpr (prediction_resistance)
    {
        return pr_generate_impl(return_data, requested_bits, additional_data_1, additional_data_2);
    }
    else
    {
        return no_pr_generate_impl(return_data, requested_bits, additional_data_1);
    }
}

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <concepts::sized_range SizedRange1,
          concepts::sized_range SizedRange2,
          concepts::sized_range SizedRange3>
BOOST_CRYPT_GPU_ENABLED auto hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::generate(
    SizedRange1&& return_data, compat::size_t requested_bits,
    SizedRange2&& additional_data_1,
    SizedRange3&& additional_data_2) noexcept -> state
{
    if constexpr (prediction_resistance)
    {
        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
        #endif

        // Since these are sized ranges we can safely convert them into spans
        auto return_data_span {compat::make_span(compat::forward<SizedRange1>(return_data))};
        auto additional_data1_span {compat::make_span(compat::forward<SizedRange2>(additional_data_1))};
        auto additional_data2_span {compat::make_span(compat::forward<SizedRange3>(additional_data_2))};

        return pr_generate_impl(compat::as_writable_bytes(return_data_span), requested_bits,
                                compat::as_bytes(additional_data1_span),
                                compat::as_bytes(additional_data2_span));

        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic pop
        #endif
    }
    else
    {
        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
        #endif

        // Since these are sized ranges we can safely convert them into spans
        auto return_data_span {compat::make_span(compat::forward<SizedRange1>(return_data))};
        auto additional_data1_span {compat::make_span(compat::forward<SizedRange2>(additional_data_1))};

        return no_pr_generate_impl(compat::as_writable_bytes(return_data_span), requested_bits,
                                   compat::as_bytes(additional_data1_span));

        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic pop
        #endif
    }
}

} // namespace boost::crypt::drbg_detail

#endif // BOOST_CRYPT2_DRBG_DETAIL_HMAC_DRBG_HPP
