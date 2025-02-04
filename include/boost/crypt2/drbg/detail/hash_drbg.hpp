// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_DRBG_HASH_DRBG_HPP
#define BOOST_CRYPT2_DRBG_HASH_DRBG_HPP

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
template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
class hash_drbg
{
private:

    static_assert(max_hasher_security == 128 || max_hasher_security == 192 || max_hasher_security == 256, "Invalid value for max hasher security");
    static_assert(outlen == 224 || outlen == 256 || outlen == 384 || outlen == 512, "Invalid outlen value");

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
    static constexpr compat::size_t seedlen {outlen >= 384 ? 888U : 440U};
    static constexpr compat::size_t seedlen_bytes {seedlen / 8U};

    static constexpr compat::uint64_t max_length {4294967296ULL}; // 2^35 / 8
    static constexpr compat::uint64_t reseed_interval {281474976710656ULL}; // 2^48

    compat::array<compat::byte, seedlen_bytes> constant_ {};
    compat::span<const std::byte, seedlen_bytes> constant_span_ {constant_};
    compat::array<compat::byte, seedlen_bytes> value_ {};
    compat::span<const compat::byte, seedlen_bytes> value_span_ {value_};

    compat::uint64_t reseed_counter_ {};
    bool initialized_ {};

    template <compat::size_t ExtentReturn = compat::dynamic_extent,
              compat::size_t Extent1 = compat::dynamic_extent,
              compat::size_t Extent2 = compat::dynamic_extent,
              compat::size_t Extent3 = compat::dynamic_extent,
              compat::size_t Extent4 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_df(compat::uint32_t no_of_bits_to_return,
                                                   compat::span<compat::byte, ExtentReturn> return_container,
                                                   compat::span<const compat::byte, Extent1> provided_data_1,
                                                   compat::span<const compat::byte, Extent2> provided_data_2 = compat::span<const compat::byte, 0U> {},
                                                   compat::span<const compat::byte, Extent3> provided_data_3 = compat::span<const compat::byte, 0U> {},
                                                   compat::span<const compat::byte, Extent4> provided_data_4 = compat::span<const compat::byte, 0U> {}) noexcept -> state;

    template <compat::size_t Extent = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hashgen(compat::span<compat::byte, Extent> returned_bits, compat::size_t requested_number_of_bytes) noexcept -> state;

    template <compat::size_t Extent1 = compat::dynamic_extent,
              compat::size_t Extent2 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto no_pr_generate_impl(compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                               compat::span<const compat::byte, Extent2> additional_data = compat::span<const compat::byte, 0U> {}) noexcept -> state;

    template <compat::size_t Extent1 = compat::dynamic_extent,
              compat::size_t Extent2 = compat::dynamic_extent,
              compat::size_t Extent3 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto pr_generate_impl(compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                            compat::span<const compat::byte, Extent2> entropy,
                                                            compat::span<const compat::byte, Extent3> additional_data = compat::span<const compat::byte, 0U> {}) noexcept -> state;
public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hash_drbg() noexcept = default;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hash_drbg() noexcept;

    template <compat::size_t Extent1 = compat::dynamic_extent,
              compat::size_t Extent2 = compat::dynamic_extent,
              compat::size_t Extent3 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init(compat::span<const compat::byte, Extent1> entropy,
                                                compat::span<const compat::byte, Extent2> nonce = compat::span<compat::byte, 0>{},
                                                compat::span<const compat::byte, Extent3> personalization = compat::span<compat::byte, 0>{}) noexcept -> state;

    template <concepts::sized_range SizedRange1,
              concepts::sized_range SizedRange2,
              concepts::sized_range SizedRange3 = compat::array<compat::byte, 0U>>
    BOOST_CRYPT_GPU_ENABLED auto init(SizedRange1&& entropy,
                                      SizedRange2&& nonce = compat::array<compat::byte, 0U> {},
                                      SizedRange3&& personalization = compat::array<compat::byte, 0U> {}) noexcept -> state;

    template <compat::size_t Extent1 = compat::dynamic_extent,
              compat::size_t Extent2 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto reseed(compat::span<const compat::byte, Extent1> entropy,
                                                  compat::span<const compat::byte, Extent2> additional_input = compat::span<compat::byte, 0>{}) noexcept -> state;

    template <concepts::sized_range SizedRange1,
              concepts::sized_range SizedRange2 = compat::array<compat::byte, 0U>>
    BOOST_CRYPT_GPU_ENABLED auto reseed(SizedRange1&& entropy,
                                        SizedRange2&& additional_input = compat::array<compat::byte, 0U> {}) noexcept -> state;

    template <compat::size_t Extent1,
              compat::size_t Extent2 = compat::dynamic_extent,
              compat::size_t Extent3 = compat::dynamic_extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto generate(compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                    compat::span<const compat::byte, Extent2> additional_data1 = compat::span<const compat::byte, 0U> {},
                                                    [[maybe_unused]] compat::span<const compat::byte, Extent3> additional_data2 = compat::span<const compat::byte, 0U> {}) noexcept -> state;

    template <concepts::sized_range SizedRange1,
              concepts::sized_range SizedRange2 = compat::array<compat::byte, 0U>,
              concepts::sized_range SizedRange3 = compat::array<compat::byte, 0U>>
    BOOST_CRYPT_GPU_ENABLED auto generate(SizedRange1&& return_data, compat::size_t requested_bits,
                                          SizedRange2&& additional_data1 = compat::array<compat::byte, 0U>{},
                                          [[maybe_unused]] SizedRange3&& additional_data2 = compat::array<compat::byte, 0U>{}) noexcept -> state;
};

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t ExtentReturn,
          compat::size_t Extent1,
          compat::size_t Extent2,
          compat::size_t Extent3,
          compat::size_t Extent4>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::hash_df(
        compat::uint32_t no_of_bits_to_return,
        compat::span<compat::byte, ExtentReturn> return_container,
        compat::span<const compat::byte, Extent1> provided_data_1,
        compat::span<const compat::byte, Extent2> provided_data_2,
        compat::span<const compat::byte, Extent3> provided_data_3,
        compat::span<const compat::byte, Extent4> provided_data_4) noexcept -> state
{
    const auto no_of_bytes_to_return {(no_of_bits_to_return + 7U) / 8U};
    const auto len {(no_of_bytes_to_return + outlen_bytes - 1U) / outlen_bytes};

    // Neither of these should be possible since this is an internal method, but it's best
    // to check in case we messed something else up somewhere
    if (len > 255U) [[unlikely]]
    {
        return state::requested_too_many_bits; // LCOV_EXCL_LINE
    }
    else if (return_container.size() < no_of_bytes_to_return) [[unlikely]]
    {
        return state::out_of_memory; // LCOV_EXCL_LINE
    }

    // The hash string concatenates the value of no_of_bits_to_return
    const compat::array<compat::byte, 4U> bits_to_return_array {
        static_cast<compat::byte>((no_of_bits_to_return >> 24) & 0xFF),
        static_cast<compat::byte>((no_of_bits_to_return >> 16) & 0xFF),
        static_cast<compat::byte>((no_of_bits_to_return >> 8) & 0xFF),
        static_cast<compat::byte>(no_of_bits_to_return & 0xFF)
    };
    const compat::span<const compat::byte, 4U> bits_to_return_span {bits_to_return_array};

    // See 10.3.1
    // temp = temp || HASH(counter, no_of_bits_to_return || input_string)
    compat::size_t offset {};
    for (compat::size_t counter {1}; counter <= len; ++counter)
    {
        HasherType hasher;
        hasher.process_byte(static_cast<compat::byte>(counter));
        hasher.process_bytes(bits_to_return_span);

        if constexpr (Extent1 != 0U)
        {
            [[maybe_unused]] const auto status = hasher.process_bytes(provided_data_1);
            BOOST_CRYPT_ASSERT(status == state::success);
        }

        if constexpr (Extent2 != 0U)
        {
            [[maybe_unused]] const auto status = hasher.process_bytes(provided_data_2);
            BOOST_CRYPT_ASSERT(status == state::success);
        }

        if constexpr (Extent3 != 0U)
        {
            [[maybe_unused]] const auto status = hasher.process_bytes(provided_data_3);
            BOOST_CRYPT_ASSERT(status == state::success);
        }

        if constexpr (Extent4 != 0U)
        {
            [[maybe_unused]] const auto status = hasher.process_bytes(provided_data_4);
            BOOST_CRYPT_ASSERT(status == state::success);
        }

        const auto finalize_status = hasher.finalize();
        if (finalize_status != state::success) [[unlikely]]
        {
            return finalize_status; // LCOV_EXCL_LINE
        }

        const auto return_val {hasher.get_digest()};

        BOOST_CRYPT_ASSERT(return_val.has_value());

        const auto return_val_array {return_val.value()};

        for (compat::size_t i {}; i < return_val_array.size() && offset < no_of_bytes_to_return; ++i)
        {
            return_container[offset++] = return_val_array[i];
        }
    }

    return state::success;
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::hashgen(compat::span<compat::byte, Extent> returned_bits, compat::size_t requested_number_of_bytes) noexcept -> state
{
    if (returned_bits.size() < requested_number_of_bytes)
    {
        return state::out_of_memory;
    }

    auto data {value_};
    const auto data_span {compat::span<compat::byte, seedlen_bytes>(data)};
    compat::size_t offset {};
    HasherType hasher;
    while (offset < requested_number_of_bytes)
    {
        // Step 1: hash the current state of the value array
        hasher.init();
        [[maybe_unused]] const auto process_bytes_status {hasher.process_bytes(data_span)};
        BOOST_CRYPT_ASSERT(process_bytes_status == state::success);
        [[maybe_unused]] const auto finalize_status {hasher.finalize()};
        BOOST_CRYPT_ASSERT(finalize_status == state::success);
        const auto w_expected {hasher.get_digest()};
        if (!w_expected.has_value()) [[unlikely]]
        {
            return w_expected.error(); // LCOV_EXCL_LINE
        }

        // Step 2: Write the output of the hash(data) for return
        const auto w {w_expected.value()};
        if (offset + w.size() <= requested_number_of_bytes)
        {
            for (const auto byte : w)
            {
                returned_bits[offset++] = byte;
            }
        }
        else
        {
            for (compat::size_t i {}; offset < requested_number_of_bytes && i < w.size(); ++i)
            {
                returned_bits[offset++] = w[i];
            }
        }

        // Step 3: Increment data by 1 modulo 2^seedlen
        compat::uint16_t carry {1};
        auto data_position {data.rbegin()};

        while (carry && data_position != data.rend())
        {
            const auto sum {static_cast<compat::uint16_t>(static_cast<compat::uint16_t>(*data_position) + carry)};
            carry = static_cast<compat::uint16_t>(sum >> 8U);
            *data_position++ = static_cast<compat::byte>(sum & 0xFFU);
        }
    }

    return state::success;
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::~hash_drbg() noexcept
{
    detail::clear_mem(constant_);
    detail::clear_mem(value_);
    reseed_counter_ = 0U;
    initialized_ = false;
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1,
          compat::size_t Extent2,
          compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::init(
    compat::span<const compat::byte, Extent1> entropy,
    compat::span<const compat::byte, Extent2> nonce,
    compat::span<const compat::byte, Extent3> personalization) noexcept -> state
{
    if (entropy.size() + nonce.size() < min_entropy)
    {
        return state::insufficient_entropy;
    }

    auto writeable_value_span {compat::span<compat::byte, seedlen_bytes>(value_)};
    auto seed_status {hash_df(seedlen, writeable_value_span, entropy, nonce, personalization)};

    if (seed_status != state::success) [[unlikely]]
    {
        return seed_status; // LCOV_EXCL_LINE
    }

    constexpr compat::array<compat::byte, 1U> offset_array {compat::byte {0x00}};
    const compat::span<const compat::byte, 1U> offset_span {offset_array};
    auto writeable_constant_span {compat::span<compat::byte, seedlen_bytes>(constant_)};
    seed_status = hash_df(seedlen, writeable_constant_span, offset_span, value_span_);

    if (seed_status != state::success) [[unlikely]]
    {
        return seed_status; // LCOV_EXCL_LINE
    }

    initialized_ = true;
    reseed_counter_ = 1U;

    return state::success;
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <concepts::sized_range SizedRange1,
          concepts::sized_range SizedRange2,
          concepts::sized_range SizedRange3>
BOOST_CRYPT_GPU_ENABLED auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::init(
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

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1,
          compat::size_t Extent2>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::reseed(
    compat::span<const compat::byte, Extent1> entropy,
    compat::span<const compat::byte, Extent2> additional_input) noexcept -> state
{
    constexpr auto min_reseed_entropy {max_hasher_security / 8U};

    if (entropy.size() < min_reseed_entropy)
    {
        return state::insufficient_entropy;
    }

    compat::array<compat::byte, seedlen_bytes> seed {};
    compat::span<compat::byte, seedlen_bytes> seed_span {seed};
    constexpr compat::array<const compat::byte, 1U> offset_array { compat::byte{0x01} };
    compat::span<const compat::byte, 1U> offset_array_span {offset_array};

    auto seed_status {hash_df(seedlen,
                              seed_span,
                              offset_array_span,
                              value_span_,
                              entropy,
                              additional_input)};

    if (seed_status != state::success) [[unlikely]]
    {
        return seed_status; // LCOV_EXCL_LINE
    }

    value_ = seed;

    constexpr compat::array<const compat::byte, 1U> c_offset_array { compat::byte{0x00} };
    compat::span<const compat::byte, 1U> c_offset_span {c_offset_array};

    compat::span<compat::byte, seedlen_bytes> writeable_constant_span {constant_};
    seed_status = hash_df(seedlen,
                          writeable_constant_span,
                          c_offset_span,
                          value_span_);

    if (seed_status != state::success) [[unlikely]]
    {
        return seed_status; // LCOV_EXCL_LINE
    }

    reseed_counter_ = 1U;
    return state::success;
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <concepts::sized_range SizedRange1,
          concepts::sized_range SizedRange2>
BOOST_CRYPT_GPU_ENABLED auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::reseed(
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

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1,
          compat::size_t Extent2>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::no_pr_generate_impl(
    compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
    compat::span<const compat::byte, Extent2> additional_data) noexcept -> state
{
    if (reseed_counter_ > reseed_interval) [[unlikely]]
    {
        return state::requires_reseed; // LCOV_EXCL_LINE
    }
    if (!initialized_)
    {
        return state::uninitialized;
    }

    const compat::size_t requested_bytes {(requested_bits + 7U) / 8U};
    if (requested_bytes > max_bytes_per_request)
    {
        return state::requested_too_many_bits;
    }

    if constexpr (Extent2 != 0)
    {
        if (!additional_data.empty())
        {
            // Step 2.1 and 2.2
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

            HasherType hasher {};
            hasher.process_byte(compat::byte{0x02});
            hasher.process_bytes(value_span_);
            hasher.process_bytes(additional_data);
            hasher.finalize();
            const auto w_exp {hasher.get_digest()};

            if (!w_exp.has_value()) [[unlikely]]
            {
                return w_exp.error(); // LCOV_EXCL_LINE
            }
            const auto w {w_exp.value()};

            // V = (v + w) mode 2^seedlen
            auto w_iter {w.crbegin()};
            const auto w_end {w.crend()};

            auto v_iter {value_.rbegin()};
            const auto v_end {value_.rend()};

            // Since the size of V depends on the size of w we will never have an overflow situation
            compat::uint16_t carry {};
            for (; w_iter != w_end; ++w_iter, ++v_iter)
            {
                const auto sum {static_cast<compat::uint16_t>(static_cast<compat::uint16_t>(*w_iter) + static_cast<compat::uint16_t>(*v_iter) + carry)};
                carry = static_cast<compat::uint16_t>(sum >> 8U);
                *v_iter = static_cast<compat::byte>(sum & 0xFFU);
            }

            // Handle final carry past the end of w
            // Since we are to do v = (v+w) mod seedlen we don't concern ourselves past v_end
            while (carry && v_iter != v_end)
            {
                const auto sum {static_cast<compat::uint16_t>(static_cast<compat::uint16_t>(*v_iter) + carry)};
                carry = static_cast<compat::uint16_t>(sum >> 8U);
                *v_iter++ = static_cast<compat::byte>(sum & 0xFFU);
            }
        }
    }

    // Step 3: Fill the buffer with the bytes to return to the user
    const auto hashgen_return {hashgen(return_data, requested_bytes)};
    if (hashgen_return != state::success) [[unlikely]]
    {
        return hashgen_return; // LCOV_EXCL_LINE
    }

    // Step 4: H = Hash(0x03 || V)
    HasherType hasher {};
    hasher.process_byte(compat::byte{0x03});
    hasher.process_bytes(value_span_);
    hasher.finalize();
    const auto h_exp {hasher.get_digest()};
    BOOST_CRYPT_ASSERT(h_exp.has_value());
    const auto h {h_exp.value()};

    // Step 5: v = (v + h + c + reseed counter) mod 2^seedlen
    // Rather than converting V, H, C and reseed to bignums and applying big num modular arithmetic
    // we add all bytes of the same offset at once and have an integer rather than boolean carry
    // we also terminate the calculation at mod 2^seedlen since anything past that is irrelevant
    // It just so happens that value_ is 2^seedlen long
    //
    // The rub is that everything is to be in big endian order so we use reverse iterators
    const compat::array<compat::byte, 64U / 8U> reseed_counter_bytes = {
        static_cast<compat::byte>((reseed_counter_ >> 56U) & 0xFFU),
        static_cast<compat::byte>((reseed_counter_ >> 48U) & 0xFFU),
        static_cast<compat::byte>((reseed_counter_ >> 40U) & 0xFFU),
        static_cast<compat::byte>((reseed_counter_ >> 32U) & 0xFFU),
        static_cast<compat::byte>((reseed_counter_ >> 24U) & 0xFFU),
        static_cast<compat::byte>((reseed_counter_ >> 16U) & 0xFFU),
        static_cast<compat::byte>((reseed_counter_ >> 8U) & 0xFFU),
        static_cast<compat::byte>(reseed_counter_ & 0xFFU),
    };

    // Initialize iterators for V
    auto value_iter {value_.rbegin()};
    const auto value_end {value_.rend()};

    // Initialize iterators for H, C, and reseed_counter_bytes
    auto h_iter {h.crbegin()};
    const auto h_end {h.crend()};

    auto c_iter {constant_.crbegin()};

    auto reseed_counter_iter {reseed_counter_bytes.crbegin()};
    const auto reseed_counter_end {reseed_counter_bytes.crend()};

    // Older GCC warns the += is int instead of uint16_t
    #if defined(__GNUC__) && __GNUC__ >= 5 && __GNUC__ < 10
    #  pragma GCC diagnostic push
    #  pragma GCC diagnostic ignored "-Wconversion"
    #endif

    compat::uint16_t carry {};
    // Since the length of constant and value are known to be the same we only boundary check one of the two
    while (value_iter != value_end)
    {
        compat::uint16_t sum {static_cast<compat::uint16_t>(
                                        static_cast<compat::uint16_t>(*value_iter) +
                                        static_cast<compat::uint16_t>(*c_iter++) + carry
                                        )};

        if (h_iter != h_end)
        {
            sum += static_cast<compat::uint16_t>(*h_iter++);
        }

        if (reseed_counter_iter != reseed_counter_end)
        {
            sum += static_cast<compat::uint16_t>(*reseed_counter_iter++);
        }

        carry = static_cast<compat::uint16_t>(sum >> 8U);
        *value_iter++ = static_cast<compat::byte>(sum & 0xFFU);
    }

    #if defined(__GNUC__) && __GNUC__ >= 5 && __GNUC__ < 10
    #  pragma GCC diagnostic pop
    #endif

    ++reseed_counter_;
    return state::success;
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1,
          compat::size_t Extent2,
          compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::pr_generate_impl(
                                                        compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                        compat::span<const compat::byte, Extent2> entropy,
                                                        compat::span<const compat::byte, Extent3> additional_data) noexcept -> state
{
    if (reseed_counter_ > reseed_interval) [[unlikely]]
    {
        return state::requires_reseed; // LCOV_EXCL_LINE
    }
    if (!initialized_)
    {
        return state::uninitialized;
    }

    // 9.3.3 Reseed using the entropy and the additional data, then set additional data to NULL
    const auto reseed_return {reseed(entropy, additional_data)};
    if (reseed_return != state::success) [[unlikely]]
    {
        return reseed_return; // LCOV_EXCL_LINE
    }

    return no_pr_generate_impl(return_data, requested_bits);
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <compat::size_t Extent1,
          compat::size_t Extent2,
          compat::size_t Extent3>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::generate(
                                                compat::span<compat::byte, Extent1> return_data, compat::size_t requested_bits,
                                                compat::span<const compat::byte, Extent2> additional_data1,
                                                [[maybe_unused]] compat::span<const compat::byte, Extent3> additional_data2) noexcept -> state
{
    if constexpr (prediction_resistance)
    {
        return pr_generate_impl(return_data, requested_bits, additional_data1, additional_data2);
    }
    else
    {
        return no_pr_generate_impl(return_data, requested_bits, additional_data1);
    }
}

template <typename HasherType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
template <concepts::sized_range SizedRange1,
          concepts::sized_range SizedRange2,
          concepts::sized_range SizedRange3>
BOOST_CRYPT_GPU_ENABLED auto hash_drbg<HasherType, max_hasher_security, outlen, prediction_resistance>::generate(SizedRange1&& return_data, compat::size_t requested_bits,
                                      SizedRange2&& additional_data1,
                                      [[maybe_unused]] SizedRange3&& additional_data2) noexcept -> state
{
    if constexpr (prediction_resistance)
    {
        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wunsafe-buffer-usage-in-container"
        #endif

        // Since these are sized ranges we can safely convert them into spans
        auto return_data_span {compat::make_span(compat::forward<SizedRange1>(return_data))};
        auto additional_data1_span {compat::make_span(compat::forward<SizedRange2>(additional_data1))};
        auto additional_data2_span {compat::make_span(compat::forward<SizedRange3>(additional_data2))};

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
        auto additional_data1_span {compat::make_span(compat::forward<SizedRange2>(additional_data1))};

        return no_pr_generate_impl(compat::as_writable_bytes(return_data_span), requested_bits,
                                   compat::as_bytes(additional_data1_span));

        #if defined(__clang__) && __clang_major__ >= 19
        #pragma clang diagnostic pop
        #endif
    }
}

} // namespace boost::crypt::drbg_detail

#endif //BOOST_CRYPT2_DRBG_HASH_DRBG_HPP
