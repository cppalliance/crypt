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

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac_drbg() noexcept = default;
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~hmac_drbg() noexcept;
};

template <typename HMACType, compat::size_t max_hasher_security, compat::size_t outlen, bool prediction_resistance>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR hmac_drbg<HMACType, max_hasher_security, outlen, prediction_resistance>::~hmac_drbg() noexcept
{
    detail::clear_mem(key_);
    detail::clear_mem(value_);
    reseed_counter_ = 0U;
    initialized_ = false;
}

} // namespace boost::crypt::drbg_detail

#endif // BOOST_CRYPT2_DRBG_DETAIL_HMAC_DRBG_HPP
