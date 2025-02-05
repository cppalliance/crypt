// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/drbg/sha1_drbg.hpp>
#include <boost/core/lightweight_test.hpp>
#include <iostream>
#include <string>
#include <cstring>

void sha1_basic_correctness()
{
    boost::crypt::sha1_hmac_drbg rng;

    std::array<std::uint8_t, 16> entropy = {
        0xe9, 0x1b, 0x63, 0x30, 0x9e, 0x93, 0xd1, 0xd0, 0x8e, 0x30, 0xe8, 0xd5, 0x56, 0x90, 0x68, 0x75
    };

    std::array<std::uint8_t, 8> nonce = {
        0xf5, 0x97, 0x47, 0xc4, 0x68, 0xb0, 0xd0, 0xda
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    // ** INSTANTIATE:
    // V   = 7ea45af5f8fcba082fa40bcbea2748dfe7e09f6a
    // Key = be3976a33f77e0155b7ca84a5732d44f319e5f3a

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // V   = 0e28fe04dd16482f8e4b048675318adcd5e6e6cf
    // Key = 764d4f1fb7b04624bcb14642acb24d70eff3c0c8

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V   = 749a95f0882e0179d66d8ae2697802f8f568ce2f
    //	Key = bfcd86fcb4c2efce22f6e9b69742751a17b0056c

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0xb7, 0x92, 0x8f, 0x95, 0x03, 0xa4, 0x17, 0x11, 0x07, 0x88,
        0xf9, 0xd0, 0xc2, 0x58, 0x5f, 0x8a, 0xee, 0x6f, 0xb7, 0x3b,
        0x22, 0x0a, 0x62, 0x6b, 0x3a, 0xb9, 0x82, 0x5b, 0x7a, 0x9f,
        0xac, 0xc7, 0x97, 0x23, 0xd7, 0xe1, 0xba, 0x92, 0x55, 0xe4,
        0x0e, 0x65, 0xc2, 0x49, 0xb6, 0x08, 0x2a, 0x7b, 0xc5, 0xe3,
        0xf1, 0x29, 0xd3, 0xd8, 0xf6, 0x9b, 0x04, 0xed, 0x11, 0x83,
        0x41, 0x9d, 0x6c, 0x4f, 0x2a, 0x13, 0xb3, 0x04, 0xd2, 0xc5,
        0x74, 0x3f, 0x41, 0xc8, 0xb0, 0xee, 0x73, 0x22, 0x53, 0x47
    };

    for (std::size_t i {}; i < return_bits.size(); ++i)
    {
        if (!BOOST_TEST_EQ(return_bits[i], nist_return[i]))
        {
            // LCOV_EXCL_START
            std::cerr << std::hex
                      << "Got: " << static_cast<std::uint32_t>(return_bits[i])
                      << "\nExpected: " << static_cast<std::uint32_t>(nist_return[i]) << std::endl;
            // LCOV_EXCL_STOP
        }
    }

    std::string big_additional_input = "749a95f0882e0179d66d8ae2697802f8f568ce2fbfcd86fcb4c2efce22f6e9b69742751a17b0056c";
    BOOST_TEST(rng.init(entropy,
                        nonce,
                        big_additional_input) == boost::crypt::state::success);

    BOOST_TEST(rng.generate(return_bits, 640U, big_additional_input) == boost::crypt::state::success);
    BOOST_TEST(rng.reseed(big_additional_input, big_additional_input) == boost::crypt::state::success);

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    std::string_view str_view {big_additional_input};
    BOOST_TEST(rng.reseed(str_view) == boost::crypt::state::success);
    BOOST_TEST(rng.reseed(str_view, str_view) == boost::crypt::state::success);
    #endif
}

void sha1_additional_input()
{
    boost::crypt::sha1_hmac_drbg rng;
    constexpr std::array<std::uint8_t, 16> entropy = {
        0x49, 0x05, 0x8e, 0x67, 0x73, 0xed, 0x2b, 0x7a, 0xb3, 0x09, 0xc0, 0x94, 0x9f, 0xdf, 0x9c, 0x9e
    };
    constexpr std::array<std::uint8_t, 8> nonce = {
        0xa4, 0x57, 0xcb, 0x8e, 0xc0, 0xe7, 0xfd, 0x01
    };
    constexpr std::array<std::uint8_t, 16> personalization = {
        0xdc, 0x47, 0x76, 0x41, 0xd8, 0x9c, 0x7f, 0xc4, 0xa3, 0x0f, 0x14, 0x30, 0x19, 0x7d, 0xd1, 0x59
    };

    BOOST_TEST(rng.init(entropy,
                        nonce,
                        personalization) == boost::crypt::state::success);
    // ** INSTANTIATE:
    //	V   = 9c530ef5f1e277aab4e1e129091a273f0342d5c9
    //	Key = 7006c1c0c03c4ca267b19c50928f35891d8d8807

    std::array<std::uint8_t, 80> return_bits {};

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    //	V   = 5b1508d16daad5aff52273cd549ce6bd9e259b0d
    //	Key = b7e28116a16856b9e81bda776d421bb56e8f902f

    BOOST_TEST(rng.generate(return_bits, return_bits.size() * 8U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V   = 71fa823bc53bfd307d6438edd7e5c581fffc27cc
    //	Key = cfccf80b126cea770b468fb8652abbd5eeea2a5e

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0x4e, 0x89, 0x1f, 0x4e, 0x28, 0x11, 0x00, 0x45, 0x3b, 0x70, 0x78,
        0x89, 0x29, 0xec, 0x74, 0x3a, 0x3c, 0x5e, 0xdd, 0x9b, 0x81, 0xdc,
        0x79, 0x8b, 0xc9, 0x37, 0x71, 0x36, 0x8c, 0x39, 0xb6, 0x12, 0x03,
        0x7b, 0x6f, 0x42, 0xf6, 0x0c, 0x5d, 0x89, 0x24, 0xb6, 0x46, 0x84,
        0x81, 0x51, 0xb0, 0xc2, 0x95, 0xbe, 0x49, 0x1d, 0x4a, 0x28, 0xd1,
        0x92, 0x7d, 0xee, 0xd5, 0x23, 0xfd, 0x04, 0xd3, 0xd2, 0xdd, 0xa9,
        0x5e, 0xd4, 0x21, 0x66, 0x31, 0x2e, 0x5c, 0x33, 0x92, 0xd2, 0x28,
        0x93, 0xb0, 0xdc
    };

    for (std::size_t i {}; i < return_bits.size(); ++i)
    {
        if (!BOOST_TEST_EQ(return_bits[i], nist_return[i]))
        {
            // LCOV_EXCL_START
            std::cerr << std::hex
                      << "Got: " << static_cast<std::uint32_t>(return_bits[i])
                      << "\nExpected: " << static_cast<std::uint32_t>(nist_return[i]) << std::endl;
            // LCOV_EXCL_STOP
        }
    }
}

void sha1_pr()
{
    boost::crypt::sha1_hmac_drbg_pr rng;
    constexpr std::array<std::uint8_t, 16> entropy = {
        0xa0, 0xc9, 0xab, 0x58, 0xf1, 0xe2, 0xe5, 0xa4, 0xde, 0x3e, 0xbd, 0x4f, 0xf7, 0x3e, 0x9c, 0x5b
    };
    constexpr std::array<std::uint8_t, 8> nonce = {
        0x64, 0xef, 0xd8, 0xca, 0x02, 0x8c, 0xf8, 0x11
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_1 = {
        0x48, 0xa5, 0x84, 0xfe, 0x69, 0xab, 0x5a, 0xee, 0x42, 0xaa, 0x4d, 0x42, 0x17, 0x60, 0x99, 0xd4
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_2 = {
        0x5e, 0x13, 0x97, 0xdc, 0x40, 0x4d, 0x86, 0xa3, 0x7b, 0xf5, 0x59, 0x54, 0x75, 0x69, 0x51, 0xe4
    };

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0x9a, 0x00, 0xa2, 0xd0, 0x0e, 0xd5, 0x9b, 0xfe, 0x31, 0xec,
        0xb1, 0x39, 0x9b, 0x60, 0x81, 0x48, 0xd1, 0x96, 0x9d, 0x25,
        0x0d, 0x3c, 0x1e, 0x94, 0x10, 0x10, 0x98, 0x12, 0x93, 0x25,
        0xca, 0xb8, 0xfc, 0xcc, 0x2d, 0x54, 0x73, 0x19, 0x70, 0xc0,
        0x10, 0x7a, 0xa4, 0x89, 0x25, 0x19, 0x95, 0x5e, 0x4b, 0xc6,
        0x00, 0x1d, 0x7f, 0x4e, 0x6a, 0x2b, 0xf8, 0xa3, 0x01, 0xab,
        0x46, 0x05, 0x5c, 0x09, 0xa6, 0x71, 0x88, 0xf1, 0xa7, 0x40,
        0xee, 0xf3, 0xe1, 0x5c, 0x02, 0x9b, 0x44, 0xaf, 0x03, 0x44
    };

    std::array<std::uint8_t, 80> return_bits {};

    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_1) == boost::crypt::state::success);

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_2) == boost::crypt::state::success);

    for (std::size_t i {}; i < return_bits.size(); ++i)
    {
        if (!BOOST_TEST_EQ(return_bits[i], nist_return[i]))
        {
            // LCOV_EXCL_START
            std::cerr << std::hex
                      << "Got: " << static_cast<std::uint32_t>(return_bits[i])
                      << "\nExpected: " << static_cast<std::uint32_t>(nist_return[i]) << std::endl;
            // LCOV_EXCL_STOP
        }
    }

    BOOST_TEST(rng.init(entropy, nonce, nonce) == boost::crypt::state::success);
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    BOOST_TEST(rng.init(entropy) == boost::crypt::state::insufficient_entropy);
}

template <typename HMACDRBGType>
void error_states()
{
    constexpr std::array<std::uint8_t, 16> entropy = {
            0xa0, 0xc9, 0xab, 0x58, 0xf1, 0xe2, 0xe5, 0xa4, 0xde, 0x3e, 0xbd, 0x4f, 0xf7, 0x3e, 0x9c, 0x5b
    };
    constexpr std::array<std::uint8_t, 8> nonce = {
            0x64, 0xef, 0xd8, 0xca, 0x02, 0x8c, 0xf8, 0x11
    };

    HMACDRBGType rng;
    std::array<std::uint8_t, 1> bad_return {};
    BOOST_TEST(rng.generate(bad_return, 8) == boost::crypt::state::uninitialized);
    BOOST_TEST(rng.init(entropy) == boost::crypt::state::insufficient_entropy);
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    BOOST_TEST(rng.generate(bad_return, 65537*8U) == boost::crypt::state::requested_too_many_bits);
    BOOST_TEST(rng.reseed(bad_return) == boost::crypt::state::insufficient_entropy);
}

int main()
{
    sha1_basic_correctness();
    sha1_additional_input();
    sha1_pr();

    error_states<boost::crypt::sha1_hmac_drbg>();
    error_states<boost::crypt::sha1_hmac_drbg_pr>();

    return boost::report_errors();
}
