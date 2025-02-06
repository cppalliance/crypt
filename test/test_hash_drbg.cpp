// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#define BOOST_CRYPT_DEBUG
#include <boost/crypt2/drbg/sha1_drbg.hpp>

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunsafe-buffer-usage"
#endif

#include <boost/core/lightweight_test.hpp>

#if defined(__clang__) && __clang_major__ >= 19
#pragma clang diagnostic pop
#endif

#include <iostream>
#include <cstring>

void sha_1_basic_correctness()
{
    boost::crypt::sha1_hash_drbg rng;

    constexpr std::array<std::uint8_t, 16> entropy = {
        0x13, 0x6c, 0xf1, 0xc1, 0x74, 0xe5, 0xa0, 0x9f, 0x66, 0xb9, 0x62, 0xd9, 0x94, 0x39, 0x65, 0x25
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
        0xff, 0xf1, 0xc6, 0x64, 0x5f, 0x19, 0x23, 0x1f
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    // ** INSTANTIATE:
    // V = a8 84 a8 3f a4 0b cf 73 0e 73 95 dd 58 00 ea 71 01 b4 87 7a aa 29 da 9b 7b c0 bd 2b d0 52 b9 b4 02 2f 83 ba e3 80 64 13 4a 23 38 35 84 5f dd 14 42 bf 3a 02 21 bd c8
    // C = 49 77 fb 12 68 c1 f6 28 6b 5b 39 69 d4 16 fb 8c a7 e4 ea ab 7f d2 ed ef c2 39 20 2b aa 03 3f 8b 44 e9 14 51 48 ad 24 ce 83 d5 97 17 6a 0b ac c8 4c 99 24 6f 15 e0 88

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // V = f1 fc a3 52 0c cd c5 9b 79 ce cf 47 2c 17 e5 fd a9 99 72 26 29 fc c8 8b 3d f9 dd 57 7a 55 f9 3f 47 18 98 92 b1 8e 1c 5f 39 df c0 77 ae 25 65 88 ee ce c7 bb d0 32 3c
    // C = 49 77 fb 12 68 c1 f6 28 6b 5b 39 69 d4 16 fb 8c a7 e4 ea ab 7f d2 ed ef c2 39 20 2b aa 03 3f 8b 44 e9 14 51 48 ad 24 ce 83 d5 97 17 6a 0b ac c8 4c 99 24 6f 15 e0 88

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    // V = 3b 74 9e 64 75 8f bb c3 e5 2a 08 b1 00 2e e1 8a 51 7e 5c d1 a9 cf b6 7b 00 32 fd 83 24 59 38 ca 8c 01 ad d7 70 68 51 5b de 24 8c 75 ad ea 10 bb aa f0 bc 18 e6 6a 2c
    // C = 49 77 fb 12 68 c1 f6 28 6b 5b 39 69 d4 16 fb 8c a7 e4 ea ab 7f d2 ed ef c2 39 20 2b aa 03 3f 8b 44 e9 14 51 48 ad 24 ce 83 d5 97 17 6a 0b ac c8 4c 99 24 6f 15 e0 88

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0x0e, 0x28, 0x13, 0x0f, 0xa5, 0xca, 0x11, 0xed, 0xd3, 0x29,
        0x3c, 0xa2, 0x6f, 0xdb, 0x8a, 0xe1, 0x81, 0x06, 0x11, 0xf7,
        0x87, 0x15, 0x08, 0x2e, 0xd3, 0x84, 0x1e, 0x74, 0x86, 0xf1,
        0x66, 0x77, 0xb2, 0x8e, 0x33, 0xff, 0xe0, 0xb9, 0x3d, 0x98,
        0xba, 0x57, 0xba, 0x35, 0x8c, 0x13, 0x43, 0xab, 0x2a, 0x26,
        0xb4, 0xeb, 0x79, 0x40, 0xf5, 0xbc, 0x63, 0x93, 0x84, 0x64,
        0x1e, 0xe8, 0x0a, 0x25, 0x14, 0x03, 0x31, 0x07, 0x62, 0x68,
        0xbd, 0x1c, 0xe7, 0x02, 0xad, 0x53, 0x4d, 0xda, 0x0e, 0xd8
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

void sha1_pr_false()
{
    boost::crypt::sha1_hash_drbg rng;

    constexpr std::array<std::uint8_t, 16> entropy = {
            0x16, 0x10, 0xb8, 0x28, 0xcc, 0xd2, 0x7d, 0xe0, 0x8c, 0xee, 0xa0, 0x32, 0xa2, 0x0e, 0x92, 0x08
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
            0x49, 0x2c, 0xf1, 0x70, 0x92, 0x42, 0xf6, 0xb5
    };

    constexpr std::array<std::uint8_t, 16> entropy_reseed = {
            0x72, 0xd2, 0x8c, 0x90, 0x8e, 0xda, 0xf9, 0xa4, 0xd1, 0xe5, 0x26, 0xd8, 0xf2, 0xde, 0xd5, 0x44
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) reseed
    // 3) Generate no-compare
    // 4) Generate compare
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    // ** INSTANTIATE:
    // 	V = 9e 83 01 72 5d 5f 13 3b 4a b7 d3 29 fd 2f 87 ae 5f 89 d9 6a 9d d7 e2 b9 8b ee e1 c7 07 b8 c3 fe 41 2d 11 25 b5 8b ae 5d c0 8a 11 da c3 be 4a 31 47 34 71 60 fe f2 18
    //	C = e5 e1 24 50 45 0e fe 5f dc 77 7c 95 b8 c2 3c 93 8f cd 59 2e 2d 78 8f 12 46 19 36 e4 a1 61 31 b1 f2 d1 1c e7 f0 15 9e e1 e6 35 e6 2f 3d f8 bd a4 fe a0 77 ad 5f 9d 06

    BOOST_TEST(rng.reseed(entropy_reseed) == boost::crypt::state::success);
    // ** RESEED:
    //	V = 74 5c 65 9f 29 44 82 9c a6 e2 09 c8 ca 2d dd ec f9 f1 86 13 83 e3 4e 94 00 7a 3a 51 b8 44 4f d5 ae 73 8e 7d 9c 0d 5e 69 aa 97 ee 16 c4 9c fd 24 32 eb 32 ba 57 38 fa
    //	C = a1 fc 40 00 93 57 a0 24 d8 78 81 8c f6 f9 79 a8 8d 4c c5 d7 60 b3 08 ae 1a 5b 9f 06 79 72 e6 f7 cf 92 dd b1 29 a8 d3 c1 bb 00 05 bc f3 f8 87 1f d6 5e 79 4f 19 90 b7

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // 	V = 1658a59fbc9c22c17f5a8b55c1275795873e4beae49657421ad5d95831b736cd7e066c738bcbb343933c411c7c17917593c03a77bed56b
    //	C = a1fc40009357a024d878818cf6f979a88d4cc5d760b308ae1a5b9f067972e6f7cf92ddb129a8d3c1bb0005bcf3f8871fd65e794f1990b7

    BOOST_TEST(rng.generate(return_bits, 640U) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V = b854e5a04ff3c2e657d30ce2b820d13e148b11c245495ff03531785eab2a1dc54d994a5597b15c5b10001f49606c88b4ff0d61acb61820
    //	C = a1fc40009357a024d878818cf6f979a88d4cc5d760b308ae1a5b9f067972e6f7cf92ddb129a8d3c1bb0005bcf3f8871fd65e794f1990b7
    constexpr std::array<std::uint8_t, 80> nist_return = {
            0x56, 0xf3, 0x3d, 0x4f, 0xdb, 0xb9, 0xa5, 0xb6, 0x4d, 0x26,
            0x23, 0x44, 0x97, 0xe9, 0xdc, 0xb8, 0x77, 0x98, 0xc6, 0x8d,
            0x08, 0xf7, 0xc4, 0x11, 0x99, 0xd4, 0xbd, 0xdf, 0x97, 0xeb,
            0xbf, 0x6c, 0xb5, 0x55, 0x0e, 0x5d, 0x14, 0x9f, 0xf4, 0xd5,
            0xbd, 0x0f, 0x05, 0xf2, 0x5a, 0x69, 0x88, 0xc1, 0x74, 0x36,
            0x39, 0x62, 0x27, 0x18, 0x4a, 0xf8, 0x4a, 0x56, 0x43, 0x35,
            0x65, 0x8e, 0x2f, 0x85, 0x72, 0xbe, 0xa3, 0x33, 0xee, 0xe2,
            0xab, 0xff, 0x22, 0xff, 0xa6, 0xde, 0x3e, 0x22, 0xac, 0xa2
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

void sha_1_pr_true()
{
    boost::crypt::sha1_hash_drbg_pr rng;

    constexpr std::array<std::uint8_t, 16> entropy = {
        0x21, 0x29, 0x56, 0x39, 0x07, 0x83, 0x38, 0x1d, 0xbf, 0xc6, 0x36, 0x2d, 0xd0, 0xda, 0x9a, 0x09
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
        0x52, 0x80, 0x98, 0x7f, 0xc5, 0xe2, 0x7a, 0x49
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_1 = {
        0x2e, 0xdb, 0x39, 0x6e, 0xeb, 0x89, 0x60, 0xf7, 0x79, 0x43, 0xc2, 0xa5, 0x90, 0x75, 0xa7, 0x86
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_2 = {
        0x30, 0xb5, 0x65, 0xb6, 0x3a, 0x50, 0x12, 0x67, 0x69, 0x40, 0xd3, 0xef, 0x17, 0xd9, 0xe9, 0x96
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    // ** INSTANTIATE:
    //	V = 02b84eba8121ca090b6b66d3371609eaf76405a5c2807d80035c1a13dfed5aa18e536af599a7b3c68b2c56240ed11997f4048910d84604
    //	C = a677e4921587563eebe55d1b25e59c3f3d200bc61aaee665e7a6858c2857c45dba4bce8182252962ae86de491046a5e3450eec44938a0a

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_1) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // 	V = f9afadfbbf2c3d1004f9baca38be247342e5fbb83281915d5de18beb963712a344e89bb0e6b925a7bbc32eadb8b441efc1fa0c649df42a
    //	C = 1d41cbbd634909e4761c232fcfd6a6c2edf0a7f4d3d3c164f74a88955f355efce2d86c1e9fa897b7005ef9d4d3a51bf4fc0b805ab896c9

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_2) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V = 7e4596f5a17447b6116788b5d8789fe99256c27a6842bd8d11f20df7f3ddcab9faae524cb72fffd56cd92b3f2393f35f606cf6d46c815e
    //	C = 317ac6e7a87b57f0828cde8a4ccf6ad666670f4cffd628670fb9239563452eb3721db06ee06e8c08d78c555a833a8d91053dcf4c343003

    constexpr std::array<std::uint8_t, 80> nist_return = {
            0xca, 0x50, 0xec, 0x95, 0xc7, 0xc3, 0x8a, 0x58, 0x12, 0x9f,
            0xd3, 0x75, 0x23, 0xd1, 0xf2, 0x59, 0x8c, 0xe6, 0xde, 0x98,
            0xa6, 0xf1, 0x07, 0x72, 0x4c, 0x55, 0x46, 0xbe, 0xad, 0xaa,
            0x5b, 0xaf, 0xbf, 0x1e, 0x62, 0xd2, 0x74, 0x84, 0x3f, 0x11,
            0x07, 0xc3, 0x45, 0xb1, 0x28, 0x81, 0x63, 0xf1, 0xdd, 0x24,
            0xaf, 0xb2, 0x7a, 0x63, 0xd3, 0x9e, 0xe2, 0xaa, 0x77, 0x0d,
            0xfc, 0xa6, 0x68, 0xeb, 0x13, 0x4a, 0xbe, 0x08, 0x05, 0x78,
            0xb2, 0xf8, 0xd1, 0xa3, 0xa8, 0x99, 0xf5, 0xa0, 0x0a, 0xf7
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

void sha1_additional_data()
{
    boost::crypt::sha1_hash_drbg_pr rng;

    constexpr std::array<std::uint8_t, 16> entropy = {
        0x46, 0x52, 0xda, 0x57, 0x42, 0x9a, 0x76, 0xd6, 0xfe, 0x9e, 0x0e, 0x1f, 0xbb, 0x2f, 0x3c, 0xcd
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
        0x50, 0x44, 0xe6, 0xab, 0x2b, 0x55, 0x20, 0x66
    };

    constexpr std::array<std::uint8_t, 16> personalization_string = {
        0x96, 0xf1, 0x87, 0x86, 0x7c, 0x05, 0x7a, 0xe9, 0x82, 0xe0, 0x3a, 0x05, 0x6b, 0xbf, 0x0f, 0x48
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_1 = {
        0xca, 0x89, 0x0d, 0x84, 0x53, 0x82, 0x1c, 0x32, 0xc4, 0xed, 0xe3, 0xd3, 0x90, 0x2b, 0x13, 0x06
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_2 = {
        0x09, 0x9a, 0x2a, 0x45, 0x52, 0x60, 0x29, 0xfc, 0xdd, 0x2d, 0xa7, 0x4f, 0x63, 0x85, 0x00, 0xa9
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, nonce, personalization_string) == boost::crypt::state::success);
    // ** INSTANTIATE:
    //	V = da28c28db25547d1459e5952935d40c652d2f5e0375850341bcd91eef3b0a9eacf90a7ed159f4d4b2c0b1efbeaec05651851ee3f509775
    //	C = b1957c4ebf2706019352971dacd9bb7fe8583d5e0e15de09d63ecacabb30890ad52fdfca97aece42f4eed36d059f50945c1fbb0c0dfce9

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_1) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // 	V = 3e2a05e87aa688f9d1d875b84e68414216848078ed80c7341e707d36d29cd673f10d16a22b602e3231aa56f19bc500e6d2cff2fc19a2bb
    //	C = ace58c1b7185a9369788314b8e8f867e22f7d9c71c0e559308d3ce948f17dc2c78e6aa804227b24354f8a0dfa9facfe630c620048681af

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_2) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V = 54ad6e24a43198965889bbf6030c9eca46e67cf0efca63ce1bbb34ba7945f394125f635aeb7f7948f1b215ab8bbca6c007a7325f508989
    //	C = 169a17564f69eaaf820f8cc44dce9bdfb3e96976935744cf99bf5da3c78cc0bd937ad642264756db4092556037108289de3042dc57d46e

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0x68, 0x4c, 0xc1, 0x69, 0x5b, 0x5a, 0x4b, 0x5d, 0x50, 0xd7,
        0x42, 0x90, 0x52, 0x8a, 0xd5, 0x56, 0x22, 0x59, 0x86, 0x18,
        0xeb, 0x8e, 0xda, 0xf1, 0x41, 0xe4, 0x1a, 0x89, 0x06, 0xf3,
        0xbf, 0x94, 0x01, 0x73, 0x38, 0x36, 0x88, 0xa8, 0x61, 0xdd,
        0xcc, 0x56, 0x4e, 0xde, 0x0e, 0xfc, 0x3e, 0xeb, 0x3b, 0x01,
        0x89, 0x7f, 0x73, 0x85, 0x23, 0xa5, 0xfa, 0xc9, 0x98, 0x52,
        0xc4, 0x35, 0xbf, 0xed, 0x58, 0xeb, 0x4a, 0x6f, 0xd7, 0xd0,
        0xd5, 0x66, 0x9a, 0x6a, 0xaf, 0xbd, 0xc8, 0xd4, 0xff, 0xf9
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

void sha1_additional_gen_input()
{
    boost::crypt::sha1_hash_drbg_pr rng;

    constexpr std::array<std::uint8_t, 16> entropy = {
        0x8b, 0x76, 0x99, 0x15, 0x91, 0x7b, 0xbf, 0x4e, 0x4b, 0x48, 0xf2, 0x66, 0x39, 0x30, 0x61, 0x52
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
        0x17, 0xea, 0x14, 0xe8, 0xad, 0x54, 0x46, 0xaa
    };

    constexpr std::array<std::uint8_t, 16> personalization_string = {
        0x99, 0x94, 0xed, 0x56, 0xb1, 0x35, 0x5a, 0x6d, 0x60, 0x3e, 0x36, 0x6a, 0x8f, 0x9c, 0x04, 0xa9
    };

    constexpr std::array<std::uint8_t, 16> additional_input_1 = {
        0x1b, 0x8c, 0x8b, 0x88, 0xd7, 0xce, 0x96, 0xeb, 0x7a, 0xbd, 0x03, 0xb5, 0x55, 0x1c, 0xe9, 0x9d
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_1 = {
        0x36, 0x39, 0x1d, 0x0d, 0x89, 0x75, 0x10, 0xaa, 0x84, 0x4c, 0x99, 0x20, 0x48, 0x8d, 0x49, 0xf2
    };

    constexpr std::array<std::uint8_t, 16> additional_input_2 = {
        0xfa, 0xb6, 0xfc, 0x0a, 0xcb, 0x22, 0x98, 0x38, 0x65, 0xc3, 0x83, 0x62, 0x53, 0x71, 0x8f, 0x31
    };

    constexpr std::array<std::uint8_t, 16> entropy_gen_2 = {
        0x74, 0xc7, 0xb5, 0x4e, 0x9f, 0xdc, 0x82, 0x4f, 0xc8, 0xe0, 0x46, 0x36, 0x73, 0xef, 0x92, 0xbc
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, nonce, personalization_string) == boost::crypt::state::success);
    // ** INSTANTIATE:
    //	V = 1bd499277b1c3b8ea183b2a924669ab99cb7dec9ef7709b6e1f11bf3e2199b09984c869669b268de0d09128fc9b4be5fc417d1c3ed9aa6
    //	C = de0f063ebdb0219fbfe6c9b3ac9271758423ff0394779e446f74dc977aded577e109efed627abf164873af417b6589ea4293c79c83cd6d

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_1, additional_input_1) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // 	V = 5175a69940d5ffd54c444fbf42716d910785b4eb11d26b2254ee5784295a8b21e61d38c7e7fde8353b7a0be7a13a9fb3e699e902574eb9
    //	C = 2d6bf03f0da8e4d4f3c0648bae0b9be4911cf870ca8789a16886a9b9fe64338012b6feae2c889cc78553c2a6a7c9829b32a57316e14042

    BOOST_TEST(rng.generate(return_bits, 640U, entropy_gen_2, additional_input_2) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V = c35d4a033e2541a93e3e7ff5840f30f90a99775273cea47d3c16280bd36655e9314f15c43df89cd668dd79385287de9b87e5577e623354
    //	C = 9767cd1c4a51fc33f046e281aa2c5c98b116364638f46271951c38db1d246eadc92b977b0643183c39ae95184e2f147f9c8b7f5d6158d5

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0x1f, 0x07, 0x77, 0x2a, 0x46, 0x66, 0x2b, 0x37, 0x50, 0xe3,
        0x9b, 0x31, 0x91, 0xfa, 0x74, 0xc8, 0x35, 0x4f, 0x9d, 0x7e,
        0xae, 0xa5, 0x6b, 0xa0, 0xd2, 0x92, 0x72, 0xd0, 0x71, 0xef,
        0x6d, 0xa2, 0x41, 0x1c, 0xd0, 0x5b, 0x64, 0x76, 0x2e, 0x27,
        0xa7, 0x36, 0xb0, 0x88, 0xd9, 0x2d, 0xad, 0x4f, 0x22, 0x2e,
        0xfa, 0x3e, 0x3c, 0xa2, 0xbe, 0xe0, 0xd5, 0xf1, 0x40, 0x1d,
        0x7e, 0xf5, 0x3e, 0x38, 0x42, 0x13, 0x21, 0x81, 0x51, 0x1a,
        0x51, 0x59, 0xbc, 0x8e, 0xa3, 0xa6, 0xdb, 0x12, 0x15, 0xab
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

void sha1_no_reseed_additional_input()
{
    boost::crypt::sha1_hash_drbg rng;

    constexpr std::array<std::uint8_t, 16> entropy = {
        0xc3, 0xef, 0x82, 0xce, 0x24, 0x1f, 0x02, 0xe4, 0x29, 0x8b, 0x11, 0x8c, 0xa4, 0xf1, 0x62, 0x25
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
        0x15, 0xe3, 0x2a, 0xbb, 0xae, 0x6b, 0x74, 0x33
    };

    constexpr std::array<std::uint8_t, 16> additional_input_1 = {
        0x2b, 0x79, 0x00, 0x52, 0xf0, 0x9b, 0x36, 0x4d, 0x4a, 0x82, 0x67, 0xa0, 0xa7, 0xde, 0x63, 0xb8
    };

    constexpr std::array<std::uint8_t, 16> additional_input_2 = {
        0x2e, 0xe0, 0x81, 0x9a, 0x67, 0x1d, 0x07, 0xb5, 0x08, 0x5c, 0xc4, 0x6a, 0xa0, 0xe6, 0x1b, 0x56
    };

    std::array<std::uint8_t, 80> return_bits {};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    // ** INSTANTIATE:
    //	V = 062e928dbf6ef8f7b57467a2a956f4754b094b5f5a9515fe0059a35d449b74485eac06f0671eaa6ec313fc52da015f69b18cc670d9e89a
    //	C = 0fb2fcface8fe5876199565b26d3db365037da40291d67915426959d90c8beba18e3dd1961b48a1ac62b0150cdefa5dc077daf27b4cf3e

    BOOST_TEST(rng.generate(return_bits, 640U, additional_input_1) == boost::crypt::state::success);
    // ** GENERATE (FIRST CALL):
    // 	V = 15e18f888dfede7f170dbdfdd02acfab9b41259f83b27d8f548038fad5643302778fe466a1b0a63b22b39b4c59a4b7f151bec718d08a16
    //	C = 0fb2fcface8fe5876199565b26d3db365037da40291d67915426959d90c8beba18e3dd1961b48a1ac62b0150cdefa5dc077daf27b4cf3e

    BOOST_TEST(rng.generate(return_bits, 640U, additional_input_2) == boost::crypt::state::success);
    // ** GENERATE (SECOND CALL):
    //	V = 25948c835c8ec40678a71458f6feaae1eb78ffdfaccfe520a8a6ce98662cf1bc9073c28d8664f953ae0352e0b5a7ecc5577d08a0babfc3
    //	C = 0fb2fcface8fe5876199565b26d3db365037da40291d67915426959d90c8beba18e3dd1961b48a1ac62b0150cdefa5dc077daf27b4cf3e

    constexpr std::array<std::uint8_t, 80> nist_return = {
        0x58, 0x25, 0xfa, 0x1d, 0x1d, 0xc3, 0x3c, 0x64, 0xcd, 0xc8,
        0x69, 0x06, 0x82, 0xef, 0xf0, 0x60, 0x39, 0xe7, 0x95, 0x08,
        0xc3, 0xaf, 0x48, 0xe8, 0x80, 0xf8, 0x22, 0x7d, 0x5f, 0x9a,
        0xaa, 0x14, 0xb3, 0xbc, 0x76, 0xba, 0xee, 0x47, 0x7e, 0xbb,
        0xb5, 0xc4, 0x55, 0x47, 0x13, 0x41, 0x79, 0x22, 0x32, 0x57,
        0x52, 0x5e, 0x8f, 0x3a, 0xfe, 0xfb, 0x78, 0xb5, 0x9d, 0xa0,
        0x32, 0xf1, 0x00, 0x6d, 0x74, 0xc9, 0x83, 0x13, 0x75, 0xa6,
        0x77, 0xea, 0xb3, 0x23, 0x9c, 0x94, 0xeb, 0xe3, 0xf7, 0xfa
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

void sha1_error_cases()
{
    constexpr std::array<std::uint8_t, 16> entropy = {
            0xc3, 0xef, 0x82, 0xce, 0x24, 0x1f, 0x02, 0xe4, 0x29, 0x8b, 0x11, 0x8c, 0xa4, 0xf1, 0x62, 0x25
    };

    constexpr std::array<std::uint8_t, 8> nonce = {
            0x15, 0xe3, 0x2a, 0xbb, 0xae, 0x6b, 0x74, 0x33
    };

    constexpr std::array<std::uint8_t, 3> bad_entropy = {
            0xc3, 0xef, 0x82
    };

    constexpr std::array<std::uint8_t, 8> bad_nonce = {
            0x15
    };

    std::array<std::byte, 1> bad_return_container {};

    boost::crypt::sha1_hash_drbg rng;
    BOOST_TEST(rng.init(bad_entropy, bad_nonce) == boost::crypt::state::insufficient_entropy);
    BOOST_TEST(rng.generate(bad_return_container, 1) == boost::crypt::state::uninitialized);
    BOOST_TEST(rng.init(entropy, nonce) == boost::crypt::state::success);
    BOOST_TEST(rng.generate(bad_return_container, 1000000U) == boost::crypt::state::requested_too_many_bits);
    BOOST_TEST(rng.generate(bad_return_container, 1000) == boost::crypt::state::out_of_memory);
    BOOST_TEST(rng.reseed(bad_entropy) == boost::crypt::state::insufficient_entropy);

    boost::crypt::sha1_hash_drbg_pr pr_rng;
    BOOST_TEST(pr_rng.generate(bad_return_container, 1, entropy, nonce) == boost::crypt::state::uninitialized);
}

consteval bool immediate_test()
{
    boost::crypt::sha1_hash_drbg rng;

    constexpr std::array<std::byte, 16> entropy = {
            std::byte{0xc3}, std::byte{0xef}, std::byte{0x82}, std::byte{0xce},
            std::byte{0x24}, std::byte{0x1f}, std::byte{0x02}, std::byte{0xe4},
            std::byte{0x29}, std::byte{0x8b}, std::byte{0x11}, std::byte{0x8c},
            std::byte{0xa4}, std::byte{0xf1}, std::byte{0x62}, std::byte{0x25}
    };

    constexpr std::array<std::byte, 8> nonce = {
            std::byte{0x15}, std::byte{0xe3}, std::byte{0x2a}, std::byte{0xbb},
            std::byte{0xae}, std::byte{0x6b}, std::byte{0x74}, std::byte{0x33}
    };

    constexpr std::array<std::byte, 16> additional_input_1 = {
            std::byte{0x2b}, std::byte{0x79}, std::byte{0x00}, std::byte{0x52},
            std::byte{0xf0}, std::byte{0x9b}, std::byte{0x36}, std::byte{0x4d},
            std::byte{0x4a}, std::byte{0x82}, std::byte{0x67}, std::byte{0xa0},
            std::byte{0xa7}, std::byte{0xde}, std::byte{0x63}, std::byte{0xb8}
    };

    constexpr std::array<std::byte, 16> additional_input_2 = {
            std::byte{0x2e}, std::byte{0xe0}, std::byte{0x81}, std::byte{0x9a},
            std::byte{0x67}, std::byte{0x1d}, std::byte{0x07}, std::byte{0xb5},
            std::byte{0x08}, std::byte{0x5c}, std::byte{0xc4}, std::byte{0x6a},
            std::byte{0xa0}, std::byte{0xe6}, std::byte{0x1b}, std::byte{0x56}
    };

    std::span<const std::byte, 16> entropy_span {entropy};
    std::span<const std::byte, 8> nonce_span {nonce};
    std::span<const std::byte, 16> additional_input_1_span {additional_input_1};
    std::span<const std::byte, 16> additional_input_2_span {additional_input_2};

    std::array<std::byte, 80> return_bits {};
    std::span<std::byte, 80> return_bit_span {return_bits};

    // Test process is:
    // 1) Instantiate drbg
    // 2) Generate bits, do not compare
    // 3) Generate bits, compare
    // 4) Destroy drbg
    rng.init(entropy_span, nonce_span);
    // ** INSTANTIATE:
    //	V = 062e928dbf6ef8f7b57467a2a956f4754b094b5f5a9515fe0059a35d449b74485eac06f0671eaa6ec313fc52da015f69b18cc670d9e89a
    //	C = 0fb2fcface8fe5876199565b26d3db365037da40291d67915426959d90c8beba18e3dd1961b48a1ac62b0150cdefa5dc077daf27b4cf3e

    rng.generate(return_bit_span, 640U, additional_input_1_span);
    // ** GENERATE (FIRST CALL):
    // 	V = 15e18f888dfede7f170dbdfdd02acfab9b41259f83b27d8f548038fad5643302778fe466a1b0a63b22b39b4c59a4b7f151bec718d08a16
    //	C = 0fb2fcface8fe5876199565b26d3db365037da40291d67915426959d90c8beba18e3dd1961b48a1ac62b0150cdefa5dc077daf27b4cf3e

    rng.generate(return_bit_span, 640U, additional_input_2_span);
    // ** GENERATE (SECOND CALL):
    //	V = 25948c835c8ec40678a71458f6feaae1eb78ffdfaccfe520a8a6ce98662cf1bc9073c28d8664f953ae0352e0b5a7ecc5577d08a0babfc3
    //	C = 0fb2fcface8fe5876199565b26d3db365037da40291d67915426959d90c8beba18e3dd1961b48a1ac62b0150cdefa5dc077daf27b4cf3e


    constexpr std::array<std::byte, 80> nist_return = {
            std::byte{0x58}, std::byte{0x25}, std::byte{0xfa}, std::byte{0x1d},
            std::byte{0x1d}, std::byte{0xc3}, std::byte{0x3c}, std::byte{0x64},
            std::byte{0xcd}, std::byte{0xc8}, std::byte{0x69}, std::byte{0x06},
            std::byte{0x82}, std::byte{0xef}, std::byte{0xf0}, std::byte{0x60},
            std::byte{0x39}, std::byte{0xe7}, std::byte{0x95}, std::byte{0x08},
            std::byte{0xc3}, std::byte{0xaf}, std::byte{0x48}, std::byte{0xe8},
            std::byte{0x80}, std::byte{0xf8}, std::byte{0x22}, std::byte{0x7d},
            std::byte{0x5f}, std::byte{0x9a}, std::byte{0xaa}, std::byte{0x14},
            std::byte{0xb3}, std::byte{0xbc}, std::byte{0x76}, std::byte{0xba},
            std::byte{0xee}, std::byte{0x47}, std::byte{0x7e}, std::byte{0xbb},
            std::byte{0xb5}, std::byte{0xc4}, std::byte{0x55}, std::byte{0x47},
            std::byte{0x13}, std::byte{0x41}, std::byte{0x79}, std::byte{0x22},
            std::byte{0x32}, std::byte{0x57}, std::byte{0x52}, std::byte{0x5e},
            std::byte{0x8f}, std::byte{0x3a}, std::byte{0xfe}, std::byte{0xfb},
            std::byte{0x78}, std::byte{0xb5}, std::byte{0x9d}, std::byte{0xa0},
            std::byte{0x32}, std::byte{0xf1}, std::byte{0x00}, std::byte{0x6d},
            std::byte{0x74}, std::byte{0xc9}, std::byte{0x83}, std::byte{0x13},
            std::byte{0x75}, std::byte{0xa6}, std::byte{0x77}, std::byte{0xea},
            std::byte{0xb3}, std::byte{0x23}, std::byte{0x9c}, std::byte{0x94},
            std::byte{0xeb}, std::byte{0xe3}, std::byte{0xf7}, std::byte{0xfa}
    };

    for (std::size_t i {}; i < return_bits.size(); ++i)
    {
        if (!(return_bits[i] == static_cast<std::byte>(nist_return[i])))
        {
            return false;
        }
    }

    return true;
}

int main()
{
    sha_1_basic_correctness();
    sha1_pr_false();
    sha_1_pr_true();
    sha1_additional_data();
    sha1_additional_gen_input();
    sha1_no_reseed_additional_input();
    sha1_error_cases();

    static_assert(immediate_test());

    return boost::report_errors();
}
