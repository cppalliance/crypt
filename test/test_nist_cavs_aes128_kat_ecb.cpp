// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/aes/ecb.hpp>
#include "test_nist_cavs_detail.hpp"
#include <string>
#include <vector>
#include <iostream>

auto main() -> int
{
    bool result_is_ok { true };

    const std::vector<std::string> files_to_test = {
        "ECBGFSbox128.rsp",
        "ECBKeySbox128.rsp",
        "ECBVarKey128.rsp",
        "ECBVarTxt128.rsp",
        "ECBGFSbox128_20.rsp",
        "ECBKeySbox128_20.rsp",
        "ECBVarKey128_20.rsp",
        "ECBVarTxt128_20.rsp"
    };

    for (const auto& file : files_to_test)
    {
        nist::cavs::test_vector_container_aes test_vectors {};

        if (!BOOST_TEST(nist::cavs::detail::parse_file_aes(file, test_vectors)))
        {
            // LCOV_EXCL_START
            std::cerr << "Failed to open file: " << file << std::endl;
            continue;
            // LCOV_EXCL_STOP
        }

        result_is_ok = (nist::cavs::test_vectors_aes_kat<boost::crypt::aes_cipher_mode::ecb, boost::crypt::aes128<boost::crypt::aes_cipher_mode::ecb>>(test_vectors) && result_is_ok);

        if (!BOOST_TEST(result_is_ok))
        {
            // LCOV_EXCL_START
            std::cerr << "Failure from file: " << file << std::endl;
            result_is_ok = true;
            // LCOV_EXCL_STOP
        }
    }

    return boost::report_errors();
}
