// Copyright 2024 Matt Borland
// Copyright 2024 Christopher Kormanyos
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/drbg/sha512_drbg.hpp>
#include "test_nist_cavs_detail.hpp"

auto main() -> int
{
    bool result_is_ok { true };

    {
        nist::cavs::test_vector_container_drbg_no_reseed test_vectors {};

        BOOST_TEST(nist::cavs::detail::parse_file_drbg<nist::cavs::detail::test_type::drbg_no_reseed>("sha512_noreseed.fax", test_vectors));

        result_is_ok = (nist::cavs::test_vectors_drbg_no_reseed<boost::crypt::sha512_hmac_drbg>(test_vectors) && result_is_ok);

        BOOST_TEST(result_is_ok);
    }

    {
        nist::cavs::test_vector_container_drbg_pr_false test_vectors {};

        BOOST_TEST(nist::cavs::detail::parse_file_drbg<nist::cavs::detail::test_type::drbg_pr_false>("sha512_pr_false.fax", test_vectors));

        result_is_ok = (nist::cavs::test_vectors_drbg_pr_false<boost::crypt::sha512_hmac_drbg>(test_vectors));

        BOOST_TEST(result_is_ok);
    }

    {
        nist::cavs::test_vector_container_drbg_pr_true test_vectors {};

        BOOST_TEST(nist::cavs::detail::parse_file_drbg<nist::cavs::detail::test_type::drbg_pr_true>("sha512_pr_true.fax", test_vectors));

        result_is_ok = (nist::cavs::test_vectors_drbg_pr_true<boost::crypt::sha512_hmac_drbg_pr>(test_vectors));

        BOOST_TEST(result_is_ok);
    }

    return boost::report_errors();
}
