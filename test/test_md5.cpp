// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Start with the sample hashes from wiki

#include <boost/crypt/hash/md5.hpp>
#include <boost/core/lightweight_test.hpp>
#include <string>
#include <array>

void basic_tests()
{
    const auto message_1_result {boost::crypt::md5("The quick brown fox jumps over the lazy dog")};
    BOOST_TEST_EQ(message_1_result[0], 0x9e107d9d);
    BOOST_TEST_EQ(message_1_result[1], 0x372bb682);
    BOOST_TEST_EQ(message_1_result[2], 0x6bd81d35);
    BOOST_TEST_EQ(message_1_result[3], 0x42a419d6);

    const auto message_2_result {boost::crypt::md5("The quick brown fox jumps over the lazy dog.")};
    BOOST_TEST_EQ(message_2_result[0], 0xe4d909c2);
    BOOST_TEST_EQ(message_2_result[1], 0x90d0fb1c);
    BOOST_TEST_EQ(message_2_result[2], 0xa068ffad);
    BOOST_TEST_EQ(message_2_result[3], 0xdf22cbd0);

    const auto message_3_result {boost::crypt::md5("")};
    BOOST_TEST_EQ(message_3_result[0], 0xd41d8cd9);
    BOOST_TEST_EQ(message_3_result[1], 0x8f00b204);
    BOOST_TEST_EQ(message_3_result[2], 0xe9800998);
    BOOST_TEST_EQ(message_3_result[3], 0xecf8427e);
}

void string_test()
{
    std::string message_1 {"The quick brown fox jumps over the lazy dog"};
    const auto message_1_result {boost::crypt::md5(message_1)};
    BOOST_TEST_EQ(message_1_result[0], 0x9e107d9d);
    BOOST_TEST_EQ(message_1_result[1], 0x372bb682);
    BOOST_TEST_EQ(message_1_result[2], 0x6bd81d35);
    BOOST_TEST_EQ(message_1_result[3], 0x42a419d6);

    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    std::string_view view_1 {message_1};
    const auto view_1_result {boost::crypt::md5(view_1)};
    BOOST_TEST_EQ(view_1_result[0], 0x9e107d9d);
    BOOST_TEST_EQ(view_1_result[1], 0x372bb682);
    BOOST_TEST_EQ(view_1_result[2], 0x6bd81d35);
    BOOST_TEST_EQ(view_1_result[3], 0x42a419d6);
    #endif

    std::string message_2 {"The quick brown fox jumps over the lazy dog."};
    const auto message_2_result {boost::crypt::md5(message_2.begin(), message_2.end())};
    BOOST_TEST_EQ(message_2_result[0], 0xe4d909c2);
    BOOST_TEST_EQ(message_2_result[1], 0x90d0fb1c);
    BOOST_TEST_EQ(message_2_result[2], 0xa068ffad);
    BOOST_TEST_EQ(message_2_result[3], 0xdf22cbd0);
}

void bad_input()
{
    const auto null_message {boost::crypt::md5(nullptr)};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    std::string message_1 {"The quick brown fox jumps over the lazy dog"};
    const auto message_1_result {boost::crypt::md5(message_1.begin(), message_1.begin())};
    BOOST_TEST_EQ(message_1_result[0], 0x0);
    BOOST_TEST_EQ(message_1_result[1], 0x0);
    BOOST_TEST_EQ(message_1_result[2], 0x0);
    BOOST_TEST_EQ(message_1_result[3], 0x0);
}

void test_class()
{
    boost::crypt::detail::md5 hasher;
    constexpr auto msg = "The quick brown fox jumps over the lazy dog";
    hasher.process_bytes(msg, std::strlen(msg));
    std::array<std::uint32_t, 4> message_1_result {};
    hasher.get_digest(message_1_result.begin(), message_1_result.size());

    BOOST_TEST_EQ(message_1_result[0], 0x9e107d9d);
    BOOST_TEST_EQ(message_1_result[1], 0x372bb682);
    BOOST_TEST_EQ(message_1_result[2], 0x6bd81d35);
    BOOST_TEST_EQ(message_1_result[3], 0x42a419d6);
}


int main()
{
    basic_tests();
    string_test();
    bad_input();

    test_class();

    return boost::report_errors();
}
