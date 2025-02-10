// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/aes/detail/pkcs7.hpp>
#include <boost/core/lightweight_test.hpp>
#include <cstddef>
#include <vector>
#include <span>

void test(std::size_t length)
{
    std::array<std::byte, 16U> padded_message {};
    std::vector<std::byte> original_message {};

    for (std::size_t i {}; i < length; ++i)
    {
        original_message.emplace_back(std::byte{42});
    }

    std::span<const std::byte> original_message_span {original_message.begin(), original_message.end()};
    boost::crypt::aes_detail::pkcs7(original_message_span, padded_message);

    auto iter {padded_message.crbegin()};
    std::size_t counter {};
    while (iter != padded_message.crend())
    {
        if (*iter++ == std::byte{42})
        {
            break;
        }

        counter++;
    }

    BOOST_TEST_EQ(counter, 16U - length);

    for (std::size_t i {}; i < length; ++i)
    {
        BOOST_TEST(original_message[i] == padded_message[i]);
    }
}

int main()
{
    for (std::size_t i {}; i <= 16; ++i)
    {
        test(i);
    }

    return boost::report_errors();
}
