// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_TEST_GENERATE_RANDOM_STRINGS
#define BOOST_CRYPT_TEST_GENERATE_RANDOM_STRINGS

#include <random>
#include <cstdlib>
#include <ctime>
#include <cstring>

static std::mt19937_64 string_rng(42);

namespace boost {
namespace crypt {

inline void generate_random_string(char* str, std::size_t length)
{

    const char charset[] = "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";

    const std::size_t charset_size = sizeof(charset) - 1;

    std::uniform_int_distribution<std::size_t> dist(0, charset_size);

    for (std::size_t i = 0; i < length - 1; ++i)
    {
        const auto index = dist(string_rng);
        str[i] = charset[index];
    }

    str[length - 1] = '\0';
}

inline void generate_random_string(char16_t* str, std::size_t length)
{
    const char16_t charset[] = u"0123456789"
                               u"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               u"abcdefghijklmnopqrstuvwxyz";

    const std::size_t charset_size = std::char_traits<char16_t>::length(charset);

    std::uniform_int_distribution<std::size_t> dist(0, charset_size - 1);

    for (std::size_t i = 0; i < length - 1; ++i)
    {
        const auto index = dist(string_rng);
        str[i] = charset[index];
    }

    str[length - 1] = u'\0';
}

inline void generate_random_string(char32_t* str, std::size_t length)
{
    const char32_t charset[] = U"0123456789"
                               U"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               U"abcdefghijklmnopqrstuvwxyz";

    const std::size_t charset_size = std::char_traits<char32_t>::length(charset);

    std::uniform_int_distribution<std::size_t> dist(0, charset_size - 1);

    for (std::size_t i = 0; i < length - 1; ++i)
    {
        const auto index = dist(string_rng);
        str[i] = charset[index];
    }

    str[length - 1] = u'\0';
}

inline void generate_random_string(wchar_t* str, std::size_t length)
{
    const wchar_t charset[] = L"0123456789"
                              L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              L"abcdefghijklmnopqrstuvwxyz";

    const std::size_t charset_size = std::char_traits<wchar_t>::length(charset);

    std::uniform_int_distribution<std::size_t> dist(0, charset_size - 1);

    for (std::size_t i = 0; i < length - 1; ++i)
    {
        const auto index = dist(string_rng);
        str[i] = charset[index];
    }

    str[length - 1] = u'\0';
}

} // Namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_TEST_GENERATE_RANDOM_STRINGS
