// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc5652#section-6.3

#ifndef BOOST_CRYPT2_AES_DETAIL_PKCS7_HPP
#define BOOST_CRYPT2_AES_DETAIL_PKCS7_HPP

#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>

namespace boost::crypt::aes_detail {

template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto pkcs7(
        compat::span<const compat::byte, Extent> message,
        compat::array<compat::byte, 16>& padded_message) noexcept -> void
{
    const auto pad_num {static_cast<compat::byte>(16U - message.size())};

    auto message_begin {message.begin()};
    auto message_end {message.end()};
    auto padded_message_begin {padded_message.begin()};

    while (message_begin != message_end)
    {
        *padded_message_begin++ = *message_begin++;
    }

    const auto padded_message_end {padded_message.end()};
    while (padded_message_begin != padded_message_end)
    {
        *padded_message_begin++ = pad_num;
    }
}

} // namespace boost::crypt::aes_detail

#endif //BOOST_CRYPT2_AES_DETAIL_PKCS7_HPP
