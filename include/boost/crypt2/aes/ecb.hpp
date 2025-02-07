// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_AES_ECB_HPP
#define BOOST_CRYPT2_AES_ECB_HPP

#include <boost/crypt2/aes/cipher_mode.hpp>
#include <boost/crypt2/aes/detail/cipher.hpp>
#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/detail/assert.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt {

namespace aes_detail {

template <compat::size_t Nr>
class ecb_impl {
private:

    static constexpr compat::size_t key_length_bytes {Nr == 10 ? 16 :
                                                      Nr == 12 ? 24 :
                                                      Nr == 14 ? 32 : 0};

    static constexpr compat::size_t block_length_bytes {16U};

    static_assert(key_length_bytes != 0, "Invalid key length");

    cipher<Nr> block_cipher;

    bool initialized {false};

public:

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ecb_impl() noexcept = default;

    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR ~ecb_impl() noexcept = default;

    template <compat::size_t Extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto init(compat::span<const compat::byte, Extent> key) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto init(SizedRange&& key) noexcept -> state;

    template <compat::size_t Extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
    encrypt_no_padding(compat::span<compat::byte, Extent> message) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto encrypt_no_padding(SizedRange&& message) noexcept -> state;

    template <compat::size_t Extent>
    BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto
    decrypt_no_padding(compat::span<compat::byte, Extent> ciphertext) noexcept -> state;

    template <concepts::sized_range SizedRange>
    BOOST_CRYPT_GPU_ENABLED auto decrypt_no_padding(SizedRange&& ciphertext) noexcept -> state;
};

template <compat::size_t Nr>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto ecb_impl<Nr>::init(
        compat::span<const compat::byte, Extent> key) noexcept -> state
{
    if (key.size() < key_length_bytes)
    {
        return state::insufficient_key_length;
    }

    const auto fixed_key {key.template first<key_length_bytes>()};
    BOOST_CRYPT_ASSERT(fixed_key.size_bytes() == key_length_bytes);

    block_cipher.init(fixed_key);

    initialized = true;

    return state::success;
}

template <compat::size_t Nr>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto ecb_impl<Nr>::init(SizedRange&& key) noexcept -> state
{
    const auto key_span {compat::make_span(key)};
    if (key_span.size_bytes() < key_length_bytes)
    {
        return state::insufficient_key_length;
    }

    const auto byte_key_span {compat::as_bytes(key_span)};
    const auto fixed_key {byte_key_span.template first<key_length_bytes>()};

    block_cipher.init(fixed_key);

    initialized = true;

    return state::success;
}

template <compat::size_t Nr>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto ecb_impl<Nr>::encrypt_no_padding(
        compat::span<compat::byte, Extent> message) noexcept -> state
{
    if (message.size() % block_length_bytes != 0)
    {
        return state::incorrect_message_length;
    }
    if (!initialized)
    {
        return state::uninitialized;
    }

    auto message_begin {message.begin()};
    const auto message_end {message.end()};
    while (message_begin != message_end)
    {
        auto fixed_span {compat::span<compat::byte, block_length_bytes>(message_begin, message_begin + block_length_bytes)};
        block_cipher.block_cipher(fixed_span);
        message_begin += block_length_bytes;
    }

    return state::success;
}

template <compat::size_t Nr>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto ecb_impl<Nr>::encrypt_no_padding(
        SizedRange&& message) noexcept -> state
{
    auto message_span {compat::make_span(message)};
    return encrypt_no_padding(compat::as_writable_bytes(message_span));
}

template <compat::size_t Nr>
template <compat::size_t Extent>
BOOST_CRYPT_GPU_ENABLED_CONSTEXPR auto ecb_impl<Nr>::decrypt_no_padding(
        compat::span<compat::byte, Extent> ciphertext) noexcept -> state
{
    if (ciphertext.size() % block_length_bytes != 0)
    {
        return state::incorrect_message_length;
    }
    if (!initialized)
    {
        return state::uninitialized;
    }

    auto ciphertext_begin {ciphertext.begin()};
    const auto ciphertext_end {ciphertext.end()};
    while (ciphertext_begin != ciphertext_end)
    {
        auto fixed_span {compat::span<compat::byte, block_length_bytes>(ciphertext_begin, ciphertext_begin + block_length_bytes)};
        block_cipher.inverse_block_cipher(fixed_span);
        ciphertext_begin += block_length_bytes;
    }

    return state::success;
}

template <compat::size_t Nr>
template <concepts::sized_range SizedRange>
BOOST_CRYPT_GPU_ENABLED auto ecb_impl<Nr>::decrypt_no_padding(
        SizedRange&& ciphertext) noexcept -> state
{
    auto ciphertext_span {compat::make_span(ciphertext)};
    return encrypt_no_padding(compat::as_writable_bytes(ciphertext_span));
}

} // namespace aes_detail

template <>
class aes128<aes_cipher_mode::ecb> : public aes_detail::ecb_impl<10> {};

template <>
class aes192<aes_cipher_mode::ecb> : public aes_detail::ecb_impl<12> {};

template <>
class aes256<aes_cipher_mode::ecb> : public aes_detail::ecb_impl<14> {};

} // namespace boost::crypt

#endif // BOOST_CRYPT2_AES_ECB_HPP
