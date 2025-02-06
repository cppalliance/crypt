// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT2_AES_DETAIL_CIPHER_HPP
#define BOOST_CRYPT2_AES_DETAIL_CIPHER_HPP

#include <boost/crypt2/aes/cipher_mode.hpp>
#include <boost/crypt2/detail/config.hpp>
#include <boost/crypt2/detail/compat.hpp>
#include <boost/crypt2/detail/concepts.hpp>
#include <boost/crypt2/detail/clear_mem.hpp>
#include <boost/crypt2/state.hpp>

namespace boost::crypt::aes_detail {

inline constexpr compat::array<compat::byte, 256> sbox = {
        compat::byte{0x63}, compat::byte{0x7c}, compat::byte{0x77}, compat::byte{0x7b}, compat::byte{0xf2}, compat::byte{0x6b}, compat::byte{0x6f}, compat::byte{0xc5}, compat::byte{0x30}, compat::byte{0x01}, compat::byte{0x67}, compat::byte{0x2b}, compat::byte{0xfe}, compat::byte{0xd7}, compat::byte{0xab}, compat::byte{0x76},
        compat::byte{0xca}, compat::byte{0x82}, compat::byte{0xc9}, compat::byte{0x7d}, compat::byte{0xfa}, compat::byte{0x59}, compat::byte{0x47}, compat::byte{0xf0}, compat::byte{0xad}, compat::byte{0xd4}, compat::byte{0xa2}, compat::byte{0xaf}, compat::byte{0x9c}, compat::byte{0xa4}, compat::byte{0x72}, compat::byte{0xc0},
        compat::byte{0xb7}, compat::byte{0xfd}, compat::byte{0x93}, compat::byte{0x26}, compat::byte{0x36}, compat::byte{0x3f}, compat::byte{0xf7}, compat::byte{0xcc}, compat::byte{0x34}, compat::byte{0xa5}, compat::byte{0xe5}, compat::byte{0xf1}, compat::byte{0x71}, compat::byte{0xd8}, compat::byte{0x31}, compat::byte{0x15},
        compat::byte{0x04}, compat::byte{0xc7}, compat::byte{0x23}, compat::byte{0xc3}, compat::byte{0x18}, compat::byte{0x96}, compat::byte{0x05}, compat::byte{0x9a}, compat::byte{0x07}, compat::byte{0x12}, compat::byte{0x80}, compat::byte{0xe2}, compat::byte{0xeb}, compat::byte{0x27}, compat::byte{0xb2}, compat::byte{0x75},
        compat::byte{0x09}, compat::byte{0x83}, compat::byte{0x2c}, compat::byte{0x1a}, compat::byte{0x1b}, compat::byte{0x6e}, compat::byte{0x5a}, compat::byte{0xa0}, compat::byte{0x52}, compat::byte{0x3b}, compat::byte{0xd6}, compat::byte{0xb3}, compat::byte{0x29}, compat::byte{0xe3}, compat::byte{0x2f}, compat::byte{0x84},
        compat::byte{0x53}, compat::byte{0xd1}, compat::byte{0x00}, compat::byte{0xed}, compat::byte{0x20}, compat::byte{0xfc}, compat::byte{0xb1}, compat::byte{0x5b}, compat::byte{0x6a}, compat::byte{0xcb}, compat::byte{0xbe}, compat::byte{0x39}, compat::byte{0x4a}, compat::byte{0x4c}, compat::byte{0x58}, compat::byte{0xcf},
        compat::byte{0xd0}, compat::byte{0xef}, compat::byte{0xaa}, compat::byte{0xfb}, compat::byte{0x43}, compat::byte{0x4d}, compat::byte{0x33}, compat::byte{0x85}, compat::byte{0x45}, compat::byte{0xf9}, compat::byte{0x02}, compat::byte{0x7f}, compat::byte{0x50}, compat::byte{0x3c}, compat::byte{0x9f}, compat::byte{0xa8},
        compat::byte{0x51}, compat::byte{0xa3}, compat::byte{0x40}, compat::byte{0x8f}, compat::byte{0x92}, compat::byte{0x9d}, compat::byte{0x38}, compat::byte{0xf5}, compat::byte{0xbc}, compat::byte{0xb6}, compat::byte{0xda}, compat::byte{0x21}, compat::byte{0x10}, compat::byte{0xff}, compat::byte{0xf3}, compat::byte{0xd2},
        compat::byte{0xcd}, compat::byte{0x0c}, compat::byte{0x13}, compat::byte{0xec}, compat::byte{0x5f}, compat::byte{0x97}, compat::byte{0x44}, compat::byte{0x17}, compat::byte{0xc4}, compat::byte{0xa7}, compat::byte{0x7e}, compat::byte{0x3d}, compat::byte{0x64}, compat::byte{0x5d}, compat::byte{0x19}, compat::byte{0x73},
        compat::byte{0x60}, compat::byte{0x81}, compat::byte{0x4f}, compat::byte{0xdc}, compat::byte{0x22}, compat::byte{0x2a}, compat::byte{0x90}, compat::byte{0x88}, compat::byte{0x46}, compat::byte{0xee}, compat::byte{0xb8}, compat::byte{0x14}, compat::byte{0xde}, compat::byte{0x5e}, compat::byte{0x0b}, compat::byte{0xdb},
        compat::byte{0xe0}, compat::byte{0x32}, compat::byte{0x3a}, compat::byte{0x0a}, compat::byte{0x49}, compat::byte{0x06}, compat::byte{0x24}, compat::byte{0x5c}, compat::byte{0xc2}, compat::byte{0xd3}, compat::byte{0xac}, compat::byte{0x62}, compat::byte{0x91}, compat::byte{0x95}, compat::byte{0xe4}, compat::byte{0x79},
        compat::byte{0xe7}, compat::byte{0xc8}, compat::byte{0x37}, compat::byte{0x6d}, compat::byte{0x8d}, compat::byte{0xd5}, compat::byte{0x4e}, compat::byte{0xa9}, compat::byte{0x6c}, compat::byte{0x56}, compat::byte{0xf4}, compat::byte{0xea}, compat::byte{0x65}, compat::byte{0x7a}, compat::byte{0xae}, compat::byte{0x08},
        compat::byte{0xba}, compat::byte{0x78}, compat::byte{0x25}, compat::byte{0x2e}, compat::byte{0x1c}, compat::byte{0xa6}, compat::byte{0xb4}, compat::byte{0xc6}, compat::byte{0xe8}, compat::byte{0xdd}, compat::byte{0x74}, compat::byte{0x1f}, compat::byte{0x4b}, compat::byte{0xbd}, compat::byte{0x8b}, compat::byte{0x8a},
        compat::byte{0x70}, compat::byte{0x3e}, compat::byte{0xb5}, compat::byte{0x66}, compat::byte{0x48}, compat::byte{0x03}, compat::byte{0xf6}, compat::byte{0x0e}, compat::byte{0x61}, compat::byte{0x35}, compat::byte{0x57}, compat::byte{0xb9}, compat::byte{0x86}, compat::byte{0xc1}, compat::byte{0x1d}, compat::byte{0x9e},
        compat::byte{0xe1}, compat::byte{0xf8}, compat::byte{0x98}, compat::byte{0x11}, compat::byte{0x69}, compat::byte{0xd9}, compat::byte{0x8e}, compat::byte{0x94}, compat::byte{0x9b}, compat::byte{0x1e}, compat::byte{0x87}, compat::byte{0xe9}, compat::byte{0xce}, compat::byte{0x55}, compat::byte{0x28}, compat::byte{0xdf},
        compat::byte{0x8c}, compat::byte{0xa1}, compat::byte{0x89}, compat::byte{0x0d}, compat::byte{0xbf}, compat::byte{0xe6}, compat::byte{0x42}, compat::byte{0x68}, compat::byte{0x41}, compat::byte{0x99}, compat::byte{0x2d}, compat::byte{0x0f}, compat::byte{0xb0}, compat::byte{0x54}, compat::byte{0xbb}, compat::byte{0x16}
};

inline constexpr compat::array<compat::byte, 256> rsbox = {
        compat::byte{0x52}, compat::byte{0x09}, compat::byte{0x6a}, compat::byte{0xd5}, compat::byte{0x30}, compat::byte{0x36}, compat::byte{0xa5}, compat::byte{0x38}, compat::byte{0xbf}, compat::byte{0x40}, compat::byte{0xa3}, compat::byte{0x9e}, compat::byte{0x81}, compat::byte{0xf3}, compat::byte{0xd7}, compat::byte{0xfb},
        compat::byte{0x7c}, compat::byte{0xe3}, compat::byte{0x39}, compat::byte{0x82}, compat::byte{0x9b}, compat::byte{0x2f}, compat::byte{0xff}, compat::byte{0x87}, compat::byte{0x34}, compat::byte{0x8e}, compat::byte{0x43}, compat::byte{0x44}, compat::byte{0xc4}, compat::byte{0xde}, compat::byte{0xe9}, compat::byte{0xcb},
        compat::byte{0x54}, compat::byte{0x7b}, compat::byte{0x94}, compat::byte{0x32}, compat::byte{0xa6}, compat::byte{0xc2}, compat::byte{0x23}, compat::byte{0x3d}, compat::byte{0xee}, compat::byte{0x4c}, compat::byte{0x95}, compat::byte{0x0b}, compat::byte{0x42}, compat::byte{0xfa}, compat::byte{0xc3}, compat::byte{0x4e},
        compat::byte{0x08}, compat::byte{0x2e}, compat::byte{0xa1}, compat::byte{0x66}, compat::byte{0x28}, compat::byte{0xd9}, compat::byte{0x24}, compat::byte{0xb2}, compat::byte{0x76}, compat::byte{0x5b}, compat::byte{0xa2}, compat::byte{0x49}, compat::byte{0x6d}, compat::byte{0x8b}, compat::byte{0xd1}, compat::byte{0x25},
        compat::byte{0x72}, compat::byte{0xf8}, compat::byte{0xf6}, compat::byte{0x64}, compat::byte{0x86}, compat::byte{0x68}, compat::byte{0x98}, compat::byte{0x16}, compat::byte{0xd4}, compat::byte{0xa4}, compat::byte{0x5c}, compat::byte{0xcc}, compat::byte{0x5d}, compat::byte{0x65}, compat::byte{0xb6}, compat::byte{0x92},
        compat::byte{0x6c}, compat::byte{0x70}, compat::byte{0x48}, compat::byte{0x50}, compat::byte{0xfd}, compat::byte{0xed}, compat::byte{0xb9}, compat::byte{0xda}, compat::byte{0x5e}, compat::byte{0x15}, compat::byte{0x46}, compat::byte{0x57}, compat::byte{0xa7}, compat::byte{0x8d}, compat::byte{0x9d}, compat::byte{0x84},
        compat::byte{0x90}, compat::byte{0xd8}, compat::byte{0xab}, compat::byte{0x00}, compat::byte{0x8c}, compat::byte{0xbc}, compat::byte{0xd3}, compat::byte{0x0a}, compat::byte{0xf7}, compat::byte{0xe4}, compat::byte{0x58}, compat::byte{0x05}, compat::byte{0xb8}, compat::byte{0xb3}, compat::byte{0x45}, compat::byte{0x06},
        compat::byte{0xd0}, compat::byte{0x2c}, compat::byte{0x1e}, compat::byte{0x8f}, compat::byte{0xca}, compat::byte{0x3f}, compat::byte{0x0f}, compat::byte{0x02}, compat::byte{0xc1}, compat::byte{0xaf}, compat::byte{0xbd}, compat::byte{0x03}, compat::byte{0x01}, compat::byte{0x13}, compat::byte{0x8a}, compat::byte{0x6b},
        compat::byte{0x3a}, compat::byte{0x91}, compat::byte{0x11}, compat::byte{0x41}, compat::byte{0x4f}, compat::byte{0x67}, compat::byte{0xdc}, compat::byte{0xea}, compat::byte{0x97}, compat::byte{0xf2}, compat::byte{0xcf}, compat::byte{0xce}, compat::byte{0xf0}, compat::byte{0xb4}, compat::byte{0xe6}, compat::byte{0x73},
        compat::byte{0x96}, compat::byte{0xac}, compat::byte{0x74}, compat::byte{0x22}, compat::byte{0xe7}, compat::byte{0xad}, compat::byte{0x35}, compat::byte{0x85}, compat::byte{0xe2}, compat::byte{0xf9}, compat::byte{0x37}, compat::byte{0xe8}, compat::byte{0x1c}, compat::byte{0x75}, compat::byte{0xdf}, compat::byte{0x6e},
        compat::byte{0x47}, compat::byte{0xf1}, compat::byte{0x1a}, compat::byte{0x71}, compat::byte{0x1d}, compat::byte{0x29}, compat::byte{0xc5}, compat::byte{0x89}, compat::byte{0x6f}, compat::byte{0xb7}, compat::byte{0x62}, compat::byte{0x0e}, compat::byte{0xaa}, compat::byte{0x18}, compat::byte{0xbe}, compat::byte{0x1b},
        compat::byte{0xfc}, compat::byte{0x56}, compat::byte{0x3e}, compat::byte{0x4b}, compat::byte{0xc6}, compat::byte{0xd2}, compat::byte{0x79}, compat::byte{0x20}, compat::byte{0x9a}, compat::byte{0xdb}, compat::byte{0xc0}, compat::byte{0xfe}, compat::byte{0x78}, compat::byte{0xcd}, compat::byte{0x5a}, compat::byte{0xf4},
        compat::byte{0x1f}, compat::byte{0xdd}, compat::byte{0xa8}, compat::byte{0x33}, compat::byte{0x88}, compat::byte{0x07}, compat::byte{0xc7}, compat::byte{0x31}, compat::byte{0xb1}, compat::byte{0x12}, compat::byte{0x10}, compat::byte{0x59}, compat::byte{0x27}, compat::byte{0x80}, compat::byte{0xec}, compat::byte{0x5f},
        compat::byte{0x60}, compat::byte{0x51}, compat::byte{0x7f}, compat::byte{0xa9}, compat::byte{0x19}, compat::byte{0xb5}, compat::byte{0x4a}, compat::byte{0x0d}, compat::byte{0x2d}, compat::byte{0xe5}, compat::byte{0x7a}, compat::byte{0x9f}, compat::byte{0x93}, compat::byte{0xc9}, compat::byte{0x9c}, compat::byte{0xef},
        compat::byte{0xa0}, compat::byte{0xe0}, compat::byte{0x3b}, compat::byte{0x4d}, compat::byte{0xae}, compat::byte{0x2a}, compat::byte{0xf5}, compat::byte{0xb0}, compat::byte{0xc8}, compat::byte{0xeb}, compat::byte{0xbb}, compat::byte{0x3c}, compat::byte{0x83}, compat::byte{0x53}, compat::byte{0x99}, compat::byte{0x61},
        compat::byte{0x17}, compat::byte{0x2b}, compat::byte{0x04}, compat::byte{0x7e}, compat::byte{0xba}, compat::byte{0x77}, compat::byte{0xd6}, compat::byte{0x26}, compat::byte{0xe1}, compat::byte{0x69}, compat::byte{0x14}, compat::byte{0x63}, compat::byte{0x55}, compat::byte{0x21}, compat::byte{0x0c}, compat::byte{0x7d}
};

inline constexpr compat::array<compat::byte, 11> Rcon = {
        compat::byte{0x8d}, compat::byte{0x01}, compat::byte{0x02}, compat::byte{0x04}, compat::byte{0x08}, compat::byte{0x10}, compat::byte{0x20}, compat::byte{0x40}, compat::byte{0x80}, compat::byte{0x1b}, compat::byte{0x36}
};

} // namespace aes detail

#endif // BOOST_CRYPT2_AES_DETAIL_CIPHER_HPP
