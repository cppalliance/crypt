// Copyright 2025 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/crypt2/drbg/sha1_drbg.hpp>
#include <boost/crypt2/drbg/sha512_drbg.hpp>
#include <boost/crypt2/drbg/sha3_256_drbg.hpp>
#include <iostream>
#include <exception>
#include <string>
#include <vector>
#include <cstdint>
#include <string>
#include <span>
#include <string_view>
#include <vector>
#include <type_traits>

using namespace boost::crypt;

// Type list to store hasher types
template<typename... Ts>
struct type_list {};

// Helper to iterate over types
template<typename TypeList, template<typename> class F>
struct for_each_type;

template<template<typename> class F, typename... Ts>
struct for_each_type<type_list<Ts...>, F> {
    static void apply(const std::uint8_t* data, std::size_t size) {
        (F<Ts>::apply(data, size), ...);
    }
};

// Functor to process each hash type
template<typename DRBGType>
struct process_hash {
    static void apply(const std::uint8_t* data, std::size_t size) {
        auto c_data = reinterpret_cast<const char*>(data);
        std::string c_data_str{c_data, size};
        std::span<const std::uint8_t> c_data_span{data, size};
        std::string_view c_data_str_view{c_data_str};

        DRBGType drbg_tester;
        drbg_tester.init(c_data_span, c_data_span, c_data_span);
        std::vector<std::byte> return_vector(size);
        [[maybe_unused]] const auto code = drbg_tester.generate(return_vector, size);
        drbg_tester.reseed(c_data_str, c_data_str_view);
        drbg_tester.generate(return_vector, size);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size == 0) {
        return 0;
    }

    try {
        using hasher_types = type_list<
                sha1_hmac_drbg,
                sha512_hmac_drbg,
                sha3_256_hmac_drbg,
                sha1_hash_drbg,
                sha512_hash_drbg,
                sha3_256_hash_drbg
        >;

        for_each_type<hasher_types, process_hash>::apply(data, size);
    }
    catch (...) {
        return 0; // Silent failure for fuzzing
    }

    return 0;
}
