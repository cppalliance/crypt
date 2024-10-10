//  Copyright (c) 2024 Matt Borland
//  Use, modification and distribution are subject to the
//  Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
//  Regular use of std::numeric_limits functions can not be used on
//  GPU platforms like CUDA since they are missing the __device__ marker
//  and libcu++ does not provide something analogous.
//  Rather than using giant if else blocks make our own version of numeric limits
//
//  On the CUDA NVRTC platform we use a best attempt at emulating the functions
//  and values since we do not have any macros to go off of.
//  Use the values as found on GCC 11.4 RHEL 9.4 x64

#ifndef BOOST_CRYPT_UTILITY_LIMITS_HPP
#define BOOST_CRYPT_UTILITY_LIMITS_HPP

#include <boost/crypt/utility/config.hpp>

#if !defined(BOOST_CRYPT_HAS_NVRTC) && !defined(BOOST_CRYPT_BUILD_MODULE)

#include <type_traits>
#include <limits>
#include <climits>
#include <cfloat>

#endif

namespace boost {
namespace crypt {

template <typename T>
struct numeric_limits
#ifndef BOOST_CRYPT_HAS_NVRTC
        : public std::numeric_limits<T> {};
#else
{};
#endif

#if defined(BOOST_CRYPT_HAS_CUDA) && !defined(BOOST_CRYPT_HAS_NVRTC)

template <>
struct numeric_limits<float>
{
    static constexpr bool is_specialized = std::numeric_limits<float>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<float>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<float>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<float>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<float>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<float>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<float>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<float>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<float>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<float>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<float>::is_modulo;
    static constexpr int digits = std::numeric_limits<float>::digits;
    static constexpr int digits10 = std::numeric_limits<float>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<float>::max_digits10;
    static constexpr int radix = std::numeric_limits<float>::radix;
    static constexpr int min_exponent = std::numeric_limits<float>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<float>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<float>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<float>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<float>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<float>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr float (min)         () { return FLT_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float (max)         () { return FLT_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float lowest        () { return -FLT_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float epsilon       () { return FLT_EPSILON; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float round_error   () { return 0.5F; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float infinity      () { return static_cast<float>(INFINITY); }
    BOOST_CRYPT_GPU_ENABLED static constexpr float quiet_NaN     () { return static_cast<float>(NAN); }
    BOOST_CRYPT_GPU_ENABLED static constexpr float signaling_NaN ()
    {
        #ifdef FLT_SNAN
        return FLT_SNAN;
        #else
        return static_cast<float>(NAN);
        #endif
    }
    BOOST_CRYPT_GPU_ENABLED static constexpr float denorm_min    () { return FLT_TRUE_MIN; }
};

template <>
struct numeric_limits<double>
{
    static constexpr bool is_specialized = std::numeric_limits<double>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<double>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<double>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<double>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<double>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<double>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<double>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<double>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<double>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<double>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<double>::is_modulo;
    static constexpr int digits = std::numeric_limits<double>::digits;
    static constexpr int digits10 = std::numeric_limits<double>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<double>::max_digits10;
    static constexpr int radix = std::numeric_limits<double>::radix;
    static constexpr int min_exponent = std::numeric_limits<double>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<double>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<double>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<double>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<double>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<double>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr double (min)         () { return DBL_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double (max)         () { return DBL_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double lowest        () { return -DBL_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double epsilon       () { return DBL_EPSILON; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double round_error   () { return 0.5; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double infinity      () { return static_cast<double>(INFINITY); }
    BOOST_CRYPT_GPU_ENABLED static constexpr double quiet_NaN     () { return static_cast<double>(NAN); }
    BOOST_CRYPT_GPU_ENABLED static constexpr double signaling_NaN ()
    {
        #ifdef DBL_SNAN
        return DBL_SNAN;
        #else
        return static_cast<double>(NAN);
        #endif
    }
    BOOST_CRYPT_GPU_ENABLED static constexpr double denorm_min    () { return DBL_TRUE_MIN; }
};

template <>
struct numeric_limits<short>
{
    static constexpr bool is_specialized = std::numeric_limits<short>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<short>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<short>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<short>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<short>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<short>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<short>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<short>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<short>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<short>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<short>::is_modulo;
    static constexpr int digits = std::numeric_limits<short>::digits;
    static constexpr int digits10 = std::numeric_limits<short>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<short>::max_digits10;
    static constexpr int radix = std::numeric_limits<short>::radix;
    static constexpr int min_exponent = std::numeric_limits<short>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<short>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<short>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<short>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<short>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<short>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr short (min)         () { return SHRT_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short (max)         () { return SHRT_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short lowest        () { return SHRT_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned short>
{
    static constexpr bool is_specialized = std::numeric_limits<unsigned short>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<unsigned short>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<unsigned short>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<unsigned short>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<unsigned short>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<unsigned short>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<unsigned short>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<unsigned short>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<unsigned short>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<unsigned short>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<unsigned short>::is_modulo;
    static constexpr int digits = std::numeric_limits<unsigned short>::digits;
    static constexpr int digits10 = std::numeric_limits<unsigned short>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<unsigned short>::max_digits10;
    static constexpr int radix = std::numeric_limits<unsigned short>::radix;
    static constexpr int min_exponent = std::numeric_limits<unsigned short>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<unsigned short>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<unsigned short>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<unsigned short>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<unsigned short>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<unsigned short>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short (max)         () { return USHRT_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short denorm_min    () { return 0; }
};

template <>
struct numeric_limits<int>
{
    static constexpr bool is_specialized = std::numeric_limits<int>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<int>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<int>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<int>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<int>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<int>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<int>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<int>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<int>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<int>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<int>::is_modulo;
    static constexpr int digits = std::numeric_limits<int>::digits;
    static constexpr int digits10 = std::numeric_limits<int>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<int>::max_digits10;
    static constexpr int radix = std::numeric_limits<int>::radix;
    static constexpr int min_exponent = std::numeric_limits<int>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<int>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<int>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<int>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<int>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<int>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr int (min)         () { return INT_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int (max)         () { return INT_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int lowest        () { return INT_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned int>
{
    static constexpr bool is_specialized = std::numeric_limits<unsigned int>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<unsigned int>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<unsigned int>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<unsigned int>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<unsigned int>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<unsigned int>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<unsigned int>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<unsigned int>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<unsigned int>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<unsigned int>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<unsigned int>::is_modulo;
    static constexpr int digits = std::numeric_limits<unsigned int>::digits;
    static constexpr int digits10 = std::numeric_limits<unsigned int>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<unsigned int>::max_digits10;
    static constexpr int radix = std::numeric_limits<unsigned int>::radix;
    static constexpr int min_exponent = std::numeric_limits<unsigned int>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<unsigned int>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<unsigned int>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<unsigned int>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<unsigned int>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<unsigned int>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int (max)         () { return UINT_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int denorm_min    () { return 0; }
};

template <>
struct numeric_limits<long>
{
    static constexpr bool is_specialized = std::numeric_limits<long>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<long>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<long>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<long>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<long>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<long>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<long>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<long>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<long>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<long>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<long>::is_modulo;
    static constexpr int digits = std::numeric_limits<long>::digits;
    static constexpr int digits10 = std::numeric_limits<long>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<long>::max_digits10;
    static constexpr int radix = std::numeric_limits<long>::radix;
    static constexpr int min_exponent = std::numeric_limits<long>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<long>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<long>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<long>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<long>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<long>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr long (min)         () { return LONG_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long (max)         () { return LONG_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long lowest        () { return LONG_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned long>
{
    static constexpr bool is_specialized = std::numeric_limits<unsigned long>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<unsigned long>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<unsigned long>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<unsigned long>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<unsigned long>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<unsigned long>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<unsigned long>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<unsigned long>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<unsigned long>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<unsigned long>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<unsigned long>::is_modulo;
    static constexpr int digits = std::numeric_limits<unsigned long>::digits;
    static constexpr int digits10 = std::numeric_limits<unsigned long>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<unsigned long>::max_digits10;
    static constexpr int radix = std::numeric_limits<unsigned long>::radix;
    static constexpr int min_exponent = std::numeric_limits<unsigned long>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<unsigned long>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<unsigned long>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<unsigned long>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<unsigned long>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<unsigned long>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long (max)         () { return ULONG_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<long long>
{
    static constexpr bool is_specialized = std::numeric_limits<long long>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<long long>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<long long>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<long long>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<long long>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<long long>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<long long>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<long long>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<long long>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<long long>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<long long>::is_modulo;
    static constexpr int digits = std::numeric_limits<long long>::digits;
    static constexpr int digits10 = std::numeric_limits<long long>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<long long>::max_digits10;
    static constexpr int radix = std::numeric_limits<long long>::radix;
    static constexpr int min_exponent = std::numeric_limits<long long>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<long long>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<long long>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<long long>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<long long>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<long long>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr long long (min)         () { return LLONG_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long (max)         () { return LLONG_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long lowest        () { return LLONG_MIN; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned long long>
{
    static constexpr bool is_specialized = std::numeric_limits<unsigned long long>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<unsigned long long>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<unsigned long long>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<unsigned long long>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<unsigned long long>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<unsigned long long>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<unsigned long long>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<unsigned long long>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<unsigned long long>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<unsigned long long>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<unsigned long long>::is_modulo;
    static constexpr int digits = std::numeric_limits<unsigned long long>::digits;
    static constexpr int digits10 = std::numeric_limits<unsigned long long>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<unsigned long long>::max_digits10;
    static constexpr int radix = std::numeric_limits<unsigned long long>::radix;
    static constexpr int min_exponent = std::numeric_limits<unsigned long long>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<unsigned long long>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<unsigned long long>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<unsigned long long>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<unsigned long long>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<unsigned long long>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long (max)         () { return ULLONG_MAX; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<bool>
{
    static constexpr bool is_specialized = std::numeric_limits<bool>::is_specialized;
    static constexpr bool is_signed = std::numeric_limits<bool>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<bool>::is_integer;
    static constexpr bool is_exact = std::numeric_limits<bool>::is_exact;
    static constexpr bool has_infinity = std::numeric_limits<bool>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<bool>::has_quiet_NaN;
    static constexpr bool has_signaling_NaN = std::numeric_limits<bool>::has_signaling_NaN;

    static constexpr std::float_round_style round_style = std::numeric_limits<bool>::round_style;
    static constexpr bool is_iec559 = std::numeric_limits<bool>::is_iec559;
    static constexpr bool is_bounded = std::numeric_limits<bool>::is_bounded;
    static constexpr bool is_modulo = std::numeric_limits<bool>::is_modulo;
    static constexpr int digits = std::numeric_limits<bool>::digits;
    static constexpr int digits10 = std::numeric_limits<bool>::digits10;
    static constexpr int max_digits10 = std::numeric_limits<bool>::max_digits10;
    static constexpr int radix = std::numeric_limits<bool>::radix;
    static constexpr int min_exponent = std::numeric_limits<bool>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<bool>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<bool>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<bool>::max_exponent10;
    static constexpr bool traps = std::numeric_limits<bool>::traps;
    static constexpr bool tinyness_before = std::numeric_limits<bool>::tinyness_before;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr bool (min)         () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool (max)         () { return true; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool lowest        () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool epsilon       () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool round_error   () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool infinity      () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool quiet_NaN     () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool signaling_NaN () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool denorm_min    () { return false; }
};

#elif defined(BOOST_CRYPT_HAS_NVRTC) // Pure NVRTC support - Removes rounding style and approximates the traits

template <>
struct numeric_limits<float>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = true;
    static constexpr bool has_quiet_NaN = true;
    static constexpr bool has_signaling_NaN = true;

    static constexpr bool is_iec559 = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 24;
    static constexpr int digits10 = 6;
    static constexpr int max_digits10 = 9;
    static constexpr int radix = 2;
    static constexpr int min_exponent = -125;
    static constexpr int min_exponent10 = -37;
    static constexpr int max_exponent = 128;
    static constexpr int max_exponent10 = 38;
    static constexpr bool traps = false;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr float (min)         () { return 1.17549435e-38F; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float (max)         () { return 3.40282347e+38F; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float lowest        () { return -3.40282347e+38F; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float epsilon       () { return 1.1920929e-07; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float round_error   () { return 0.5F; }
    BOOST_CRYPT_GPU_ENABLED static constexpr float infinity      () { return __int_as_float(0x7f800000); }
    BOOST_CRYPT_GPU_ENABLED static constexpr float quiet_NaN     () { return __int_as_float(0x7fc00000); }
    BOOST_CRYPT_GPU_ENABLED static constexpr float signaling_NaN () { return __int_as_float(0x7fa00000); }
    BOOST_CRYPT_GPU_ENABLED static constexpr float denorm_min    () { return 1.4013e-45F; }
};

template <>
struct numeric_limits<double>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = true;
    static constexpr bool has_quiet_NaN = true;
    static constexpr bool has_signaling_NaN = true;

    static constexpr bool is_iec559 = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 53;
    static constexpr int digits10 = 15;
    static constexpr int max_digits10 = 21;
    static constexpr int radix = 2;
    static constexpr int min_exponent = -1021;
    static constexpr int min_exponent10 = -307;
    static constexpr int max_exponent = 1024;
    static constexpr int max_exponent10 = 308;
    static constexpr bool traps = false;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr double (min)         () { return 2.2250738585072014e-308; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double (max)         () { return 1.7976931348623157e+308; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double lowest        () { return -1.7976931348623157e+308; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double epsilon       () { return 2.2204460492503131e-16; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double round_error   () { return 0.5; }
    BOOST_CRYPT_GPU_ENABLED static constexpr double infinity      () { return __longlong_as_double(0x7ff0000000000000ULL); }
    BOOST_CRYPT_GPU_ENABLED static constexpr double quiet_NaN     () { return __longlong_as_double(0x7ff8000000000000ULL); }
    BOOST_CRYPT_GPU_ENABLED static constexpr double signaling_NaN () { return __longlong_as_double(0x7ff4000000000000ULL); }
    BOOST_CRYPT_GPU_ENABLED static constexpr double denorm_min    () { return 4.9406564584124654e-324; }
};

template <>
struct numeric_limits<short>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 15;
    static constexpr int digits10 = 4;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr short (min)         () { return -32768; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short (max)         () { return 32767; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short lowest        () { return -32768; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr short denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned short>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = true;
    static constexpr int digits = 16;
    static constexpr int digits10 = 4;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short (max)         () { return 65535U; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned short denorm_min    () { return 0; }
};

template <>
struct numeric_limits<int>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 31;
    static constexpr int digits10 = 9;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr int (min)         () { return -2147483648; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int (max)         () { return 2147483647; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int lowest        () { return -2147483648; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr int denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned int>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = true;
    static constexpr int digits = 32;
    static constexpr int digits10 = 9;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int (max)         () { return 4294967295U; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned int denorm_min    () { return 0; }
};

template <>
struct numeric_limits<long>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 63;
    static constexpr int digits10 = 18;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr long (min)         () { return -9223372036854775808L; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long (max)         () { return 9223372036854775807L; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long lowest        () { return -9223372036854775808L; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned long>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = true;
    static constexpr int digits = 64;
    static constexpr int digits10 = 19;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long (max)         () { return 18446744073709551615UL; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<long long>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 63;
    static constexpr int digits10 = 18;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr long long (min)         () { return -9223372036854775808LL; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long (max)         () { return 9223372036854775807LL; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long lowest        () { return -9223372036854775808LL; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr long long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<unsigned long long>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = true;
    static constexpr int digits = 64;
    static constexpr int digits10 = 19;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = true;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long (min)         () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long (max)         () { return 18446744073709551615UL; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long lowest        () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long epsilon       () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long round_error   () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long infinity      () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long quiet_NaN     () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long signaling_NaN () { return 0; }
    BOOST_CRYPT_GPU_ENABLED static constexpr unsigned long long denorm_min    () { return 0; }
};

template <>
struct numeric_limits<bool>
{
    static constexpr bool is_specialized = true;
    static constexpr bool is_signed = false;
    static constexpr bool is_integer = true;
    static constexpr bool is_exact = true;
    static constexpr bool has_infinity = false;
    static constexpr bool has_quiet_NaN = false;
    static constexpr bool has_signaling_NaN = false;

    static constexpr bool is_iec559 = false;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr int digits = 1;
    static constexpr int digits10 = 0;
    static constexpr int max_digits10 = 0;
    static constexpr int radix = 2;
    static constexpr int min_exponent = 0;
    static constexpr int min_exponent10 = 0;
    static constexpr int max_exponent = 0;
    static constexpr int max_exponent10 = 0;
    static constexpr bool traps = false;
    static constexpr bool tinyness_before = false;

    // Member Functions
    BOOST_CRYPT_GPU_ENABLED static constexpr bool (min)         () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool (max)         () { return true; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool lowest        () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool epsilon       () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool round_error   () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool infinity      () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool quiet_NaN     () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool signaling_NaN () { return false; }
    BOOST_CRYPT_GPU_ENABLED static constexpr bool denorm_min    () { return false; }
};

#endif // BOOST_CRYPT_HAS_CUDA

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_UTILITY_LIMITS_HPP
