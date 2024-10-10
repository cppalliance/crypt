// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_CONCEPTS_HPP
#define BOOST_CRYPT_UTILITY_CONCEPTS_HPP

#include <boost/crypt/utility/type_traits.hpp>

// GCC-11 yields internal compiler errors when using the concepts

/*
./boost/decimal/detail/concepts.hpp:239:80: note: in definition of macro 'BOOST_CRYPT_REQUIRES_RETURN'
  239 | #define BOOST_CRYPT_REQUIRES_RETURN(X, T, ReturnType) -> ReturnType requires X<T>
      |                                                                                ^
0xe3223b internal_error(char const*, ...)
    ???:0
0xf56ed4 duplicate_decls(tree_node*, tree_node*, bool, bool)
    ???:0
0xf60a2b pushdecl_namespace_level(tree_node*, bool)
    ???:0
0x10801ca push_template_decl(tree_node*, bool)
    ???:0
0x1527ec1 do_friend(tree_node*, tree_node*, tree_node*, tree_node*, overload_flags, bool)
    ???:0
0xfc4e1e grokdeclarator(cp_declarator const*, cp_decl_specifier_seq*, decl_context, int, tree_node**)
    ???:0
0x100dcf4 grokfield(cp_declarator const*, cp_decl_specifier_seq*, tree_node*, bool, tree_node*, tree_node*)
    ???:0
0x149dce3 c_parse_file()
    ???:0
0x148d4de c_common_parse_file()
    ???:0
*/
#if (__cplusplus >= 202002L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)) && !defined(BOOST_MATH_DISABLE_CONCEPTS) &&\
    (!defined(__GNUC__) || __GNUC__ != 11)

#if __has_include(<concepts>)

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <utility>
#include <algorithm>
#include <concepts>
#include <functional>
#include <limits>
#include <iterator>
#include <complex>
#endif

namespace boost::crypt::concepts {

template <typename T>
concept integral = boost::crypt::is_integral_v<T>;

template <typename T>
concept signed_integral = integral<T> && boost::crypt::is_signed_v<T>;

template <typename T>
concept unsigned_integral = integral<T> && boost::crypt::is_unsigned_v<T>;

template <typename T>
concept real = boost::crypt::is_floating_point_v<T>;

} // boost::crypt::concepts

#define BOOST_CRYPT_HAS_CONCEPTS 1

#define BOOST_CRYPT_INTEGRAL boost::crypt::concepts::integral
#define BOOST_CRYPT_SIGNED_INTEGRAL boost::crypt::concepts::signed_integral
#define BOOST_CRYPT_UNSIGNED_INTEGRAL boost::crypt::concepts::unsigned_integral
#define BOOST_CRYPT_REAL boost::crypt::concepts::real

#define BOOST_CRYPT_REQUIRES(X, T) -> T requires X<T>
#define BOOST_CRYPT_REQUIRES_TWO(X1, T1, X2, T2) -> detail::promote_args_t<T1, T2> requires X1<T1> && X2<T2>
#define BOOST_CRYPT_REQUIRES_TWO_RETURN(X1, T1, X2, T2, ReturnType) -> ReturnType requires X1<T1> && X2<T2>
#define BOOST_CRYPT_REQUIRES_THREE(X1, T1, X2, T2, X3, T3) -> detail::promote_args_t<T1, T2, T3> requires X1<T1> && X2<T2> && X3<T3>
#define BOOST_CRYPT_REQUIRES_RETURN(X, T, ReturnType) -> ReturnType requires X<T>
#define BOOST_CRYPT_REQUIRES_CONVERSION(T1, T2) -> void requires boost::crypt::is_convertible_v<T1, T2>

#endif // Has <concepts>
#endif // C++20

// If concepts are unavailable replace them with typename for compatibility

#ifndef BOOST_CRYPT_INTEGRAL
#  define BOOST_CRYPT_INTEGRAL typename
#endif

#ifndef BOOST_CRYPT_SIGNED_INTEGRAL
#  define BOOST_CRYPT_SIGNED_INTEGRAL typename
#endif

#ifndef BOOST_CRYPT_UNSIGNED_INTEGRAL
#  define BOOST_CRYPT_UNSIGNED_INTEGRAL typename
#endif

#ifndef BOOST_CRYPT_REAL
#  define BOOST_CRYPT_REAL typename
#endif
#ifndef BOOST_CRYPT_REQUIRES
#  define BOOST_CRYPT_REQUIRES(X, T) -> boost::crypt::enable_if_t<X<T>, T>
#endif

#ifndef BOOST_CRYPT_REQUIRES_TWO
#  define BOOST_CRYPT_REQUIRES_TWO(X1, T1, X2, T2) -> boost::crypt::enable_if_t<X1<T1> && X2<T2>, detail::promote_args_t<T1, T2>>
#endif

#ifndef BOOST_CRYPT_REQUIRES_TWO_RETURN
#  define BOOST_CRYPT_REQUIRES_TWO_RETURN(X1, T1, X2, T2, ReturnType) -> boost::crypt::enable_if_t<X1<T1> && X2<T2>, ReturnType>
#endif

#ifndef BOOST_CRYPT_REQUIRES_THREE
#  define BOOST_CRYPT_REQUIRES_THREE(X1, T1, X2, T2, X3, T3) -> boost::crypt::enable_if_t<X1<T1> && X2<T2> && X3<T3>, detail::promote_args_t<T1, T2, T3>>
#endif

#ifndef BOOST_CRYPT_REQUIRES_RETURN
#  define BOOST_CRYPT_REQUIRES_RETURN(X, T, ReturnType) -> boost::crypt::enable_if_t<X<T>, ReturnType>
#endif

#ifndef BOOST_CRYPT_REQUIRES_CONVERSION
#  define BOOST_CRYPT_REQUIRES_CONVERSION(T1, T2) -> boost::crypt::enable_if_t<boost::crypt::is_convertible_v<T1, T2>, void>
#endif

#endif //BOOST_CRYPT_UTILITY_CONCEPTS_HPP
