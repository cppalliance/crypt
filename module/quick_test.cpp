// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

// Import the STL if we can
#if defined(__cpp_lib_modules) && __cpp_lib_modules >= 202207L
import std;
#else
#include <iostream>
#endif

import boost2.crypt;

int main()
{
    const auto res = boost::crypt::md5("abc");
    std::cout << res[0] << std::endl;

    return 0;
}
