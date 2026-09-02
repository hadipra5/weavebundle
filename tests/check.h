#ifndef WEAVEBUNDLE_TEST_CHECK_H_
#define WEAVEBUNDLE_TEST_CHECK_H_

#include <cstdlib>
#include <iostream>

// Unlike assert(), checks must still run in Release/RelWithDebInfo builds.
inline std::size_t checks_run = 0;
#define CHECK(condition) do { \
  ++checks_run; \
  if (!(condition)) { \
    std::cerr << __FILE__ << ':' << __LINE__ << ": " #condition " failed\n"; \
    std::exit(EXIT_FAILURE); \
  } \
} while (false)

#endif
