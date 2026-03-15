cmake_minimum_required(VERSION 3.16)

project(weavebundle LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WEAVEBUNDLE_ENABLE_FUZZING "Build the libFuzzer target when supported" ON)
option(WEAVEBUNDLE_ENABLE_ASAN "Enable AddressSanitizer on non-fuzz targets" OFF)

add_library(weavebundle STATIC
  src/parser.cpp
)

target_include_directories(weavebundle
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(weavebundle
  PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

if(WEAVEBUNDLE_ENABLE_ASAN)
  target_compile_options(weavebundle PUBLIC -fsanitize=address)
  target_link_options(weavebundle PUBLIC -fsanitize=address)
endif()

add_executable(weavebundle_example
  examples/parse_example.cpp
)

target_link_libraries(weavebundle_example PRIVATE weavebundle)

add_executable(test_parser
  tests/test_parser.cpp
)

target_link_libraries(test_parser PRIVATE weavebundle)

enable_testing()
add_test(NAME weavebundle_tests COMMAND test_parser)

if(WEAVEBUNDLE_ENABLE_FUZZING)
  if(DEFINED ENV{LIB_FUZZING_ENGINE} AND NOT "$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")
    add_executable(fuzz_parser
      fuzz/fuzz_parser.cpp
    )

    target_link_libraries(fuzz_parser PRIVATE weavebundle "$ENV{LIB_FUZZING_ENGINE}")
    target_compile_options(fuzz_parser PRIVATE -fsanitize=address)
    target_link_options(fuzz_parser PRIVATE -fsanitize=address)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_executable(fuzz_parser
      fuzz/fuzz_parser.cpp
    )

    target_link_libraries(fuzz_parser PRIVATE weavebundle)
    target_compile_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address)
    target_link_options(fuzz_parser PRIVATE -fsanitize=fuzzer,address)
  else()
    message(STATUS "Skipping fuzz_parser: use upstream LLVM clang or provide LIB_FUZZING_ENGINE.")
  endif()
endif()
