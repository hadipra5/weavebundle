cmake_minimum_required(VERSION 3.16)
project(weavebundle LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WEAVEBUNDLE_ENABLE_FUZZING "Build the libFuzzer targets" OFF)
option(WEAVEBUNDLE_ENABLE_ASAN "Enable AddressSanitizer on normal targets" OFF)
option(WEAVEBUNDLE_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer on normal targets" OFF)
option(WEAVEBUNDLE_BUILD_EXAMPLES "Build the example parser" ON)
include(CTest)

add_library(weavebundle STATIC src/parser.cpp)
add_library(weavebundle::weavebundle ALIAS weavebundle)
target_include_directories(weavebundle PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(weavebundle PUBLIC cxx_std_17)
if(MSVC)
  target_compile_options(weavebundle PRIVATE /W4)
else()
  target_compile_options(weavebundle PRIVATE -Wall -Wextra -Wpedantic)
endif()

foreach(sanitizer IN ITEMS ASAN UBSAN)
  if(WEAVEBUNDLE_ENABLE_${sanitizer})
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
      message(FATAL_ERROR "${sanitizer} requires a Clang or GCC toolchain")
    endif()
    if(sanitizer STREQUAL "ASAN")
      set(sanitizer_flag -fsanitize=address)
    else()
      set(sanitizer_flag -fsanitize=undefined)
    endif()
    target_compile_options(weavebundle PUBLIC ${sanitizer_flag} -fno-omit-frame-pointer)
    target_link_options(weavebundle PUBLIC ${sanitizer_flag})
  endif()
endforeach()

if(WEAVEBUNDLE_BUILD_EXAMPLES)
  add_executable(weavebundle_example examples/parse_example.cpp)
  target_link_libraries(weavebundle_example PRIVATE weavebundle)
endif()

set(WEAVEBUNDLE_FUZZ_SOURCES
  fuzz/fuzz_parser.cpp fuzz/fuzz_rle.cpp fuzz/fuzz_section.cpp fuzz/fuzz_footer.cpp)

if(BUILD_TESTING)
  add_executable(test_parser tests/test_parser.cpp)
  target_link_libraries(test_parser PRIVATE weavebundle)
  add_test(NAME weavebundle_tests COMMAND test_parser)

  add_executable(test_edge_cases tests/test_edge_cases.cpp)
  target_link_libraries(test_edge_cases PRIVATE weavebundle)
  add_test(NAME parser_edge_cases COMMAND test_edge_cases)

  add_executable(test_fuzz_builders tests/test_fuzz_builders.cpp ${WEAVEBUNDLE_FUZZ_SOURCES})
  target_compile_definitions(test_fuzz_builders PRIVATE WEAVEBUNDLE_FUZZ_BUILDERS_ONLY)
  target_link_libraries(test_fuzz_builders PRIVATE weavebundle)
  foreach(case IN ITEMS parser rle section footer routing)
    add_test(NAME fuzz_builder_${case} COMMAND test_fuzz_builders ${case})
  endforeach()
endif()

if(WEAVEBUNDLE_ENABLE_FUZZING)
  # Instrument the parser itself, not just the harness, without forcing a
  # libFuzzer runtime onto ordinary tests and library consumers.
  add_library(weavebundle_fuzz STATIC src/parser.cpp)
  target_include_directories(weavebundle_fuzz PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

  if(DEFINED ENV{LIB_FUZZING_ENGINE} AND NOT "$ENV{LIB_FUZZING_ENGINE}" STREQUAL "")
    # OSS-Fuzz/ClusterFuzzLite supply instrumentation through CXXFLAGS. Do not
    # override their sanitizer (undefined, memory, coverage, etc.) with ASan.
    separate_arguments(fuzz_engine NATIVE_COMMAND "$ENV{LIB_FUZZING_ENGINE}")
  else()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      message(FATAL_ERROR "Local fuzzing requires LLVM Clang with libFuzzer, or LIB_FUZZING_ENGINE.")
    endif()
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer,address,undefined")
    check_cxx_source_compiles(
      "#include <cstddef>\nextern \"C\" int LLVMFuzzerTestOneInput(const unsigned char*, std::size_t) { return 0; }"
      WEAVEBUNDLE_HAS_LIBFUZZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if(NOT WEAVEBUNDLE_HAS_LIBFUZZER)
      message(FATAL_ERROR "libFuzzer is unavailable. Use upstream LLVM Clang or disable WEAVEBUNDLE_ENABLE_FUZZING.")
    endif()
    target_compile_options(weavebundle_fuzz PUBLIC
      -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
  endif()

  foreach(name IN ITEMS parser rle section footer)
    add_executable(fuzz_${name} fuzz/fuzz_${name}.cpp)
    target_link_libraries(fuzz_${name} PRIVATE weavebundle_fuzz)
    if(DEFINED fuzz_engine)
      target_link_libraries(fuzz_${name} PRIVATE ${fuzz_engine})
    else()
      target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()
  endforeach()
endif()
