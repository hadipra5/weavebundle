#!/usr/bin/env bash
set -euo pipefail

# Exercise the shared build contract without Docker. This deliberately does
# not claim to validate Google's container images or GitHub Actions runtime.
project_dir="$PWD"
mkdir -p "$project_dir/build"
run_root="$(mktemp -d "$project_dir/build/engine-test-XXXXXXXX")"
mkdir -p "$run_root/src/weavebundle"
cp -R CMakeLists.txt include src fuzz examples oss-fuzz .clusterfuzzlite "$run_root/src/weavebundle/"
for sanitizer in address undefined; do
  export SRC="$run_root/src"
  export WORK="$run_root/work-$sanitizer"
  export OUT="$run_root/out-$sanitizer"
  export CXX="${CXX:-clang++}"
  export CXXFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,$sanitizer"
  export LIB_FUZZING_ENGINE="-fsanitize=fuzzer -pthread"
  export CMAKE_GENERATOR="Unix Makefiles"
  export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
  mkdir -p "$WORK" "$OUT"
  bash .clusterfuzzlite/build.sh
  for target in fuzz_parser fuzz_rle fuzz_section fuzz_footer; do
    test -s "$OUT/$target.dict"
    unzip -t "$OUT/${target}_seed_corpus.zip"
    "$OUT/$target" -runs=1000 -max_len=4096 examples/sample.wvbf
  done
done
echo "External-engine build and corpus packaging passed: $run_root"
