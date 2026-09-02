#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS.

set -euo pipefail
: "${SRC:?SRC must identify the source root}"
: "${OUT:?OUT must identify the fuzz output directory}"
: "${WORK:?WORK must identify the build directory}"
: "${CXX:?CXX must identify the fuzzing compiler}"
: "${LIB_FUZZING_ENGINE:?LIB_FUZZING_ENGINE must be supplied by the fuzzing environment}"

cd "$SRC/weavebundle"
build_dir="$WORK/weavebundle-build"
mkdir -p "$OUT"
cmake -S . -B "$build_dir" -G "${CMAKE_GENERATOR:-Ninja}" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DBUILD_TESTING=OFF \
  -DWEAVEBUNDLE_BUILD_EXAMPLES=OFF \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON
cmake --build "$build_dir" --parallel "${BUILD_JOBS:-2}"

for target in fuzz_parser fuzz_rle fuzz_section fuzz_footer; do
  cp "$build_dir/$target" "$OUT/"
  cp "fuzz/$target.dict" "$OUT/"
  # OSS-Fuzz discovers ZIP archives named after the executable, not directories.
  (cd examples && cmake -E tar cf "$OUT/${target}_seed_corpus.zip" --format=zip sample.wvbf)
done
