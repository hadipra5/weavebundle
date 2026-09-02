#!/usr/bin/env bash
set -euo pipefail

# Bounded, single-process fuzz smoke test. Run from the repository root using
# an upstream LLVM toolchain, e.g. CXX=clang++-19 bash scripts/test-linux.sh.
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1
seconds="${FUZZ_SECONDS:-60}"
if [[ ! "$seconds" =~ ^[0-9]+$ ]] || (( seconds < 1 || seconds > 600 )); then
  echo "FUZZ_SECONDS must be between 1 and 600" >&2
  exit 2
fi

cmake -S . -B build/linux-fuzz \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON \
  -DWEAVEBUNDLE_ENABLE_ASAN=ON \
  -DWEAVEBUNDLE_ENABLE_UBSAN=ON \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
cmake --build build/linux-fuzz --parallel 2
ctest --test-dir build/linux-fuzz --output-on-failure

run_root="$(mktemp -d "$PWD/build/fuzz-run-XXXXXXXX")"
mkdir -p "$run_root/coverage"
echo "Fuzz results: $run_root"
for target in fuzz_parser fuzz_rle fuzz_section fuzz_footer; do
  mkdir -p "$run_root/$target/corpus" "$run_root/$target/artifacts"
  cp examples/sample.wvbf "$run_root/$target/corpus/"
  LLVM_PROFILE_FILE="$run_root/coverage/$target-%p.profraw" \
    timeout "$((seconds + 30))" nice -n 15 "build/linux-fuzz/$target" \
    "$run_root/$target/corpus" \
    "-dict=fuzz/$target.dict" \
    "-artifact_prefix=$run_root/$target/artifacts/" \
    "-max_total_time=$seconds" -timeout=5 -rss_limit_mb=512 \
    -malloc_limit_mb=64 -max_len=4096 -print_final_stats=1 \
    > "$run_root/$target.log" 2>&1
  tail -n 8 "$run_root/$target.log"
done

"${LLVM_PROFDATA:-llvm-profdata}" merge -sparse \
  "$run_root"/coverage/*.profraw -o "$run_root/coverage/merged.profdata"
"${LLVM_COV:-llvm-cov}" report build/linux-fuzz/fuzz_parser \
  -object build/linux-fuzz/fuzz_rle \
  -object build/linux-fuzz/fuzz_section \
  -object build/linux-fuzz/fuzz_footer \
  "-instr-profile=$run_root/coverage/merged.profdata" src/parser.cpp \
  | tee "$run_root/coverage/report.txt"
