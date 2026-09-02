# WeaveBundle

WeaveBundle is a small C++ library for parsing a deliberately rich binary container format called `WVBF` (WeaveBundle Format). This is an experimental parser-hardening and fuzzing project, not a production storage standard.

The parser accepts untrusted binary input and exercises:

- header validation
- nested sections
- variable-length records
- optional names and footers
- dynamic allocation for strings, payloads, attributes, records, and child sections
- optional RLE-compressed payload blocks
- checksum verification at both file and section levels
- multiple malformed-input error paths

This makes it a good fuzzing target because a single input can drive deep control flow, repeated length parsing, recursive structure handling, and heap-backed decoding logic.

## Project status and security

The earlier [OSS-Fuzz submission](https://github.com/google/oss-fuzz/pull/15158) was closed: the reviewer considered the target insufficiently mature and recommended [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/). This repository now includes a ClusterFuzzLite configuration; this is not acceptance into OSS-Fuzz, endorsement by Google, or evidence that Google uses this library.

The parser has per-section and per-payload limits of 1 MiB and a nesting-depth limit of 8 below the root. These are **not** a cumulative document memory/CPU budget. Do not expose the parser directly to unbounded production uploads; apply input-size, memory, and execution-time limits externally. Checksums detect accidental changes, not malicious tampering. Passing tests or a short fuzz run does not establish security.

See [readiness notes](docs/READINESS.md) for verified fixes, test scope, and remaining work.

## Threat Model

The parser assumes every byte of input is attacker-controlled. A hostile input may contain malformed headers, inconsistent length fields, invalid checksums, truncated nested sections, malformed records, oversized compressed payloads, or deliberately chosen flag combinations intended to stress edge cases in allocation, bounds checking, recursion, and decompression logic.

The security goal is to handle those cases without memory corruption, out-of-bounds access, integer-overflow-driven misbehavior, or excessive parsing work that would make fuzzing less effective.

## Security goals

WeaveBundle is intentionally designed to exercise common parser risk patterns:

- multiple independent length fields
- recursive section structures
- variable-length metadata blocks
- optional compression
- checksummed data boundaries

These features mimic real-world container formats that historically produce memory-safety bugs when fuzzed, while keeping the codebase small enough to inspect.

## Repository layout

- `include/weavebundle/parser.h`: public C++17 API
- `src/`: parser implementation
- `tests/`: parser, bounds, and structured-harness regression tests
- `fuzz/`: four libFuzzer targets, testable builders, and dictionaries
- `.clusterfuzzlite/`: local-source container build integration
- `.github/workflows/`: build/test and pull-request fuzzing configurations
- `oss-fuzz/`: upstream build recipe retained for future evaluation
- `scripts/test-linux.sh`: bounded Linux fuzzing and parser-coverage report

## WVBF format specification

All integers are little-endian.

### File header

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Magic = `WVBF` |
| 4 | 1 | Version (`1` or `2`) |
| 5 | 1 | Global flags |
| 6 | 2 | Top-level section count |
| 8 | 4 | Directory size in bytes |
| 12 | 4 | File ID |
| 16 | 4 | Body checksum |
| 20 | 4 | Header checksum over bytes `0..19` |

`global_flags & 0x01` means the parser must verify the body checksum across the entire directory payload.

### Section header

Each top-level or nested section is encoded inline as:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | Section type |
| 1 | 1 | Section flags |
| 2 | 2 | Reserved |
| 4 | 4 | Section body size |
| 8 | 4 | Section ID |
| 12 | 4 | Section checksum |

Section flags:

- `0x01`: section has a UTF-8-ish byte name
- `0x02`: section has an optional footer blob
- `0x04`: verify `section_checksum` against the body
- `0x08`: section contains nested child sections

### Section body

The section body fields appear in this order:

1. `name_len:u16` and `name:name_len bytes` if `flags & 0x01`
2. `attr_block_len:u16`
3. attribute TLVs within the block:
   - `key:u8`
   - `value_len:u8`
   - `value:value_len bytes`
4. `record_count:u16`
5. `record_count` repeated record entries
6. `payload_mode:u8`
7. payload data, depending on the mode
8. `child_count:u16` followed by inline child sections if `flags & 0x08`
9. `footer_len:u16` and `footer:footer_len bytes` if `flags & 0x02`
10. any remaining bytes are preserved as opaque trailer data

### Record encoding

Each record begins with:

| Field | Size |
| --- | --- |
| `record_type` | `u8` |
| `record_flags` | `u8` |
| `record_size` | `u16` |

Record body layout:

1. `timestamp:u32` if `record_flags & 0x01`
2. `metadata_count:u8`
3. repeated metadata entries:
   - `meta_key:u8`
   - `meta_len:u8`
   - `meta_value:meta_len bytes`
4. `data_len:u16`
5. `data:data_len bytes`
6. `child_count:u8` and repeated nested values if `record_flags & 0x02`

Nested value encoding:

| Field | Size |
| --- | --- |
| `tag` | `u8` |
| `flags` | `u8` |
| `length` | `u16` |
| `value` | `length bytes` |

### Payload modes

- `0`: no payload
- `1`: raw payload
  - `raw_len:u32`
  - `raw_bytes:raw_len bytes`
- `2`: RLE-compressed payload
  - `expected_output_len:u32`
  - `compressed_len:u32`
  - `compressed_bytes:compressed_len bytes`

RLE payloads are encoded as `(run_len:u8, value:u8)` pairs. The expanded size must exactly match `expected_output_len`.

### Checksum algorithm

WeaveBundle uses a simple 32-bit FNV-1a style checksum:

```text
state = 2166136261
for each byte:
  state ^= byte
  state *= 16777619
state ^= size
state *= 16777619
```

The same checksum is used for the file header, file body, and sections.

## Building locally

### Regular build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

### Sanitized tests

Tests remain active in Debug, Release, and RelWithDebInfo builds.

```bash
cmake -S . -B build-sanitized -DCMAKE_BUILD_TYPE=Debug \
  -DWEAVEBUNDLE_ENABLE_ASAN=ON -DWEAVEBUNDLE_ENABLE_UBSAN=ON
cmake --build build-sanitized --parallel 2
UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-sanitized --output-on-failure
```

### Local fuzzing build

Use upstream LLVM Clang with its libFuzzer runtime. The build instruments **both the parser and harnesses** with libFuzzer coverage, ASan, and UBSan.

```bash
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER=clang++ -DWEAVEBUNDLE_ENABLE_FUZZING=ON
cmake --build build-fuzz --parallel 2
mkdir -p build-fuzz/corpus-parser
cp examples/sample.wvbf build-fuzz/corpus-parser/
UBSAN_OPTIONS=halt_on_error=1 ./build-fuzz/fuzz_parser \
  build-fuzz/corpus-parser -dict=fuzz/fuzz_parser.dict \
  -max_len=4096 -max_total_time=60 -rss_limit_mb=512
```

Use a separate corpus directory for each target. Passing a single file instead of a directory only replays that file; it does not start a fuzz campaign.

On macOS, use an upstream LLVM installation if AppleClang lacks libFuzzer (for example, set `CMAKE_CXX_COMPILER` to the `clang++` under `brew --prefix llvm`). An explicitly requested but unavailable fuzzing toolchain now fails configuration instead of silently omitting targets.

For a bounded Linux run of all four targets with LLVM source coverage:

```bash
CXX=clang++-19 LLVM_PROFDATA=llvm-profdata-19 LLVM_COV=llvm-cov-19 \
  FUZZ_SECONDS=60 bash scripts/test-linux.sh
```

This runs one fuzzer at a time, limits each to 512 MiB RSS and five seconds per input, and leaves logs/corpora/coverage under a unique `build/fuzz-run-*` directory. Adjust the tool names to your installed LLVM version.

## Running the example parser

```bash
./build/weavebundle_example ./examples/sample.wvbf
```

## Why this is a strong fuzzing target

- Multiple independent length fields influence allocation and control flow.
- Recursive child sections and nested record values create deep parser states.
- The optional compressed payload path exercises heap allocation and decompression logic.
- Checksum-gated sections give the fuzzer both reject and accept paths to explore.
- `fuzz_parser` parses raw inputs directly and also wraps arbitrary bytes into a structurally valid container to improve coverage.
- `fuzz_rle` concentrates on compressed payload length handling and decompression paths.
- `fuzz_section` concentrates on nested section, record, and recursive parsing paths.
- `fuzz_footer` concentrates on optional footer blobs and trailing section data.
- Each target caps input processing at 4096 bytes to keep allocations and decompression work fuzz-efficient.
- Inputs beginning with `WVBF` always take the raw parser path so real corpus files are replayed faithfully. Other inputs select raw parsing via a first-byte modulo rule (roughly 30% for uniformly distributed bytes); the rest use structured builders.

## Fuzzing Strategy

- Raw fuzzing: each target still exercises direct `ParseContainer(data, size)` on a smaller share of runs so header-validation and error-handling paths remain reachable.
- Structured container fuzzing: most executions wrap arbitrary bytes into partially valid `WVBF` containers so the fuzzer spends more time in deep parsing logic instead of failing at the magic header.
- Targeted RLE fuzzing: `fuzz_rle` focuses mutation energy on compressed payload headers, run-length pairs, declared output sizes, and footer-adjacent parsing.
- Recursive section fuzzing: `fuzz_section` drives nested sections, child counts, record payloads, and section-flag combinations that influence optional fields and recursion.
- Footer and trailer fuzzing: `fuzz_footer` emphasizes optional names, footer blobs, and opaque trailing bytes that are easy to under-exercise in a single generic target.
- Guided mutation: target-specific dictionaries and exposed flag bits help libFuzzer discover valid structural states more quickly.

## Dictionaries

Target-specific dictionaries are included in [`fuzz/`](fuzz) and are copied by [`oss-fuzz/build.sh`](oss-fuzz/build.sh):

- `fuzz_parser.dict`
- `fuzz_rle.dict`
- `fuzz_section.dict`
- `fuzz_footer.dict`

## ClusterFuzzLite and OSS-Fuzz

The pull-request workflow builds the checked-out code using `.clusterfuzzlite/Dockerfile` and runs address/undefined sanitizer jobs through Google's open-source ClusterFuzzLite actions. No paid service, extra token, or corpus-storage repository is required by this configuration. GitHub Actions must be enabled, and workflows from outside contributors may need maintainer approval.

The shared build script honors the compiler instrumentation and fuzzing engine supplied by the environment and packages each seed corpus as `<target>_seed_corpus.zip`.

To validate the container end to end, use the official [ClusterFuzzLite build instructions](https://google.github.io/clusterfuzzlite/build-integration/) with an OSS-Fuzz helper checkout and a working Docker daemon. Ordinary local or VPS builds are not a substitute for that container validation.

The `oss-fuzz/` recipe is retained for possible future submission. A working build alone is insufficient: [OSS-Fuzz eligibility](https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/) also considers significant usage or importance to global infrastructure. Establish genuine use cases and downstream users first; do not present a synthetic fuzz target as an adopted production dependency.

## Example input

An example valid container is included at [`examples/sample.wvbf`](examples/sample.wvbf). It exercises:

- a valid file header
- one top-level section
- a named section
- section checksum verification
- one record with nested values
- an RLE-compressed payload
- a nested child section
- a footer blob
