# WeaveBundle

WeaveBundle is a small C++ library for parsing a deliberately rich binary container format called `WVBF` (WeaveBundle Format). The format is designed to be realistic enough for parser-hardening work while staying compact enough to audit, fuzz, and integrate into OSS-Fuzz quickly.

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

## Security note

This repository is intended as a safe fuzzing target template. It is intentionally parser-complex and sanitizer-friendly, but it does not seed known memory corruption vulnerabilities on purpose.

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

These features mimic real-world container formats that historically produce memory-safety bugs when fuzzed, while still keeping the codebase small enough to audit and integrate into OSS-Fuzz quickly.

## Repository layout

```text
.
├── CMakeLists.txt
├── LICENSE
├── README.md
├── examples
│   ├── parse_example.cpp
│   └── sample.wvbf
├── fuzz
│   ├── fuzz_footer.cpp
│   ├── fuzz_footer.dict
│   ├── fuzz_helpers.h
│   ├── fuzz_parser.cpp
│   ├── fuzz_parser.dict
│   ├── fuzz_rle.cpp
│   ├── fuzz_rle.dict
│   ├── fuzz_section.cpp
│   └── fuzz_section.dict
├── include
│   └── weavebundle
│       └── parser.h
├── oss-fuzz
│   ├── build.sh
│   ├── Dockerfile
│   └── project.yaml
├── src
│   ├── parser.cpp
│   └── parser.h
└── tests
    └── test_parser.cpp
```

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

### Local fuzzing build

```bash
cmake -S . -B build-fuzz \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON
cmake --build build-fuzz --target fuzz_parser fuzz_rle fuzz_section fuzz_footer
./build-fuzz/fuzz_parser -max_len=4096 ./examples/sample.wvbf
./build-fuzz/fuzz_rle -max_len=4096 ./examples/sample.wvbf
./build-fuzz/fuzz_section -max_len=4096 ./examples/sample.wvbf
./build-fuzz/fuzz_footer -max_len=4096 ./examples/sample.wvbf
```

On macOS, AppleClang often lacks the libFuzzer runtime. In that case, use an upstream LLVM toolchain, for example:

```bash
cmake -S . -B build-fuzz \
  -DCMAKE_CXX_COMPILER="$(brew --prefix llvm)/bin/clang++" \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON
cmake --build build-fuzz --target fuzz_parser fuzz_rle fuzz_section fuzz_footer
./build-fuzz/fuzz_parser -max_len=4096 ./examples/sample.wvbf
./build-fuzz/fuzz_rle -max_len=4096 ./examples/sample.wvbf
./build-fuzz/fuzz_section -max_len=4096 ./examples/sample.wvbf
./build-fuzz/fuzz_footer -max_len=4096 ./examples/sample.wvbf
```

If you want to force sanitizer coverage flags explicitly in a local build:

```bash
cmake -S . -B build-fuzz \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=fuzzer,address" \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON
cmake --build build-fuzz --target fuzz_parser fuzz_rle fuzz_section fuzz_footer
```

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
- Raw parsing is only exercised on roughly 30% of executions; the remaining runs bias toward structured containers.

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

## OSS-Fuzz integration

The [`oss-fuzz/Dockerfile`](oss-fuzz/Dockerfile), [`oss-fuzz/build.sh`](oss-fuzz/build.sh), and [`oss-fuzz/project.yaml`](oss-fuzz/project.yaml) files are ready to be copied into a new OSS-Fuzz project directory.

Typical OSS-Fuzz submission flow:

1. Publish this repository on GitHub or another public host.
2. Update [`oss-fuzz/project.yaml`](oss-fuzz/project.yaml) with the real repository URL and maintainer email.
3. Copy the `oss-fuzz/` files into `google/oss-fuzz/projects/weavebundle/`.
4. Open a pull request against the OSS-Fuzz repository.

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
