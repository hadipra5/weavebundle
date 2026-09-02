# Readiness assessment — 2026-09-02

## What this update establishes

WeaveBundle remains an experimental WVBF parser and fuzzing project. It has
working local regression tests and Linux libFuzzer targets. This update does
not establish production readiness, Google adoption, or OSS-Fuzz eligibility.

The [previous OSS-Fuzz PR](https://github.com/google/oss-fuzz/pull/15158) was
closed after the reviewer considered the target insufficiently mature and
recommended ClusterFuzzLite. The appropriate immediate step is CI fuzzing
and real-world validation, not resubmitting the same project with new claims.

## Confirmed problems fixed

- The RLE builder wrote an extra field, selecting payload mode 0 instead of
  mode 2. A regression now requires successful decoding of known RLE bytes.
- The generic builder's record flags disagreed with its body, and child/footer
  fields were out of order.
- The nested-section builder encoded the wrong record count and timestamp/
  metadata layout.
- Random malformed attributes often stopped the footer builder before it
  reached the footer. Its structured path now emits valid attributes.
- Real WVBF seed files never selected the old modulo-based raw path. They now
  always reach direct parsing.
- Native fuzzing instrumented the harness without instrumenting the parser
  library. A dedicated instrumented parser library now backs all four targets.
- External-engine builds forced ASan regardless of the requested sanitizer.
  Compiler flags are now preserved and multi-argument engines are supported.
- Release builds disabled assert-based test checks. Checks now run regardless
  of NDEBUG.
- Seed corpora were directories instead of the ZIP archives expected by the
  integration. Build scripts now create and validate the intended artifacts.
- RLE runs are validated before allocating declared output, and internal
  cursor advancement saturates without unsigned addition overflow.

Five newly added harness/routing regression groups failed against the old
builder logic before the fixes; all now pass.

## Validation performed

| Environment | Configuration | Result |
| --- | --- | --- |
| macOS / AppleClang 21 | Release | 7 CTest groups, 3,297 checks passed |
| macOS / AppleClang 21 | Debug + ASan + UBSan | 7 groups passed |
| Linux x86-64 / Clang 19.1.7 | RelWithDebInfo + ASan + UBSan | 7 groups, 3,297 checks passed |
| Linux external engine | address sanitizer | 4 executables built; 4 seed ZIPs validated; each target replayed the sample 1,000 times |
| Linux external engine | undefined sanitizer | Same checks passed independently |
| Integration configuration | Shell syntax and YAML parsing | Passed; not an end-to-end GitHub Actions test |

One bounded Linux fuzz campaign ran each target for a configured 60 seconds
(libFuzzer reported 61 seconds per target), using the sample corpus and its
dictionary, with a 4,096-byte input cap, 512 MiB RSS limit, and five-second
per-input timeout. ASan and UBSan were enabled with halt-on-error behavior.

| Target | Executions | Peak RSS |
| --- | ---: | ---: |
| fuzz_parser | 654,435 | 277 MiB |
| fuzz_rle | 990,363 | 267 MiB |
| fuzz_section | 630,250 | 280 MiB |
| fuzz_footer | 990,048 | 282 MiB |
| Total | 3,265,096 | — |

No crashes or sanitizer findings were reported in this bounded run. This is
a smoke test, not an exhaustive audit. Execution counts include repeated and
mutated inputs; they are not counts of unique test cases.

The combined LLVM report estimated parser line coverage at 60.04%, region
coverage at 78.19%, and branch coverage at 56.91%. LLVM also emitted one
profile-mismatch warning, so treat these figures as provisional rather than
a clean coverage acceptance gate. A direct function report did confirm that
ExpandRle was reached, including successful expansion and malformed-length
paths. Unit-test profiles were not included in the fuzz coverage totals.

Reproduce the bounded campaign with scripts/test-linux.sh and the external
engine/seed packaging checks with scripts/test-fuzz-build.sh. Fuzz logs and
the report from this run are retained locally under build/vps-results/;
generated build artifacts and corpora are intentionally not committed.

No packages were installed and no existing VPS services were reconfigured.

## Still unverified / next steps

1. Run the actual ClusterFuzzLite container/PR workflow. Neither test host had
   an available Docker daemon during this work. The external-engine checks
   exercise the shared script, not Google's container images or GitHub runtime.
2. Resolve the coverage-profile warning and expand fuzz coverage, particularly
   checksum-correct malformed deep structures and resource-limit boundaries.
3. Add an explicit cumulative document allocation/work budget before handling
   large hostile inputs. Current per-object limits are not a document-wide cap.
4. Define and validate a real use case with actual downstream consumers.
   Decide whether WVBF offers value beyond being a parser-hardening exercise.
5. Keep a release/compatibility policy, sustained regression history, and
   evidence of use before discussing a new OSS-Fuzz submission.

OSS-Fuzz considers significant usage or importance to global infrastructure;
see its [official eligibility criteria](https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/).
ClusterFuzzLite can help test this project now, but using Google's testing
tools is not the same as Google adopting the library.
