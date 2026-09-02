#include "weavebundle/parser.h"
#include "fuzz_builders.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace weavebundle::fuzzing {

std::vector<std::uint8_t> MakeRleContainer(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> section_body;
  const std::uint8_t section_flags = weavebundle::fuzzing::SelectFlags(
      static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 0, 0x06) & 0x06U), 0x06U, 0x04U);

  weavebundle::fuzzing::AppendU16(&section_body, 0);
  weavebundle::fuzzing::AppendU16(&section_body, 0);
  weavebundle::fuzzing::AppendU8(&section_body, 2);

  std::uint32_t expected_output =
      static_cast<std::uint32_t>(weavebundle::fuzzing::Bounded16(data, size, 0, 512, 16));
  const std::uint32_t compressed_len =
      size > 2 ? static_cast<std::uint32_t>(size - 2U) : 0U;
  // Keep malformed-length exploration, but also reach successful expansion
  // without requiring the fuzzer to guess the exact sum of every run.
  if ((weavebundle::fuzzing::ByteAt(data, size, 0, 0) & 0x80U) != 0U) {
    expected_output = 0;
    for (std::size_t i = 2; i + 1 < size; i += 2) {
      expected_output += data[i];
    }
  }

  weavebundle::fuzzing::AppendU32(&section_body, expected_output);
  weavebundle::fuzzing::AppendU32(&section_body, compressed_len);
  if (compressed_len > 0) {
    section_body.insert(section_body.end(), data + 2, data + size);
  }

  const bool with_footer = (section_flags & 0x02U) != 0U;
  if (with_footer) {
    const std::uint16_t footer_len =
        static_cast<std::uint16_t>(weavebundle::fuzzing::Bounded16(data, size, 3, 32, 0));
    weavebundle::fuzzing::AppendU16(&section_body, footer_len);
    for (std::uint16_t i = 0; i < footer_len; ++i) {
      weavebundle::fuzzing::AppendU8(
          &section_body, weavebundle::fuzzing::ByteAt(data, size, 5U + i, static_cast<std::uint8_t>(i)));
    }
  }

  const std::vector<std::uint8_t> section =
      weavebundle::fuzzing::MakeSection(3, section_flags, 0x524c4501U, section_body);
  const std::uint8_t global_flags = static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 1, 1) & 0x01U);
  return weavebundle::fuzzing::MakeContainer({section}, 1, global_flags, 0x524c4521U);
}

}  // namespace weavebundle::fuzzing

#ifndef WEAVEBUNDLE_FUZZ_BUILDERS_ONLY
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (weavebundle::fuzzing::ShouldSkipInput(size)) {
    return 0;
  }

  if (weavebundle::fuzzing::ShouldUseRawPath(data, size)) {
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(data, size));
  } else {
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(weavebundle::fuzzing::MakeRleContainer(data, size)));
  }
  return 0;
}
#endif
