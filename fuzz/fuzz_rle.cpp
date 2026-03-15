#include "weavebundle/parser.h"
#include "fuzz_helpers.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

std::vector<std::uint8_t> MakeRleContainer(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> section_body;

  weavebundle::fuzzing::AppendU16(&section_body, 0);
  weavebundle::fuzzing::AppendU16(&section_body, 0);
  weavebundle::fuzzing::AppendU16(&section_body, 0);
  weavebundle::fuzzing::AppendU8(&section_body, 2);

  const std::uint32_t expected_output =
      static_cast<std::uint32_t>(weavebundle::fuzzing::Bounded16(data, size, 0, 512, 16));
  const std::uint32_t compressed_len =
      size > 2 ? static_cast<std::uint32_t>(size - 2U) : 0U;

  weavebundle::fuzzing::AppendU32(&section_body, expected_output);
  weavebundle::fuzzing::AppendU32(&section_body, compressed_len);
  if (compressed_len > 0) {
    section_body.insert(section_body.end(), data + 2, data + size);
  }

  const bool with_footer = (weavebundle::fuzzing::ByteAt(data, size, 2, 0) & 0x01U) != 0U;
  if (with_footer) {
    const std::uint16_t footer_len =
        static_cast<std::uint16_t>(weavebundle::fuzzing::Bounded16(data, size, 3, 32, 0));
    weavebundle::fuzzing::AppendU16(&section_body, footer_len);
    for (std::uint16_t i = 0; i < footer_len; ++i) {
      weavebundle::fuzzing::AppendU8(
          &section_body, weavebundle::fuzzing::ByteAt(data, size, 5U + i, static_cast<std::uint8_t>(i)));
    }
  }

  const std::uint8_t section_flags = static_cast<std::uint8_t>(0x04U | (with_footer ? 0x02U : 0x00U));
  const std::vector<std::uint8_t> section =
      weavebundle::fuzzing::MakeSection(3, section_flags, 0x524c4501U, section_body);
  return weavebundle::fuzzing::MakeContainer({section}, 1, 1, 0x524c4521U);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(data, size));
  weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(MakeRleContainer(data, size)));
  return 0;
}
