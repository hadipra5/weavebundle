#include "weavebundle/parser.h"
#include "fuzz_builders.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace weavebundle::fuzzing {

std::vector<std::uint8_t> MakeFooterContainer(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> section_body;
  const std::uint8_t section_flags = weavebundle::fuzzing::SelectFlags(
      static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 0, 0x07) & 0x07U), 0x07U, 0x02U);
  if ((section_flags & 0x01U) != 0U) {
    weavebundle::fuzzing::AppendU16(&section_body, 5);
    weavebundle::fuzzing::AppendU8(&section_body, 'n');
    weavebundle::fuzzing::AppendU8(&section_body, 'o');
    weavebundle::fuzzing::AppendU8(&section_body, 't');
    weavebundle::fuzzing::AppendU8(&section_body, 'e');
    weavebundle::fuzzing::AppendU8(&section_body, 's');
  }

  const std::uint16_t attr_len =
      static_cast<std::uint16_t>(weavebundle::fuzzing::Bounded16(data, size, 0, 16, 4));
  // A valid TLV lets this target actually reach the footer/trailer. Malformed
  // attribute blocks remain covered by raw WVBF inputs.
  weavebundle::fuzzing::AppendU16(&section_body, static_cast<std::uint16_t>(attr_len + 2U));
  weavebundle::fuzzing::AppendU8(&section_body, 1);
  weavebundle::fuzzing::AppendU8(&section_body, static_cast<std::uint8_t>(attr_len));
  for (std::uint16_t i = 0; i < attr_len; ++i) {
    weavebundle::fuzzing::AppendU8(
        &section_body, weavebundle::fuzzing::ByteAt(data, size, 2U + i, static_cast<std::uint8_t>(i)));
  }

  weavebundle::fuzzing::AppendU16(&section_body, 0);
  weavebundle::fuzzing::AppendU8(&section_body, 0);

  const std::uint16_t footer_len =
      static_cast<std::uint16_t>(weavebundle::fuzzing::Bounded16(data, size, 4, 64, 8));
  if ((section_flags & 0x02U) != 0U) {
    weavebundle::fuzzing::AppendU16(&section_body, footer_len);
    for (std::uint16_t i = 0; i < footer_len; ++i) {
      weavebundle::fuzzing::AppendU8(
          &section_body, weavebundle::fuzzing::ByteAt(data, size, 6U + i, static_cast<std::uint8_t>(0xf0U + i)));
    }
  }

  const std::uint16_t trailer_len =
      static_cast<std::uint16_t>(weavebundle::fuzzing::Bounded16(data, size, 8, 32, 4));
  for (std::uint16_t i = 0; i < trailer_len; ++i) {
    weavebundle::fuzzing::AppendU8(
        &section_body, weavebundle::fuzzing::ByteAt(data, size, 10U + i, static_cast<std::uint8_t>(0xa0U + i)));
  }

  const std::vector<std::uint8_t> section =
      weavebundle::fuzzing::MakeSection(4, section_flags, 0x464f4f54U, section_body);
  const std::uint8_t global_flags = static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 1, 1) & 0x01U);
  return weavebundle::fuzzing::MakeContainer({section}, 2, global_flags, 0x464f4f54U);
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
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(weavebundle::fuzzing::MakeFooterContainer(data, size)));
  }
  return 0;
}
#endif
