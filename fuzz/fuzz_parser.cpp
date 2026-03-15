#include "weavebundle/parser.h"
#include "fuzz_helpers.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

std::vector<std::uint8_t> MakeWrappedInput(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> record_body;
  const std::uint8_t metadata_value = weavebundle::fuzzing::ByteAt(data, size, 0, 0);
  const std::uint8_t nested_value = weavebundle::fuzzing::ByteAt(data, size, 1, 0x41);
  const std::uint8_t record_flags =
      static_cast<std::uint8_t>(0x01U | (weavebundle::fuzzing::ByteAt(data, size, 5, 0x02) & 0x02U));
  const std::uint8_t section_flags = weavebundle::fuzzing::SelectFlags(
      static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 6, 0x0f) & 0x0fU), 0x0fU, 0x04U);

  weavebundle::fuzzing::AppendU32(&record_body, 0x01020304U);
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body, record_flags);
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body, metadata_value);

  const std::uint16_t record_data_len = static_cast<std::uint16_t>(size > 24 ? 24 : size);
  weavebundle::fuzzing::AppendU16(&record_body, record_data_len);
  for (std::uint16_t i = 0; i < record_data_len; ++i) {
    weavebundle::fuzzing::AppendU8(&record_body, data[i]);
  }

  if ((record_flags & 0x02U) != 0U) {
    weavebundle::fuzzing::AppendU8(&record_body, 1);
    weavebundle::fuzzing::AppendU8(&record_body, 0x21);
    weavebundle::fuzzing::AppendU8(&record_body, 0);
    weavebundle::fuzzing::AppendU16(&record_body, 3);
    weavebundle::fuzzing::AppendU8(&record_body, 'N');
    weavebundle::fuzzing::AppendU8(&record_body, nested_value);
    weavebundle::fuzzing::AppendU8(&record_body, 'D');
  }

  std::vector<std::uint8_t> section_body;
  if ((section_flags & 0x01U) != 0U) {
    weavebundle::fuzzing::AppendU16(&section_body, 4);
    weavebundle::fuzzing::AppendU8(&section_body, 's');
    weavebundle::fuzzing::AppendU8(&section_body, 'e');
    weavebundle::fuzzing::AppendU8(&section_body, 'e');
    weavebundle::fuzzing::AppendU8(&section_body, 'd');
  }

  weavebundle::fuzzing::AppendU16(&section_body, 3);
  weavebundle::fuzzing::AppendU8(&section_body, 0x01);
  weavebundle::fuzzing::AppendU8(&section_body, 1);
  weavebundle::fuzzing::AppendU8(&section_body, weavebundle::fuzzing::ByteAt(data, size, 2, 0x7f));

  weavebundle::fuzzing::AppendU16(&section_body, 1);
  weavebundle::fuzzing::AppendU8(&section_body, 0x30);
  weavebundle::fuzzing::AppendU8(&section_body, 0x03);
  weavebundle::fuzzing::AppendU16(&section_body, static_cast<std::uint16_t>(record_body.size()));
  section_body.insert(section_body.end(), record_body.begin(), record_body.end());

  const bool use_rle = (size % 2U) == 0U;
  if (use_rle) {
    std::vector<std::uint8_t> compressed;
    const std::uint8_t first = weavebundle::fuzzing::ByteAt(data, size, 3, 0x42);
    const std::uint8_t second = weavebundle::fuzzing::ByteAt(data, size, 4, 0x24);
    weavebundle::fuzzing::AppendU8(&compressed, 2);
    weavebundle::fuzzing::AppendU8(&compressed, first);
    weavebundle::fuzzing::AppendU8(&compressed, 2);
    weavebundle::fuzzing::AppendU8(&compressed, second);
    weavebundle::fuzzing::AppendU8(&section_body, 2);
    weavebundle::fuzzing::AppendU32(&section_body, 4);
    weavebundle::fuzzing::AppendU32(&section_body, static_cast<std::uint32_t>(compressed.size()));
    section_body.insert(section_body.end(), compressed.begin(), compressed.end());
  } else {
    weavebundle::fuzzing::AppendU8(&section_body, 1);
    const std::uint32_t payload_len = static_cast<std::uint32_t>(size > 32 ? 32 : size);
    weavebundle::fuzzing::AppendU32(&section_body, payload_len);
    section_body.insert(section_body.end(), data, data + payload_len);
  }

  weavebundle::fuzzing::AppendU16(&section_body, 2);
  weavebundle::fuzzing::AppendU8(&section_body, 0xaa);
  weavebundle::fuzzing::AppendU8(&section_body, 0x55);

  if ((section_flags & 0x08U) != 0U) {
    weavebundle::fuzzing::AppendU16(&section_body, 0);
  }

  if ((section_flags & 0x02U) != 0U) {
    const std::uint16_t footer_len =
        static_cast<std::uint16_t>(weavebundle::fuzzing::ByteAt(data, size, 7, 2) % 8U);
    weavebundle::fuzzing::AppendU16(&section_body, footer_len);
    for (std::uint16_t i = 0; i < footer_len; ++i) {
      weavebundle::fuzzing::AppendU8(
          &section_body, weavebundle::fuzzing::ByteAt(data, size, 8U + i, static_cast<std::uint8_t>(0x90U + i)));
    }
  }

  const std::vector<std::uint8_t> section =
      weavebundle::fuzzing::MakeSection(1, section_flags, 0x900df00dU, section_body);
  const std::uint8_t global_flags = static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 9, 1) & 0x01U);
  return weavebundle::fuzzing::MakeContainer({section}, 1, global_flags, 0x1337c0deU);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (weavebundle::fuzzing::ShouldSkipInput(size)) {
    return 0;
  }

  if (weavebundle::fuzzing::ShouldUseRawPath(data, size)) {
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(data, size));
  } else {
    const std::vector<std::uint8_t> wrapped = MakeWrappedInput(data, size);
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(wrapped));
  }
  return 0;
}
