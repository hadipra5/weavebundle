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

  weavebundle::fuzzing::AppendU32(&record_body, 0x01020304U);
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body, 0x10);
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body, metadata_value);

  const std::uint16_t record_data_len = static_cast<std::uint16_t>(size > 24 ? 24 : size);
  weavebundle::fuzzing::AppendU16(&record_body, record_data_len);
  for (std::uint16_t i = 0; i < record_data_len; ++i) {
    weavebundle::fuzzing::AppendU8(&record_body, data[i]);
  }

  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body, 0x21);
  weavebundle::fuzzing::AppendU8(&record_body, 0);
  weavebundle::fuzzing::AppendU16(&record_body, 3);
  weavebundle::fuzzing::AppendU8(&record_body, 'N');
  weavebundle::fuzzing::AppendU8(&record_body, nested_value);
  weavebundle::fuzzing::AppendU8(&record_body, 'D');

  std::vector<std::uint8_t> section_body;
  weavebundle::fuzzing::AppendU16(&section_body, 4);
  weavebundle::fuzzing::AppendU8(&section_body, 's');
  weavebundle::fuzzing::AppendU8(&section_body, 'e');
  weavebundle::fuzzing::AppendU8(&section_body, 'e');
  weavebundle::fuzzing::AppendU8(&section_body, 'd');

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

  const std::vector<std::uint8_t> section =
      weavebundle::fuzzing::MakeSection(1, 0x01U | 0x02U | 0x04U, 0x900df00dU, section_body);
  return weavebundle::fuzzing::MakeContainer({section}, 1, 1, 0x1337c0deU);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(data, size));

  const std::vector<std::uint8_t> wrapped = MakeWrappedInput(data, size);
  weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(wrapped));
  return 0;
}
