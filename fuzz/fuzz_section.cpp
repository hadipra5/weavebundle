#include "weavebundle/parser.h"
#include "fuzz_helpers.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

std::vector<std::uint8_t> MakeLeafBody(const std::uint8_t* data, std::size_t size, std::size_t offset) {
  std::vector<std::uint8_t> body;
  weavebundle::fuzzing::AppendU16(&body, 0);
  weavebundle::fuzzing::AppendU16(&body, 0);
  weavebundle::fuzzing::AppendU16(&body, 1);

  std::vector<std::uint8_t> record_body;
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body,
                                 weavebundle::fuzzing::ByteAt(data, size, offset, 0x11));
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body, 0x90);
  weavebundle::fuzzing::AppendU8(&record_body, 1);
  weavebundle::fuzzing::AppendU8(&record_body,
                                 weavebundle::fuzzing::ByteAt(data, size, offset + 1U, 0x22));

  const std::uint16_t data_len =
      static_cast<std::uint16_t>(weavebundle::fuzzing::Bounded16(data, size, offset + 2U, 24, 4));
  weavebundle::fuzzing::AppendU16(&record_body, data_len);
  for (std::uint16_t i = 0; i < data_len; ++i) {
    weavebundle::fuzzing::AppendU8(
        &record_body, weavebundle::fuzzing::ByteAt(data, size, offset + 4U + i, static_cast<std::uint8_t>(i)));
  }

  weavebundle::fuzzing::AppendU8(&body, 0x41);
  weavebundle::fuzzing::AppendU8(&body, 0x01);
  weavebundle::fuzzing::AppendU16(&body, static_cast<std::uint16_t>(record_body.size()));
  body.insert(body.end(), record_body.begin(), record_body.end());

  weavebundle::fuzzing::AppendU8(&body, 1);
  weavebundle::fuzzing::AppendU32(&body, data_len);
  for (std::uint16_t i = 0; i < data_len; ++i) {
    weavebundle::fuzzing::AppendU8(
        &body, weavebundle::fuzzing::ByteAt(data, size, offset + 8U + i, static_cast<std::uint8_t>(0xa0U + i)));
  }
  return body;
}

std::vector<std::uint8_t> MakeSectionContainer(const std::uint8_t* data, std::size_t size) {
  const std::vector<std::uint8_t> leaf_body = MakeLeafBody(data, size, 0);
  const std::vector<std::uint8_t> child =
      weavebundle::fuzzing::MakeSection(2, 0x04U, 0x53454302U, leaf_body);

  std::vector<std::uint8_t> root_body;
  weavebundle::fuzzing::AppendU16(&root_body, 4);
  weavebundle::fuzzing::AppendU8(&root_body, 'r');
  weavebundle::fuzzing::AppendU8(&root_body, 'o');
  weavebundle::fuzzing::AppendU8(&root_body, 'o');
  weavebundle::fuzzing::AppendU8(&root_body, 't');

  weavebundle::fuzzing::AppendU16(&root_body, 3);
  weavebundle::fuzzing::AppendU8(&root_body, 0x01);
  weavebundle::fuzzing::AppendU8(&root_body, 1);
  weavebundle::fuzzing::AppendU8(&root_body, weavebundle::fuzzing::ByteAt(data, size, 0, 0x7f));

  weavebundle::fuzzing::AppendU16(&root_body, 0);
  weavebundle::fuzzing::AppendU8(&root_body, 0);
  weavebundle::fuzzing::AppendU16(&root_body, 1);
  root_body.insert(root_body.end(), child.begin(), child.end());

  const std::vector<std::uint8_t> root =
      weavebundle::fuzzing::MakeSection(1, 0x01U | 0x04U | 0x08U, 0x53454301U, root_body);
  return weavebundle::fuzzing::MakeContainer({root}, 1, 1, 0x53454310U);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(data, size));
  weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(MakeSectionContainer(data, size)));
  return 0;
}
