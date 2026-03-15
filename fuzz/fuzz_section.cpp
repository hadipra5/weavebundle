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
  const std::uint8_t child_flags = weavebundle::fuzzing::SelectFlags(
      static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 0, 0x04) & 0x0fU), 0x04U, 0x04U);
  const std::uint8_t root_flags = weavebundle::fuzzing::SelectFlags(
      static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 1, 0x0d) & 0x0fU), 0x0fU, 0x0cU);
  const std::vector<std::uint8_t> leaf_body = MakeLeafBody(data, size, 0);
  const std::vector<std::uint8_t> child =
      weavebundle::fuzzing::MakeSection(2, child_flags, 0x53454302U, leaf_body);

  std::vector<std::uint8_t> root_body;
  if ((root_flags & 0x01U) != 0U) {
    weavebundle::fuzzing::AppendU16(&root_body, 4);
    weavebundle::fuzzing::AppendU8(&root_body, 'r');
    weavebundle::fuzzing::AppendU8(&root_body, 'o');
    weavebundle::fuzzing::AppendU8(&root_body, 'o');
    weavebundle::fuzzing::AppendU8(&root_body, 't');
  }

  weavebundle::fuzzing::AppendU16(&root_body, 3);
  weavebundle::fuzzing::AppendU8(&root_body, 0x01);
  weavebundle::fuzzing::AppendU8(&root_body, 1);
  weavebundle::fuzzing::AppendU8(&root_body, weavebundle::fuzzing::ByteAt(data, size, 0, 0x7f));

  weavebundle::fuzzing::AppendU16(&root_body, 0);
  weavebundle::fuzzing::AppendU8(&root_body, 0);
  if ((root_flags & 0x08U) != 0U) {
    weavebundle::fuzzing::AppendU16(&root_body, 1);
    root_body.insert(root_body.end(), child.begin(), child.end());
  }

  if ((root_flags & 0x02U) != 0U) {
    const std::uint16_t footer_len =
        static_cast<std::uint16_t>(weavebundle::fuzzing::ByteAt(data, size, 2, 3) % 12U);
    weavebundle::fuzzing::AppendU16(&root_body, footer_len);
    for (std::uint16_t i = 0; i < footer_len; ++i) {
      weavebundle::fuzzing::AppendU8(
          &root_body, weavebundle::fuzzing::ByteAt(data, size, 3U + i, static_cast<std::uint8_t>(0x60U + i)));
    }
  }

  const std::vector<std::uint8_t> root =
      weavebundle::fuzzing::MakeSection(1, root_flags, 0x53454301U, root_body);
  const std::uint8_t global_flags = static_cast<std::uint8_t>(weavebundle::fuzzing::ByteAt(data, size, 4, 1) & 0x01U);
  return weavebundle::fuzzing::MakeContainer({root}, 1, global_flags, 0x53454310U);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (weavebundle::fuzzing::ShouldSkipInput(size)) {
    return 0;
  }

  if (weavebundle::fuzzing::ShouldUseRawPath(data, size)) {
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(data, size));
  } else {
    weavebundle::fuzzing::ConsumeResult(weavebundle::ParseContainer(MakeSectionContainer(data, size)));
  }
  return 0;
}
