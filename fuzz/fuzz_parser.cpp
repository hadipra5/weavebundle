#include "weavebundle/parser.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

void AppendU8(std::vector<std::uint8_t>* out, std::uint8_t value) {
  out->push_back(value);
}

void AppendU16(std::vector<std::uint8_t>* out, std::uint16_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void AppendU32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

std::vector<std::uint8_t> MakeWrappedInput(const std::uint8_t* data, std::size_t size) {
  std::vector<std::uint8_t> record_body;
  const std::uint8_t metadata_value = size > 0 ? data[0] : 0;
  const std::uint8_t nested_value = size > 1 ? data[1] : 0x41;

  AppendU32(&record_body, 0x01020304U);
  AppendU8(&record_body, 1);
  AppendU8(&record_body, 0x10);
  AppendU8(&record_body, 1);
  AppendU8(&record_body, metadata_value);

  const std::uint16_t record_data_len = static_cast<std::uint16_t>(size > 24 ? 24 : size);
  AppendU16(&record_body, record_data_len);
  for (std::uint16_t i = 0; i < record_data_len; ++i) {
    AppendU8(&record_body, data[i]);
  }

  AppendU8(&record_body, 1);
  AppendU8(&record_body, 0x21);
  AppendU8(&record_body, 0);
  AppendU16(&record_body, 3);
  AppendU8(&record_body, 'N');
  AppendU8(&record_body, nested_value);
  AppendU8(&record_body, 'D');

  std::vector<std::uint8_t> section_body;
  AppendU16(&section_body, 4);
  AppendU8(&section_body, 's');
  AppendU8(&section_body, 'e');
  AppendU8(&section_body, 'e');
  AppendU8(&section_body, 'd');

  AppendU16(&section_body, 3);
  AppendU8(&section_body, 0x01);
  AppendU8(&section_body, 1);
  AppendU8(&section_body, size > 2 ? data[2] : 0x7f);

  AppendU16(&section_body, 1);
  AppendU8(&section_body, 0x30);
  AppendU8(&section_body, 0x03);
  AppendU16(&section_body, static_cast<std::uint16_t>(record_body.size()));
  section_body.insert(section_body.end(), record_body.begin(), record_body.end());

  const bool use_rle = (size % 2U) == 0U;
  if (use_rle) {
    std::vector<std::uint8_t> compressed;
    const std::uint8_t first = size > 3 ? data[3] : 0x42;
    const std::uint8_t second = size > 4 ? data[4] : 0x24;
    AppendU8(&compressed, 2);
    AppendU8(&compressed, first);
    AppendU8(&compressed, 2);
    AppendU8(&compressed, second);
    AppendU8(&section_body, 2);
    AppendU32(&section_body, 4);
    AppendU32(&section_body, static_cast<std::uint32_t>(compressed.size()));
    section_body.insert(section_body.end(), compressed.begin(), compressed.end());
  } else {
    AppendU8(&section_body, 1);
    const std::uint32_t payload_len = static_cast<std::uint32_t>(size > 32 ? 32 : size);
    AppendU32(&section_body, payload_len);
    section_body.insert(section_body.end(), data, data + payload_len);
  }

  AppendU16(&section_body, 2);
  AppendU8(&section_body, 0xaa);
  AppendU8(&section_body, 0x55);

  std::vector<std::uint8_t> section;
  const std::uint8_t flags = 0x01U | 0x02U | 0x04U;
  AppendU8(&section, 1);
  AppendU8(&section, flags);
  AppendU16(&section, 0);
  AppendU32(&section, static_cast<std::uint32_t>(section_body.size()));
  AppendU32(&section, 0x900df00dU);
  AppendU32(&section, weavebundle::ComputeChecksum32(section_body.data(), section_body.size()));
  section.insert(section.end(), section_body.begin(), section_body.end());

  std::vector<std::uint8_t> wrapped;
  wrapped.resize(24);
  wrapped[0] = 'W';
  wrapped[1] = 'V';
  wrapped[2] = 'B';
  wrapped[3] = 'F';
  wrapped[4] = 1;
  wrapped[5] = 1;
  wrapped[6] = 1;
  wrapped[7] = 0;

  const std::uint32_t directory_size = static_cast<std::uint32_t>(section.size());
  wrapped[8] = static_cast<std::uint8_t>(directory_size & 0xffU);
  wrapped[9] = static_cast<std::uint8_t>((directory_size >> 8U) & 0xffU);
  wrapped[10] = static_cast<std::uint8_t>((directory_size >> 16U) & 0xffU);
  wrapped[11] = static_cast<std::uint8_t>((directory_size >> 24U) & 0xffU);

  const std::uint32_t file_id = 0x1337c0deU;
  wrapped[12] = static_cast<std::uint8_t>(file_id & 0xffU);
  wrapped[13] = static_cast<std::uint8_t>((file_id >> 8U) & 0xffU);
  wrapped[14] = static_cast<std::uint8_t>((file_id >> 16U) & 0xffU);
  wrapped[15] = static_cast<std::uint8_t>((file_id >> 24U) & 0xffU);

  const std::uint32_t body_checksum = weavebundle::ComputeChecksum32(section.data(), section.size());
  wrapped[16] = static_cast<std::uint8_t>(body_checksum & 0xffU);
  wrapped[17] = static_cast<std::uint8_t>((body_checksum >> 8U) & 0xffU);
  wrapped[18] = static_cast<std::uint8_t>((body_checksum >> 16U) & 0xffU);
  wrapped[19] = static_cast<std::uint8_t>((body_checksum >> 24U) & 0xffU);

  const std::uint32_t header_checksum = weavebundle::ComputeChecksum32(wrapped.data(), 20);
  wrapped[20] = static_cast<std::uint8_t>(header_checksum & 0xffU);
  wrapped[21] = static_cast<std::uint8_t>((header_checksum >> 8U) & 0xffU);
  wrapped[22] = static_cast<std::uint8_t>((header_checksum >> 16U) & 0xffU);
  wrapped[23] = static_cast<std::uint8_t>((header_checksum >> 24U) & 0xffU);

  wrapped.insert(wrapped.end(), section.begin(), section.end());
  return wrapped;
}

void ConsumeResult(const weavebundle::ParseResult& result) {
  if (!result.ok) {
    return;
  }

  volatile std::size_t sink = result.document.sections.size();
  for (const auto& section : result.document.sections) {
    sink += section.records.size();
    sink += section.payload.unpacked.size();
    sink += section.children.size();
  }
  (void)sink;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  ConsumeResult(weavebundle::ParseContainer(data, size));

  const std::vector<std::uint8_t> wrapped = MakeWrappedInput(data, size);
  ConsumeResult(weavebundle::ParseContainer(wrapped));
  return 0;
}
