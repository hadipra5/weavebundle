#include "weavebundle/parser.h"

#include <cassert>
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

std::vector<std::uint8_t> MakeChildSection() {
  std::vector<std::uint8_t> body;
  AppendU16(&body, 0);
  AppendU16(&body, 0);
  AppendU16(&body, 0);
  AppendU8(&body, 0);

  std::vector<std::uint8_t> section;
  AppendU8(&section, 2);
  AppendU8(&section, 0x04);
  AppendU16(&section, 0);
  AppendU32(&section, static_cast<std::uint32_t>(body.size()));
  AppendU32(&section, 0x22222222U);
  AppendU32(&section, weavebundle::ComputeChecksum32(body.data(), body.size()));
  section.insert(section.end(), body.begin(), body.end());
  return section;
}

std::vector<std::uint8_t> MakeValidContainer() {
  std::vector<std::uint8_t> record_body;
  AppendU32(&record_body, 0xaabbccddU);
  AppendU8(&record_body, 1);
  AppendU8(&record_body, 0x44);
  AppendU8(&record_body, 2);
  AppendU8(&record_body, 'o');
  AppendU8(&record_body, 'k');
  AppendU16(&record_body, 4);
  AppendU8(&record_body, 'd');
  AppendU8(&record_body, 'a');
  AppendU8(&record_body, 't');
  AppendU8(&record_body, 'a');
  AppendU8(&record_body, 1);
  AppendU8(&record_body, 0x51);
  AppendU8(&record_body, 0);
  AppendU16(&record_body, 3);
  AppendU8(&record_body, 'x');
  AppendU8(&record_body, 'y');
  AppendU8(&record_body, 'z');

  std::vector<std::uint8_t> child_section = MakeChildSection();

  std::vector<std::uint8_t> section_body;
  AppendU16(&section_body, 4);
  AppendU8(&section_body, 'r');
  AppendU8(&section_body, 'o');
  AppendU8(&section_body, 'o');
  AppendU8(&section_body, 't');

  AppendU16(&section_body, 4);
  AppendU8(&section_body, 0x10);
  AppendU8(&section_body, 2);
  AppendU8(&section_body, 0xaa);
  AppendU8(&section_body, 0xbb);

  AppendU16(&section_body, 1);
  AppendU8(&section_body, 7);
  AppendU8(&section_body, 0x03);
  AppendU16(&section_body, static_cast<std::uint16_t>(record_body.size()));
  section_body.insert(section_body.end(), record_body.begin(), record_body.end());

  std::vector<std::uint8_t> compressed;
  AppendU8(&compressed, 2);
  AppendU8(&compressed, 'A');
  AppendU8(&compressed, 2);
  AppendU8(&compressed, 'B');

  AppendU8(&section_body, 2);
  AppendU32(&section_body, 4);
  AppendU32(&section_body, static_cast<std::uint32_t>(compressed.size()));
  section_body.insert(section_body.end(), compressed.begin(), compressed.end());

  AppendU16(&section_body, 1);
  section_body.insert(section_body.end(), child_section.begin(), child_section.end());

  AppendU16(&section_body, 3);
  AppendU8(&section_body, 0xde);
  AppendU8(&section_body, 0xad);
  AppendU8(&section_body, 0xbe);

  std::vector<std::uint8_t> section;
  const std::uint8_t flags = 0x01U | 0x02U | 0x04U | 0x08U;
  AppendU8(&section, 1);
  AppendU8(&section, flags);
  AppendU16(&section, 0);
  AppendU32(&section, static_cast<std::uint32_t>(section_body.size()));
  AppendU32(&section, 0x11111111U);
  AppendU32(&section, weavebundle::ComputeChecksum32(section_body.data(), section_body.size()));
  section.insert(section.end(), section_body.begin(), section_body.end());

  std::vector<std::uint8_t> file(24);
  file[0] = 'W';
  file[1] = 'V';
  file[2] = 'B';
  file[3] = 'F';
  file[4] = 1;
  file[5] = 1;
  file[6] = 1;
  file[7] = 0;

  const std::uint32_t directory_size = static_cast<std::uint32_t>(section.size());
  file[8] = static_cast<std::uint8_t>(directory_size & 0xffU);
  file[9] = static_cast<std::uint8_t>((directory_size >> 8U) & 0xffU);
  file[10] = static_cast<std::uint8_t>((directory_size >> 16U) & 0xffU);
  file[11] = static_cast<std::uint8_t>((directory_size >> 24U) & 0xffU);

  const std::uint32_t file_id = 0xcafebabeU;
  file[12] = static_cast<std::uint8_t>(file_id & 0xffU);
  file[13] = static_cast<std::uint8_t>((file_id >> 8U) & 0xffU);
  file[14] = static_cast<std::uint8_t>((file_id >> 16U) & 0xffU);
  file[15] = static_cast<std::uint8_t>((file_id >> 24U) & 0xffU);

  const std::uint32_t body_checksum = weavebundle::ComputeChecksum32(section.data(), section.size());
  file[16] = static_cast<std::uint8_t>(body_checksum & 0xffU);
  file[17] = static_cast<std::uint8_t>((body_checksum >> 8U) & 0xffU);
  file[18] = static_cast<std::uint8_t>((body_checksum >> 16U) & 0xffU);
  file[19] = static_cast<std::uint8_t>((body_checksum >> 24U) & 0xffU);

  const std::uint32_t header_checksum = weavebundle::ComputeChecksum32(file.data(), 20);
  file[20] = static_cast<std::uint8_t>(header_checksum & 0xffU);
  file[21] = static_cast<std::uint8_t>((header_checksum >> 8U) & 0xffU);
  file[22] = static_cast<std::uint8_t>((header_checksum >> 16U) & 0xffU);
  file[23] = static_cast<std::uint8_t>((header_checksum >> 24U) & 0xffU);

  file.insert(file.end(), section.begin(), section.end());
  return file;
}

}  // namespace

int main() {
  std::vector<std::uint8_t> valid = MakeValidContainer();
  const weavebundle::ParseResult ok = weavebundle::ParseContainer(valid);
  assert(ok.ok);
  assert(ok.document.sections.size() == 1U);
  assert(ok.document.sections[0].children.size() == 1U);
  assert(ok.document.sections[0].payload.unpacked.size() == 4U);
  assert(ok.document.sections[0].records.size() == 1U);
  assert(ok.document.sections[0].records[0].children.size() == 1U);

  valid[20] ^= 0xffU;
  const weavebundle::ParseResult bad_header = weavebundle::ParseContainer(valid);
  assert(!bad_header.ok);
  assert(bad_header.error.code == weavebundle::ErrorCode::kInvalidHeaderChecksum);

  valid = MakeValidContainer();
  valid[0] = 'B';
  const weavebundle::ParseResult bad_magic = weavebundle::ParseContainer(valid);
  assert(!bad_magic.ok);
  assert(bad_magic.error.code == weavebundle::ErrorCode::kInvalidMagic);

  return 0;
}
