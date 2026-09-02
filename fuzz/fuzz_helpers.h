#ifndef WEAVEBUNDLE_FUZZ_HELPERS_H_
#define WEAVEBUNDLE_FUZZ_HELPERS_H_

#include "weavebundle/parser.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace weavebundle {
namespace fuzzing {

constexpr std::size_t kMaxFuzzInputSize = 4096;

inline void AppendU8(std::vector<std::uint8_t>* out, std::uint8_t value) {
  out->push_back(value);
}

inline void AppendU16(std::vector<std::uint8_t>* out, std::uint16_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

inline void AppendU32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
  out->push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

inline std::uint8_t ByteAt(const std::uint8_t* data, std::size_t size, std::size_t index, std::uint8_t fallback) {
  return index < size ? data[index] : fallback;
}

inline std::uint16_t Bounded16(const std::uint8_t* data,
                               std::size_t size,
                               std::size_t index,
                               std::uint16_t modulus,
                               std::uint16_t fallback) {
  if (index + 1U >= size) {
    return fallback;
  }
  const std::uint16_t value = static_cast<std::uint16_t>(data[index]) |
                              (static_cast<std::uint16_t>(data[index + 1U]) << 8U);
  return modulus == 0 ? value : static_cast<std::uint16_t>(value % modulus);
}

inline bool ShouldSkipInput(std::size_t size) {
  return size > kMaxFuzzInputSize;
}

inline bool ShouldUseRawPath(const std::uint8_t* data, std::size_t size) {
  if (size == 0) {
    return false;
  }
  // Real WVBF corpus files start with 'W' (87), which never selected the old
  // modulo-based raw path. Preserve corpus replay and dictionary-built files.
  if (size >= 4 && data[0] == 'W' && data[1] == 'V' &&
      data[2] == 'B' && data[3] == 'F') {
    return true;
  }
  return (data[0] % 10U) < 3U;
}

inline std::uint8_t SelectFlags(std::uint8_t candidate, std::uint8_t allowed_mask, std::uint8_t required_mask) {
  return static_cast<std::uint8_t>((candidate & allowed_mask) | required_mask);
}

inline std::vector<std::uint8_t> MakeSection(std::uint8_t type,
                                             std::uint8_t flags,
                                             std::uint32_t section_id,
                                             const std::vector<std::uint8_t>& body) {
  std::vector<std::uint8_t> section;
  AppendU8(&section, type);
  AppendU8(&section, flags);
  AppendU16(&section, 0);
  AppendU32(&section, static_cast<std::uint32_t>(body.size()));
  AppendU32(&section, section_id);
  const std::uint32_t checksum = (flags & 0x04U) != 0U ? ComputeChecksum32(body.data(), body.size()) : 0U;
  AppendU32(&section, checksum);
  section.insert(section.end(), body.begin(), body.end());
  return section;
}

inline std::vector<std::uint8_t> MakeContainer(const std::vector<std::vector<std::uint8_t>>& sections,
                                               std::uint8_t version,
                                               std::uint8_t global_flags,
                                               std::uint32_t file_id) {
  std::vector<std::uint8_t> directory;
  for (const auto& section : sections) {
    directory.insert(directory.end(), section.begin(), section.end());
  }

  std::vector<std::uint8_t> file(24, 0);
  file[0] = 'W';
  file[1] = 'V';
  file[2] = 'B';
  file[3] = 'F';
  file[4] = version;
  file[5] = global_flags;
  file[6] = static_cast<std::uint8_t>(sections.size() & 0xffU);
  file[7] = static_cast<std::uint8_t>((sections.size() >> 8U) & 0xffU);

  const std::uint32_t directory_size = static_cast<std::uint32_t>(directory.size());
  file[8] = static_cast<std::uint8_t>(directory_size & 0xffU);
  file[9] = static_cast<std::uint8_t>((directory_size >> 8U) & 0xffU);
  file[10] = static_cast<std::uint8_t>((directory_size >> 16U) & 0xffU);
  file[11] = static_cast<std::uint8_t>((directory_size >> 24U) & 0xffU);

  file[12] = static_cast<std::uint8_t>(file_id & 0xffU);
  file[13] = static_cast<std::uint8_t>((file_id >> 8U) & 0xffU);
  file[14] = static_cast<std::uint8_t>((file_id >> 16U) & 0xffU);
  file[15] = static_cast<std::uint8_t>((file_id >> 24U) & 0xffU);

  const std::uint32_t body_checksum = ComputeChecksum32(directory.data(), directory.size());
  file[16] = static_cast<std::uint8_t>(body_checksum & 0xffU);
  file[17] = static_cast<std::uint8_t>((body_checksum >> 8U) & 0xffU);
  file[18] = static_cast<std::uint8_t>((body_checksum >> 16U) & 0xffU);
  file[19] = static_cast<std::uint8_t>((body_checksum >> 24U) & 0xffU);

  const std::uint32_t header_checksum = ComputeChecksum32(file.data(), 20);
  file[20] = static_cast<std::uint8_t>(header_checksum & 0xffU);
  file[21] = static_cast<std::uint8_t>((header_checksum >> 8U) & 0xffU);
  file[22] = static_cast<std::uint8_t>((header_checksum >> 16U) & 0xffU);
  file[23] = static_cast<std::uint8_t>((header_checksum >> 24U) & 0xffU);

  file.insert(file.end(), directory.begin(), directory.end());
  return file;
}

inline void ConsumeResult(const ParseResult& result) {
  if (!result.ok) {
    return;
  }

  volatile std::size_t sink = result.document.sections.size();
  for (const auto& section : result.document.sections) {
    sink += section.records.size();
    sink += section.payload.unpacked.size();
    sink += section.children.size();
    sink += section.footer.size();
    sink += section.trailer.size();
  }
  (void)sink;
}

}  // namespace fuzzing
}  // namespace weavebundle

#endif  // WEAVEBUNDLE_FUZZ_HELPERS_H_
