#ifndef WEAVEBUNDLE_PARSER_H_
#define WEAVEBUNDLE_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace weavebundle {

enum class ErrorCode {
  kOk = 0,
  kUnexpectedEof,
  kInvalidMagic,
  kUnsupportedVersion,
  kInvalidHeaderChecksum,
  kInvalidBodyChecksum,
  kInvalidSectionChecksum,
  kInvalidLength,
  kInvalidFormat,
  kUnsupportedFeature,
  kRecursionLimitExceeded
};

enum class PayloadMode {
  kNone = 0,
  kRaw = 1,
  kRle = 2
};

struct ParseError {
  ErrorCode code = ErrorCode::kOk;
  std::size_t offset = 0;
  std::string message;
};

struct Attribute {
  std::uint8_t key = 0;
  std::vector<std::uint8_t> value;
};

struct NestedValue {
  std::uint8_t tag = 0;
  std::uint8_t flags = 0;
  std::vector<std::uint8_t> value;
};

struct Record {
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint32_t timestamp = 0;
  std::vector<Attribute> metadata;
  std::vector<std::uint8_t> data;
  std::vector<NestedValue> children;
};

struct PayloadBlock {
  PayloadMode mode = PayloadMode::kNone;
  std::vector<std::uint8_t> stored;
  std::vector<std::uint8_t> unpacked;
};

struct Section {
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint32_t section_id = 0;
  std::string name;
  std::vector<Attribute> attributes;
  std::vector<Record> records;
  PayloadBlock payload;
  std::vector<Section> children;
  std::vector<std::uint8_t> footer;
  std::vector<std::uint8_t> trailer;
};

struct Document {
  std::uint8_t version = 0;
  std::uint8_t global_flags = 0;
  std::uint32_t file_id = 0;
  std::uint32_t body_checksum = 0;
  std::uint32_t header_checksum = 0;
  std::vector<Section> sections;
  std::vector<std::uint8_t> trailing_data;
};

struct ParseResult {
  bool ok = false;
  Document document;
  ParseError error;
};

std::uint32_t ComputeChecksum32(const std::uint8_t* data, std::size_t size);
ParseResult ParseContainer(const std::uint8_t* data, std::size_t size);
ParseResult ParseContainer(const std::vector<std::uint8_t>& data);
std::string ErrorCodeToString(ErrorCode code);

}  // namespace weavebundle

#endif  // WEAVEBUNDLE_PARSER_H_
