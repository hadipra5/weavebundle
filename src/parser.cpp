#include "parser.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace weavebundle {
namespace {

constexpr std::size_t kFileHeaderSize = 24;
constexpr std::size_t kSectionHeaderSize = 16;
constexpr std::size_t kMaxSections = 128;
constexpr std::size_t kMaxRecordsPerSection = 256;
constexpr std::size_t kMaxMetadataPerRecord = 64;
constexpr std::size_t kMaxChildrenPerRecord = 64;
constexpr std::size_t kMaxChildSections = 32;
constexpr std::size_t kMaxSectionBytes = 1U << 20;
constexpr std::size_t kMaxPayloadBytes = 1U << 20;
constexpr std::size_t kMaxRecursionDepth = 8;

constexpr std::uint8_t kSectionHasName = 0x01;
constexpr std::uint8_t kSectionHasFooter = 0x02;
constexpr std::uint8_t kSectionVerifyChecksum = 0x04;
constexpr std::uint8_t kSectionHasChildren = 0x08;

constexpr std::uint8_t kRecordHasTimestamp = 0x01;
constexpr std::uint8_t kRecordHasChildren = 0x02;

struct SectionHeader {
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint16_t reserved = 0;
  std::uint32_t body_size = 0;
  std::uint32_t section_id = 0;
  std::uint32_t checksum = 0;
};

ParseResult MakeErrorResult(ErrorCode code, std::size_t offset, const std::string& message) {
  ParseResult result;
  result.ok = false;
  result.error.code = code;
  result.error.offset = offset;
  result.error.message = message;
  return result;
}

bool CheckedAdd(std::size_t lhs, std::size_t rhs, std::size_t* out) {
  if (lhs > std::numeric_limits<std::size_t>::max() - rhs) {
    return false;
  }
  *out = lhs + rhs;
  return true;
}

bool ReadAttributeBlock(Cursor* cursor, std::vector<Attribute>* attributes, ParseError* error) {
  std::uint16_t attr_block_len = 0;
  if (!cursor->ReadU16(&attr_block_len)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Missing attribute block length"};
    return false;
  }

  Cursor attr_cursor = cursor->Slice(attr_block_len);
  if (!cursor->Skip(attr_block_len)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated attribute block"};
    return false;
  }

  while (attr_cursor.remaining() > 0) {
    Attribute attribute;
    std::uint8_t value_len = 0;
    if (!attr_cursor.ReadU8(&attribute.key) || !attr_cursor.ReadU8(&value_len)) {
      *error = {ErrorCode::kUnexpectedEof, attr_cursor.absolute_offset(), "Truncated attribute"};
      return false;
    }
    if (!attr_cursor.ReadBytes(value_len, &attribute.value)) {
      *error = {ErrorCode::kUnexpectedEof, attr_cursor.absolute_offset(), "Truncated attribute value"};
      return false;
    }
    attributes->push_back(std::move(attribute));
  }

  return true;
}

bool ParseNestedValue(Cursor* cursor, NestedValue* nested, ParseError* error) {
  std::uint16_t value_len = 0;
  if (!cursor->ReadU8(&nested->tag) || !cursor->ReadU8(&nested->flags) || !cursor->ReadU16(&value_len)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated nested value"};
    return false;
  }
  if (!cursor->ReadBytes(value_len, &nested->value)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Nested value exceeds section bounds"};
    return false;
  }
  return true;
}

bool ParseRecord(Cursor* cursor, Record* record, ParseError* error) {
  std::uint16_t record_size = 0;
  if (!cursor->ReadU8(&record->type) || !cursor->ReadU8(&record->flags) || !cursor->ReadU16(&record_size)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated record header"};
    return false;
  }

  Cursor record_cursor = cursor->Slice(record_size);
  if (!cursor->Skip(record_size)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated record body"};
    return false;
  }

  if ((record->flags & kRecordHasTimestamp) != 0) {
    if (!record_cursor.ReadU32(&record->timestamp)) {
      *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Missing record timestamp"};
      return false;
    }
  }

  std::uint8_t metadata_count = 0;
  if (!record_cursor.ReadU8(&metadata_count)) {
    *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Missing metadata count"};
    return false;
  }
  if (metadata_count > kMaxMetadataPerRecord) {
    *error = {ErrorCode::kInvalidLength, record_cursor.absolute_offset(), "Metadata count exceeds parser limit"};
    return false;
  }

  for (std::uint8_t i = 0; i < metadata_count; ++i) {
    Attribute attribute;
    std::uint8_t value_len = 0;
    if (!record_cursor.ReadU8(&attribute.key) || !record_cursor.ReadU8(&value_len)) {
      *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Truncated record metadata"};
      return false;
    }
    if (!record_cursor.ReadBytes(value_len, &attribute.value)) {
      *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Truncated record metadata value"};
      return false;
    }
    record->metadata.push_back(std::move(attribute));
  }

  std::uint16_t data_len = 0;
  if (!record_cursor.ReadU16(&data_len)) {
    *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Missing record data length"};
    return false;
  }
  if (!record_cursor.ReadBytes(data_len, &record->data)) {
    *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Truncated record payload"};
    return false;
  }

  if ((record->flags & kRecordHasChildren) != 0) {
    std::uint8_t child_count = 0;
    if (!record_cursor.ReadU8(&child_count)) {
      *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Missing nested child count"};
      return false;
    }
    if (child_count > kMaxChildrenPerRecord) {
      *error = {ErrorCode::kInvalidLength, record_cursor.absolute_offset(), "Nested child count exceeds parser limit"};
      return false;
    }
    for (std::uint8_t i = 0; i < child_count; ++i) {
      NestedValue nested;
      if (!ParseNestedValue(&record_cursor, &nested, error)) {
        return false;
      }
      record->children.push_back(std::move(nested));
    }
  }

  if (record_cursor.remaining() > 0) {
    std::vector<std::uint8_t> trailing;
    if (!record_cursor.ReadBytes(record_cursor.remaining(), &trailing)) {
      *error = {ErrorCode::kUnexpectedEof, record_cursor.absolute_offset(), "Failed to consume record trailer"};
      return false;
    }
    record->data.insert(record->data.end(), trailing.begin(), trailing.end());
  }

  return true;
}

bool ExpandRle(const std::vector<std::uint8_t>& compressed,
               std::uint32_t expected_output_len,
               std::vector<std::uint8_t>* out,
               ParseError* error,
               std::size_t offset) {
  if (expected_output_len > kMaxPayloadBytes) {
    *error = {ErrorCode::kInvalidLength, offset, "Expanded payload exceeds parser limit"};
    return false;
  }
  if ((compressed.size() % 2U) != 0U) {
    *error = {ErrorCode::kInvalidFormat, offset, "RLE payload must contain run-length pairs"};
    return false;
  }

  out->assign(expected_output_len, 0);
  std::size_t write_offset = 0;
  for (std::size_t i = 0; i < compressed.size(); i += 2) {
    const std::uint8_t run_len = compressed[i];
    const std::uint8_t value = compressed[i + 1];
    if (write_offset > expected_output_len || expected_output_len - write_offset < run_len) {
      *error = {ErrorCode::kInvalidLength, offset + i, "RLE run exceeds declared output length"};
      return false;
    }
    std::fill(out->begin() + static_cast<std::ptrdiff_t>(write_offset),
              out->begin() + static_cast<std::ptrdiff_t>(write_offset + run_len),
              value);
    write_offset += run_len;
  }

  if (write_offset != expected_output_len) {
    *error = {ErrorCode::kInvalidLength, offset, "Expanded payload does not match declared output length"};
    return false;
  }

  return true;
}

bool ParsePayload(Cursor* cursor, PayloadBlock* payload, ParseError* error) {
  std::uint8_t mode = 0;
  if (!cursor->ReadU8(&mode)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Missing payload mode"};
    return false;
  }

  if (mode > static_cast<std::uint8_t>(PayloadMode::kRle)) {
    *error = {ErrorCode::kUnsupportedFeature, cursor->absolute_offset() - 1U, "Unknown payload mode"};
    return false;
  }

  payload->mode = static_cast<PayloadMode>(mode);
  if (payload->mode == PayloadMode::kNone) {
    return true;
  }

  if (payload->mode == PayloadMode::kRaw) {
    std::uint32_t raw_len = 0;
    if (!cursor->ReadU32(&raw_len)) {
      *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Missing raw payload length"};
      return false;
    }
    if (raw_len > kMaxPayloadBytes) {
      *error = {ErrorCode::kInvalidLength, cursor->absolute_offset(), "Raw payload exceeds parser limit"};
      return false;
    }
    if (!cursor->ReadBytes(raw_len, &payload->stored)) {
      *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated raw payload"};
      return false;
    }
    payload->unpacked = payload->stored;
    return true;
  }

  std::uint32_t expected_output_len = 0;
  std::uint32_t compressed_len = 0;
  if (!cursor->ReadU32(&expected_output_len) || !cursor->ReadU32(&compressed_len)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Missing compressed payload header"};
    return false;
  }
  if (compressed_len > kMaxPayloadBytes) {
    *error = {ErrorCode::kInvalidLength, cursor->absolute_offset(), "Compressed payload exceeds parser limit"};
    return false;
  }
  if (!cursor->ReadBytes(compressed_len, &payload->stored)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated compressed payload"};
    return false;
  }
  return ExpandRle(payload->stored, expected_output_len, &payload->unpacked, error,
                   cursor->absolute_offset() - payload->stored.size());
}

bool ParseSection(Cursor* cursor, Section* section, std::size_t depth, ParseError* error);

bool ParseChildSections(Cursor* cursor,
                        std::vector<Section>* children,
                        std::size_t depth,
                        ParseError* error) {
  std::uint16_t child_count = 0;
  if (!cursor->ReadU16(&child_count)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Missing child section count"};
    return false;
  }
  if (child_count > kMaxChildSections) {
    *error = {ErrorCode::kInvalidLength, cursor->absolute_offset(), "Child section count exceeds parser limit"};
    return false;
  }

  for (std::uint16_t i = 0; i < child_count; ++i) {
    Section child;
    if (!ParseSection(cursor, &child, depth + 1U, error)) {
      return false;
    }
    children->push_back(std::move(child));
  }
  return true;
}

bool ParseSection(Cursor* cursor, Section* section, std::size_t depth, ParseError* error) {
  if (depth > kMaxRecursionDepth) {
    *error = {ErrorCode::kRecursionLimitExceeded, cursor->absolute_offset(), "Section nesting exceeds parser limit"};
    return false;
  }
  if (!cursor->CanRead(kSectionHeaderSize)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated section header"};
    return false;
  }

  SectionHeader header;
  if (!cursor->ReadU8(&header.type) || !cursor->ReadU8(&header.flags) || !cursor->ReadU16(&header.reserved) ||
      !cursor->ReadU32(&header.body_size) || !cursor->ReadU32(&header.section_id) ||
      !cursor->ReadU32(&header.checksum)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Failed to read section header"};
    return false;
  }
  if (header.body_size > kMaxSectionBytes) {
    *error = {ErrorCode::kInvalidLength, cursor->absolute_offset(), "Section body exceeds parser limit"};
    return false;
  }

  Cursor body = cursor->Slice(header.body_size);
  if (!cursor->Skip(header.body_size)) {
    *error = {ErrorCode::kUnexpectedEof, cursor->absolute_offset(), "Truncated section body"};
    return false;
  }

  if ((header.flags & kSectionVerifyChecksum) != 0) {
    const std::uint32_t computed = ComputeChecksum32(body.data(), body.size());
    if (computed != header.checksum) {
      *error = {ErrorCode::kInvalidSectionChecksum, body.absolute_offset(), "Section checksum mismatch"};
      return false;
    }
  }

  section->type = header.type;
  section->flags = header.flags;
  section->section_id = header.section_id;

  if ((header.flags & kSectionHasName) != 0) {
    std::uint16_t name_len = 0;
    if (!body.ReadU16(&name_len)) {
      *error = {ErrorCode::kUnexpectedEof, body.absolute_offset(), "Missing section name length"};
      return false;
    }
    std::vector<std::uint8_t> name_bytes;
    if (!body.ReadBytes(name_len, &name_bytes)) {
      *error = {ErrorCode::kUnexpectedEof, body.absolute_offset(), "Truncated section name"};
      return false;
    }
    section->name.assign(name_bytes.begin(), name_bytes.end());
  }

  if (!ReadAttributeBlock(&body, &section->attributes, error)) {
    return false;
  }

  std::uint16_t record_count = 0;
  if (!body.ReadU16(&record_count)) {
    *error = {ErrorCode::kUnexpectedEof, body.absolute_offset(), "Missing record count"};
    return false;
  }
  if (record_count > kMaxRecordsPerSection) {
    *error = {ErrorCode::kInvalidLength, body.absolute_offset(), "Record count exceeds parser limit"};
    return false;
  }

  for (std::uint16_t i = 0; i < record_count; ++i) {
    Record record;
    if (!ParseRecord(&body, &record, error)) {
      return false;
    }
    section->records.push_back(std::move(record));
  }

  if (!ParsePayload(&body, &section->payload, error)) {
    return false;
  }

  if ((header.flags & kSectionHasChildren) != 0) {
    if (!ParseChildSections(&body, &section->children, depth, error)) {
      return false;
    }
  }

  if ((header.flags & kSectionHasFooter) != 0) {
    std::uint16_t footer_len = 0;
    if (!body.ReadU16(&footer_len)) {
      *error = {ErrorCode::kUnexpectedEof, body.absolute_offset(), "Missing footer length"};
      return false;
    }
    if (!body.ReadBytes(footer_len, &section->footer)) {
      *error = {ErrorCode::kUnexpectedEof, body.absolute_offset(), "Truncated footer"};
      return false;
    }
  }

  if (body.remaining() > 0) {
    if (!body.ReadBytes(body.remaining(), &section->trailer)) {
      *error = {ErrorCode::kUnexpectedEof, body.absolute_offset(), "Failed to capture trailing section bytes"};
      return false;
    }
  }

  return true;
}

}  // namespace

Cursor::Cursor(const std::uint8_t* data, std::size_t size, std::size_t base_offset)
    : data_(data), size_(size), offset_(0), base_offset_(base_offset) {}

bool Cursor::CanRead(std::size_t amount) const {
  return amount <= remaining();
}

bool Cursor::ReadU8(std::uint8_t* value) {
  if (!CanRead(1)) {
    return false;
  }
  *value = data_[offset_];
  ++offset_;
  return true;
}

bool Cursor::ReadU16(std::uint16_t* value) {
  if (!CanRead(2)) {
    return false;
  }
  *value = static_cast<std::uint16_t>(data_[offset_]) |
           (static_cast<std::uint16_t>(data_[offset_ + 1]) << 8U);
  offset_ += 2;
  return true;
}

bool Cursor::ReadU32(std::uint32_t* value) {
  if (!CanRead(4)) {
    return false;
  }
  *value = static_cast<std::uint32_t>(data_[offset_]) |
           (static_cast<std::uint32_t>(data_[offset_ + 1]) << 8U) |
           (static_cast<std::uint32_t>(data_[offset_ + 2]) << 16U) |
           (static_cast<std::uint32_t>(data_[offset_ + 3]) << 24U);
  offset_ += 4;
  return true;
}

bool Cursor::ReadBytes(std::size_t amount, std::vector<std::uint8_t>* out) {
  if (!CanRead(amount)) {
    return false;
  }
  out->assign(data_ + offset_, data_ + offset_ + amount);
  offset_ += amount;
  return true;
}

bool Cursor::Skip(std::size_t amount) {
  if (!CanRead(amount)) {
    return false;
  }
  offset_ += amount;
  return true;
}

Cursor Cursor::Slice(std::size_t amount) const {
  const std::size_t slice_size = std::min(amount, remaining());
  return Cursor(data_ + offset_, slice_size, absolute_offset());
}

const std::uint8_t* Cursor::current_data() const {
  return data_ + offset_;
}

const std::uint8_t* Cursor::data() const {
  return data_;
}

std::size_t Cursor::size() const {
  return size_;
}

std::size_t Cursor::remaining() const {
  return size_ - offset_;
}

std::size_t Cursor::offset() const {
  return offset_;
}

std::size_t Cursor::absolute_offset() const {
  return base_offset_ + offset_;
}

void Cursor::Advance(std::size_t amount) {
  offset_ = std::min(size_, offset_ + amount);
}

std::uint32_t ComputeChecksum32(const std::uint8_t* data, std::size_t size) {
  std::uint32_t state = 2166136261U;
  for (std::size_t i = 0; i < size; ++i) {
    state ^= data[i];
    state *= 16777619U;
  }
  state ^= static_cast<std::uint32_t>(size);
  state *= 16777619U;
  return state;
}

ParseResult ParseContainer(const std::vector<std::uint8_t>& data) {
  return ParseContainer(data.data(), data.size());
}

ParseResult ParseContainer(const std::uint8_t* data, std::size_t size) {
  if (data == nullptr || size < kFileHeaderSize) {
    return MakeErrorResult(ErrorCode::kUnexpectedEof, 0, "Input is smaller than the file header");
  }

  Cursor cursor(data, size, 0);
  std::vector<std::uint8_t> magic;
  if (!cursor.ReadBytes(4, &magic)) {
    return MakeErrorResult(ErrorCode::kUnexpectedEof, 0, "Failed to read magic");
  }
  if (magic != std::vector<std::uint8_t>({'W', 'V', 'B', 'F'})) {
    return MakeErrorResult(ErrorCode::kInvalidMagic, 0, "Magic must be WVBF");
  }

  Document document;
  std::uint16_t section_count = 0;
  std::uint32_t directory_size = 0;
  if (!cursor.ReadU8(&document.version) || !cursor.ReadU8(&document.global_flags) ||
      !cursor.ReadU16(&section_count) || !cursor.ReadU32(&directory_size) ||
      !cursor.ReadU32(&document.file_id) || !cursor.ReadU32(&document.body_checksum) ||
      !cursor.ReadU32(&document.header_checksum)) {
    return MakeErrorResult(ErrorCode::kUnexpectedEof, cursor.absolute_offset(), "Failed to read file header");
  }

  if (document.version == 0 || document.version > 2) {
    return MakeErrorResult(ErrorCode::kUnsupportedVersion, 4, "Only format versions 1 and 2 are supported");
  }
  if (section_count > kMaxSections) {
    return MakeErrorResult(ErrorCode::kInvalidLength, 6, "Section count exceeds parser limit");
  }

  const std::uint32_t computed_header_checksum = ComputeChecksum32(data, 20);
  if (computed_header_checksum != document.header_checksum) {
    return MakeErrorResult(ErrorCode::kInvalidHeaderChecksum, 20, "Header checksum mismatch");
  }

  std::size_t body_end = 0;
  if (!CheckedAdd(kFileHeaderSize, directory_size, &body_end) || body_end > size) {
    return MakeErrorResult(ErrorCode::kInvalidLength, 8, "Directory size exceeds available input");
  }

  const std::uint32_t computed_body_checksum = ComputeChecksum32(data + kFileHeaderSize, directory_size);
  if (((document.global_flags & 0x01U) != 0U) && computed_body_checksum != document.body_checksum) {
    return MakeErrorResult(ErrorCode::kInvalidBodyChecksum, 16, "Body checksum mismatch");
  }

  Cursor body_cursor(data + kFileHeaderSize, directory_size, kFileHeaderSize);
  for (std::uint16_t i = 0; i < section_count; ++i) {
    Section section;
    ParseError error;
    if (!ParseSection(&body_cursor, &section, 0, &error)) {
      return MakeErrorResult(error.code, error.offset, error.message);
    }
    document.sections.push_back(std::move(section));
  }

  if (body_cursor.remaining() > 0) {
    if (!body_cursor.ReadBytes(body_cursor.remaining(), &document.trailing_data)) {
      return MakeErrorResult(ErrorCode::kUnexpectedEof, body_cursor.absolute_offset(),
                             "Failed to capture trailing document bytes");
    }
  }

  ParseResult result;
  result.ok = true;
  result.document = std::move(document);
  return result;
}

std::string ErrorCodeToString(ErrorCode code) {
  switch (code) {
    case ErrorCode::kOk:
      return "ok";
    case ErrorCode::kUnexpectedEof:
      return "unexpected_eof";
    case ErrorCode::kInvalidMagic:
      return "invalid_magic";
    case ErrorCode::kUnsupportedVersion:
      return "unsupported_version";
    case ErrorCode::kInvalidHeaderChecksum:
      return "invalid_header_checksum";
    case ErrorCode::kInvalidBodyChecksum:
      return "invalid_body_checksum";
    case ErrorCode::kInvalidSectionChecksum:
      return "invalid_section_checksum";
    case ErrorCode::kInvalidLength:
      return "invalid_length";
    case ErrorCode::kInvalidFormat:
      return "invalid_format";
    case ErrorCode::kUnsupportedFeature:
      return "unsupported_feature";
    case ErrorCode::kRecursionLimitExceeded:
      return "recursion_limit_exceeded";
  }
  return "unknown";
}

}  // namespace weavebundle
