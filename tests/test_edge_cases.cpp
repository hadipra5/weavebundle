#include "../fuzz/fuzz_helpers.h"
#include "../src/parser.h"
#include "check.h"

#include <algorithm>
#include <limits>

using Bytes = std::vector<std::uint8_t>;
using weavebundle::ErrorCode;
using weavebundle::ParseContainer;
namespace wf = weavebundle::fuzzing;

Bytes Wrap(const Bytes& body, std::uint8_t flags = 4) {
  return wf::MakeContainer({wf::MakeSection(1, flags, 1, body)}, 1, 1, 1);
}

Bytes Rle(std::uint32_t expected, const Bytes& compressed) {
  Bytes body = {0, 0, 0, 0, 2};
  wf::AppendU32(&body, expected);
  wf::AppendU32(&body, static_cast<std::uint32_t>(compressed.size()));
  body.insert(body.end(), compressed.begin(), compressed.end());
  return Wrap(body);
}

void ExpectError(const Bytes& bytes, ErrorCode code) {
  const auto result = ParseContainer(bytes);
  CHECK(!result.ok);
  CHECK(result.error.code == code);
  CHECK(result.error.offset <= bytes.size());
  CHECK(!result.error.message.empty());
}

void SetU32(Bytes* bytes, std::size_t offset, std::uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) (*bytes)[offset + i] = static_cast<std::uint8_t>(value >> (i * 8U));
}

void RepairHeader(Bytes* bytes) {
  SetU32(bytes, 20, weavebundle::ComputeChecksum32(bytes->data(), 20));
}

void TestRle() {
  CHECK(ParseContainer(Rle(0, {})).ok);
  CHECK(ParseContainer(Rle(0, {0, 'A'})).ok);
  const auto valid = ParseContainer(Rle(5, {2, 'A', 0, 'X', 3, 'B'}));
  CHECK(valid.ok);
  CHECK(valid.document.sections[0].payload.unpacked == Bytes({'A', 'A', 'B', 'B', 'B'}));
  ExpectError(Rle(0, {1}), ErrorCode::kInvalidFormat);
  ExpectError(Rle(1, {2, 'A'}), ErrorCode::kInvalidLength);
  ExpectError(Rle(3, {2, 'A'}), ErrorCode::kInvalidLength);
  ExpectError(Rle(1U << 20, {}), ErrorCode::kInvalidLength);
  ExpectError(Rle((1U << 20) + 1, {}), ErrorCode::kInvalidLength);

  Bytes compressed;
  std::uint32_t remaining = 1U << 20;
  while (remaining > 0) {
    const auto run = static_cast<std::uint8_t>(std::min(remaining, 255U));
    compressed.push_back(run);
    compressed.push_back('Z');
    remaining -= run;
  }
  const auto maximum = ParseContainer(Rle(1U << 20, compressed));
  CHECK(maximum.ok);
  CHECK(maximum.document.sections[0].payload.unpacked.size() == (1U << 20));
  CHECK(maximum.document.sections[0].payload.unpacked.back() == 'Z');
}

void TestHeadersAndBounds() {
  CHECK(!ParseContainer(nullptr, 0).ok);
  CHECK(!ParseContainer(nullptr, 100).ok);
  for (std::uint8_t version : {1, 2}) CHECK(ParseContainer(wf::MakeContainer({}, version, 1, 0)).ok);
  for (std::uint8_t version : {0, 3}) ExpectError(wf::MakeContainer({}, version, 1, 0), ErrorCode::kUnsupportedVersion);

  const Bytes valid = Wrap({0, 0, 0, 0, 0});
  for (std::size_t length = 0; length < valid.size(); ++length) {
    const Bytes truncated(valid.begin(), valid.begin() + static_cast<std::ptrdiff_t>(length));
    const auto result = ParseContainer(truncated);
    CHECK(!result.ok);
    CHECK(result.error.offset <= length);
  }
  Bytes changed = valid;
  changed.back() ^= 1;
  ExpectError(changed, ErrorCode::kInvalidBodyChecksum);
  changed[5] = 0;  // Bypass body checksum to independently test section checksum.
  RepairHeader(&changed);
  ExpectError(changed, ErrorCode::kInvalidSectionChecksum);
  changed = valid;
  changed[20] ^= 1;
  ExpectError(changed, ErrorCode::kInvalidHeaderChecksum);
  changed = valid;
  changed[0] = 'X';
  ExpectError(changed, ErrorCode::kInvalidMagic);
  changed = valid;
  changed[6] = 129;
  RepairHeader(&changed);
  ExpectError(changed, ErrorCode::kInvalidLength);
  changed = valid;
  SetU32(&changed, 8, std::numeric_limits<std::uint32_t>::max());
  RepairHeader(&changed);
  ExpectError(changed, ErrorCode::kInvalidLength);

  ExpectError(Wrap({0, 0, 1, 1, 0}), ErrorCode::kInvalidLength);  // 257 records.
  ExpectError(Wrap({1, 0, 0}), ErrorCode::kUnexpectedEof);  // Incomplete TLV.
  ExpectError(Wrap({0, 0, 0, 0, 3}), ErrorCode::kUnsupportedFeature);
  ExpectError(Wrap({0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}), ErrorCode::kInvalidLength);
  ExpectError(Wrap({0, 0, 0, 0, 0, 33, 0}, 12), ErrorCode::kInvalidLength);
  ExpectError(Wrap({0, 0, 0, 0, 0, 4, 0, 1}, 6), ErrorCode::kUnexpectedEof);

  const auto trailer = ParseContainer(Wrap({0, 0, 0, 0, 0, 0xaa, 0xbb}));
  CHECK(trailer.ok);
  CHECK(trailer.document.sections[0].trailer == Bytes({0xaa, 0xbb}));
}

void TestRecursion() {
  Bytes section = wf::MakeSection(1, 4, 1, {0, 0, 0, 0, 0});
  for (unsigned depth = 0; depth <= 9; ++depth) {
    const auto input = wf::MakeContainer({section}, 1, 1, 1);
    if (depth <= 8) CHECK(ParseContainer(input).ok);
    else ExpectError(input, ErrorCode::kRecursionLimitExceeded);
    Bytes body = {0, 0, 0, 0, 0, 1, 0};
    body.insert(body.end(), section.begin(), section.end());
    section = wf::MakeSection(1, 12, 1, body);
  }
}

void TestCursor() {
  const std::uint8_t data[] = {1, 2, 3, 4};
  weavebundle::Cursor cursor(data, sizeof(data), 0);
  CHECK(cursor.Skip(2));
  cursor.Advance(std::numeric_limits<std::size_t>::max());
  CHECK(cursor.offset() == sizeof(data));  // Must saturate, not wrap around.
  CHECK(cursor.remaining() == 0);
  CHECK(!cursor.Skip(1));
}

int main() {
  TestRle();
  TestHeadersAndBounds();
  TestRecursion();
  TestCursor();
  std::cout << checks_run << " checks passed\n";
}
