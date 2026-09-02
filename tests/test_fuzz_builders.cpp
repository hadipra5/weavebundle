#include "../fuzz/fuzz_builders.h"
#include "check.h"

#include <string>

namespace wf = weavebundle::fuzzing;
using weavebundle::ParseContainer;
using weavebundle::PayloadMode;

void TestParser() {
  // All section/record flag combinations must remain structurally valid.
  for (unsigned flags = 0; flags < 16; ++flags) {
    for (unsigned record_flags : {0U, 2U}) {
      for (std::size_t size : {8U, 9U}) {
        std::vector<std::uint8_t> bytes(size, 0x55);
        bytes[5] = static_cast<std::uint8_t>(record_flags);
        bytes[6] = static_cast<std::uint8_t>(flags);
        const auto parsed = ParseContainer(wf::MakeWrappedInput(bytes.data(), bytes.size()));
        CHECK(parsed.ok);
        CHECK(parsed.document.sections.size() == 1);
        const auto& section = parsed.document.sections[0];
        CHECK(section.records.size() == 1);
        CHECK(section.records[0].children.size() == ((record_flags & 2U) ? 1U : 0U));
        CHECK(section.records[0].timestamp == 0x01020304U);
        CHECK(section.payload.mode == (size % 2U ? PayloadMode::kRaw : PayloadMode::kRle));
        CHECK(section.footer.size() == ((flags & 2U) ? 5U : 0U));
        CHECK(section.trailer.empty());
      }
    }
  }
  CHECK(ParseContainer(wf::MakeWrappedInput(nullptr, 0)).ok);
}

void TestRle() {
  const std::uint8_t bytes[] = {4, 0, 2, 'A', 2, 'B'};
  const auto parsed = ParseContainer(wf::MakeRleContainer(bytes, sizeof(bytes)));
  CHECK(parsed.ok);
  CHECK(parsed.document.sections[0].payload.mode == PayloadMode::kRle);
  CHECK(parsed.document.sections[0].payload.unpacked == std::vector<std::uint8_t>({'A', 'A', 'B', 'B'}));
  const std::uint8_t repaired[] = {0x84, 0, 2, 'A', 2, 'B'};
  const auto repaired_result = ParseContainer(wf::MakeRleContainer(repaired, sizeof(repaired)));
  CHECK(repaired_result.ok);
  CHECK(repaired_result.document.sections[0].payload.unpacked == parsed.document.sections[0].payload.unpacked);
  const std::uint8_t odd[] = {4, 0, 2};
  CHECK(ParseContainer(wf::MakeRleContainer(odd, sizeof(odd))).error.code == weavebundle::ErrorCode::kInvalidFormat);
  const std::uint8_t mismatch[] = {3, 0, 2, 'A'};
  CHECK(ParseContainer(wf::MakeRleContainer(mismatch, sizeof(mismatch))).error.code == weavebundle::ErrorCode::kInvalidLength);
}

void TestSection() {
  for (unsigned flags = 0; flags < 256; ++flags) {
    std::vector<std::uint8_t> bytes(32, static_cast<std::uint8_t>(flags));
    const auto parsed = ParseContainer(wf::MakeSectionContainer(bytes.data(), bytes.size()));
    CHECK(parsed.ok);
    const auto& root = parsed.document.sections[0];
    CHECK(root.children.size() == 1);
    CHECK(root.children[0].records.size() == 1);
    CHECK(root.children[0].records[0].metadata.size() == 1);
    CHECK(root.children[0].payload.mode == PayloadMode::kRaw);
    CHECK(root.trailer.empty());
  }
  CHECK(ParseContainer(wf::MakeSectionContainer(nullptr, 0)).ok);
}

void TestFooter() {
  for (unsigned flags = 0; flags < 256; ++flags) {
    std::vector<std::uint8_t> bytes(40, static_cast<std::uint8_t>(flags));
    const auto parsed = ParseContainer(wf::MakeFooterContainer(bytes.data(), bytes.size()));
    CHECK(parsed.ok);
    CHECK(parsed.document.version == 2);
    const auto& section = parsed.document.sections[0];
    CHECK(section.footer.size() == wf::Bounded16(bytes.data(), bytes.size(), 4, 64, 8));
    CHECK(section.trailer.size() == wf::Bounded16(bytes.data(), bytes.size(), 8, 32, 4));
  }
  CHECK(ParseContainer(wf::MakeFooterContainer(nullptr, 0)).ok);
}

void TestRouting() {
  const auto valid = wf::MakeContainer({}, 1, 1, 0);
  CHECK(wf::ShouldUseRawPath(valid.data(), valid.size()));
  CHECK(!wf::ShouldUseRawPath(nullptr, 0));
  CHECK(!wf::ShouldSkipInput(wf::kMaxFuzzInputSize));
  CHECK(wf::ShouldSkipInput(wf::kMaxFuzzInputSize + 1));
}

int main(int argc, char** argv) {
  CHECK(argc == 2);
  const std::string name = argv[1];
  if (name == "parser") TestParser();
  else if (name == "rle") TestRle();
  else if (name == "section") TestSection();
  else if (name == "footer") TestFooter();
  else if (name == "routing") TestRouting();
  else CHECK(false);
  std::cout << checks_run << " checks passed\n";
}
