#include "weavebundle/parser.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <vector>

namespace {

std::vector<std::uint8_t> ReadFile(const char* path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

void PrintSection(const weavebundle::Section& section, int depth) {
  const std::string indent(static_cast<std::size_t>(depth) * 2U, ' ');
  std::cout << indent << "section id=0x" << std::hex << section.section_id << std::dec
            << " type=" << static_cast<unsigned>(section.type)
            << " records=" << section.records.size()
            << " payload=" << section.payload.unpacked.size()
            << " children=" << section.children.size() << '\n';
  for (const auto& child : section.children) {
    PrintSection(child, depth + 1);
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " <file.wvbf>\n";
    return 1;
  }

  const std::vector<std::uint8_t> data = ReadFile(argv[1]);
  if (data.empty()) {
    std::cerr << "failed to read input file\n";
    return 1;
  }

  const weavebundle::ParseResult result = weavebundle::ParseContainer(data);
  if (!result.ok) {
    std::cerr << "parse error at offset " << result.error.offset
              << ": " << weavebundle::ErrorCodeToString(result.error.code)
              << " (" << result.error.message << ")\n";
    return 1;
  }

  std::cout << "version=" << static_cast<unsigned>(result.document.version)
            << " sections=" << result.document.sections.size()
            << " trailing=" << result.document.trailing_data.size() << '\n';
  for (const auto& section : result.document.sections) {
    PrintSection(section, 0);
  }
  return 0;
}
