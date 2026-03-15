#ifndef WEAVEBUNDLE_INTERNAL_PARSER_H_
#define WEAVEBUNDLE_INTERNAL_PARSER_H_

#include "weavebundle/parser.h"

#include <cstddef>
#include <cstdint>

namespace weavebundle {

class Cursor {
 public:
  Cursor(const std::uint8_t* data, std::size_t size, std::size_t base_offset);

  bool CanRead(std::size_t amount) const;
  bool ReadU8(std::uint8_t* value);
  bool ReadU16(std::uint16_t* value);
  bool ReadU32(std::uint32_t* value);
  bool ReadBytes(std::size_t amount, std::vector<std::uint8_t>* out);
  bool Skip(std::size_t amount);
  Cursor Slice(std::size_t amount) const;

  const std::uint8_t* current_data() const;
  const std::uint8_t* data() const;
  std::size_t size() const;
  std::size_t remaining() const;
  std::size_t offset() const;
  std::size_t absolute_offset() const;
  void Advance(std::size_t amount);

 private:
  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t offset_;
  std::size_t base_offset_;
};

}  // namespace weavebundle

#endif  // WEAVEBUNDLE_INTERNAL_PARSER_H_
