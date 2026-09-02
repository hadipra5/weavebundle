#ifndef WEAVEBUNDLE_FUZZ_BUILDERS_H_
#define WEAVEBUNDLE_FUZZ_BUILDERS_H_

#include "fuzz_helpers.h"

// Shared with regression tests so structured fuzzing cannot silently stop
// reaching its intended parser paths while the fuzz executables still run.
namespace weavebundle::fuzzing {
std::vector<std::uint8_t> MakeWrappedInput(const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> MakeRleContainer(const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> MakeSectionContainer(const std::uint8_t* data, std::size_t size);
std::vector<std::uint8_t> MakeFooterContainer(const std::uint8_t* data, std::size_t size);
}  // namespace weavebundle::fuzzing

#endif  // WEAVEBUNDLE_FUZZ_BUILDERS_H_
