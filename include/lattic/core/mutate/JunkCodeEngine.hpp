#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lattic::core::mutate
{
struct JunkOptions
{
    // Instruction bytes to insert between real instructions. Any sequence that leaves the
    // architectural state untouched is valid; the defaults are all register self writes.
    std::size_t   minRunLength = 2;
    std::size_t   maxRunLength = 6;
    int           density       = 35;
    std::uint32_t seed          = 0x1BADB002;
};

struct JunkResult
{
    bool        success = false;
    std::string message;

    std::size_t originalSize = 0;
    std::size_t outputSize   = 0;
    std::size_t blocksInserted = 0;
};

// Inserts dead instruction runs into a byte block. The runs use only instructions that write
// to their own destination register, so the surrounding code cannot observe them. This is
// byte level junk for the whole image, not IR level, so it can be applied anywhere.
class JunkCodeEngine
{
public:
    JunkCodeEngine() = default;
    ~JunkCodeEngine() = default;

    // True for bytes that begin a branch, return or two byte opcode. Junk is never spliced
    // before one of these, so an inserted run cannot swallow an offset.
    static bool IsUnsafeBoundary(std::uint8_t byte);

    // True for bytes that begin a branch or return. A junk run itself must not start with
    // one of these; unlike IsUnsafeBoundary this allows a 0x0F prefix, because a two byte
    // opcode is only ambiguous in the input stream, not as the start of an inserted run.
    static bool IsControlFlow(std::uint8_t byte);

    JunkCodeEngine(const JunkCodeEngine&)            = delete;
    JunkCodeEngine& operator=(const JunkCodeEngine&) = delete;

    // Walks code, decoding nothing, and sprinkles runs at roughly the requested density
    // between bytes that look like instruction starts. Because nothing is decoded, this is
    // a blunter tool than the IR passes and should not be used where correctness matters.
    JunkResult Apply(const std::vector<std::uint8_t>& input, const JunkOptions& options,
                     std::vector<std::uint8_t>& output) const;

    static const std::vector<std::vector<std::uint8_t>>& Catalog();

    // Instruction aware insertion, for real code sections.
    //
    // The byte level Apply above is for blobs that are never executed. Running it over a
    // .text section would corrupt the program twice over: it can land in the middle of an
    // instruction, and every inserted byte shifts the relative displacements of the branches
    // that follow it. This variant decodes first, only ever inserts on an instruction
    // boundary, and refuses the whole region if it contains a relative branch, call or jump,
    // because those offsets cannot be fixed up here.
    JunkResult ApplyToCode(const std::uint8_t* code, std::size_t size,
                          const JunkOptions& options, std::vector<std::uint8_t>& output) const;
};
}
