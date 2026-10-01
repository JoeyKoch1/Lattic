#include "lattic/core/mutate/JunkCodeEngine.hpp"

#include <Zydis/Zydis.h>

#include "lattic/util/Logger.hpp"

namespace lattic::core::mutate
{
namespace
{
struct Rng
{
    std::uint32_t state;

    explicit Rng(std::uint32_t seed) : state(seed != 0 ? seed : 1u)
    {
    }

    std::uint32_t Next()
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    }

    bool Chance(int percent)
    {
        if (percent <= 0)
        {
            return false;
        }

        if (percent >= 100)
        {
            return true;
        }

        return (Next() % 100u) < static_cast<std::uint32_t>(percent);
    }

    std::size_t Between(std::size_t lo, std::size_t hi)
    {
        if (hi <= lo)
        {
            return lo;
        }

        return lo + static_cast<std::size_t>(Next() % static_cast<std::uint32_t>(hi - lo + 1));
    }
};

// Bytes that would start a branch or a return are left alone so junk is never spliced into
// the middle of a displacement or an offset.
bool IsUnsafeBoundary(std::uint8_t byte)
{
    switch (byte)
    {
    case 0xC3:  // ret
    case 0xC2:  // ret imm16
    case 0xCA:  // retf
    case 0xCB:
    case 0xE8:  // call rel32
    case 0xE9:  // jmp rel32
    case 0xEB:  // jmp rel8
    case 0x0F:  // two byte opcode prefix
    case 0xFF:  // indirect call or jmp
        return true;
    default:
        return false;
    }
}
}

const std::vector<std::vector<std::uint8_t>>& JunkCodeEngine::Catalog()
{
    // Every entry must satisfy three properties, and the catalog was wrong until it did:
    //   1. it writes only the register named in its own opcode,
    //   2. it does not modify the flags, which later instructions may still read,
    //   3. it does not dereference memory, which could fault on an unmapped address.
    //
    // Several shapes that look like nops fail one of these in 64 bit mode and were removed:
    // 0x40 is a REX prefix rather than a nop, so a bare one swallows the next byte and
    // destroys the instruction boundary. D0 D8 is rcl al, 1, which writes al and the flags.
    // 0F 1F 00 is nop dword [eax], and 0F 1F 44 00 00 is nop dword [rax+rax], both of
    // which read memory at whatever the register happens to hold.
    static const std::vector<std::vector<std::uint8_t>> kCatalog =
    {
        { 0x90 },                         // nop
        { 0x66, 0x90 },                   // xchg ax, ax
        { 0x87, 0xC0 },                   // xchg eax, eax
        { 0x87, 0xDB },                   // xchg ebx, ebx
        { 0x87, 0xD2 },                   // xchg edx, edx
        { 0x87, 0xF6 },                   // xchg esi, esi
        { 0x87, 0xFF },                   // xchg edi, edi
        { 0x8B, 0xC0 },                   // mov eax, eax
        { 0x8B, 0xDB },                   // mov ebx, ebx
        { 0x8B, 0xF6 },                   // mov esi, esi
        { 0x8D, 0x40, 0x00 },             // lea eax, [rax+0]
        { 0x8D, 0x5B, 0x00 },             // lea ebx, [rbx+0]
    };

    return kCatalog;
}

bool JunkCodeEngine::IsControlFlow(std::uint8_t byte)
{
    switch (byte)
    {
    case 0xC3:  // ret
    case 0xC2:  // ret imm16
    case 0xCA:  // retf
    case 0xCB:  // retf imm16
    case 0xE8:  // call rel32
    case 0xE9:  // jmp rel32
    case 0xEB:  // jmp rel8
    case 0xFF:  // indirect call or jmp
        return true;
    default:
        return false;
    }
}

bool JunkCodeEngine::IsUnsafeBoundary(std::uint8_t byte)
{
    // A two byte opcode in the input is ambiguous: the byte after it belongs to the same
    // instruction, so inserting a run between them would corrupt the decode.
    return IsControlFlow(byte) || byte == 0x0F;
}

JunkResult JunkCodeEngine::ApplyToCode(const std::uint8_t* code, std::size_t size,
                                      const JunkOptions& options,
                                      std::vector<std::uint8_t>& output) const
{
    JunkResult result;
    result.originalSize = size;

    output.clear();

    if (code == nullptr || size == 0)
    {
        result.success   = true;
        result.outputSize = 0;
        result.message   = "Nothing to fill";
        return result;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    // Boundaries where a run may be inserted, that is, immediately after each instruction.
    std::vector<std::size_t> boundaries;

    std::size_t offset = 0;

    while (offset < size)
    {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

        // ZydisDecoderDecodeFull returns INVALID_ARGUMENT when the operand array is null,
        // which is indistinguishable from a genuine decode failure. Passing one is not
        // optional, and omitting it made this whole function a silent no-op.
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code + offset, size - offset,
                                                 &insn, ops)))
        {
            // The tail did not decode, which means this is data or padding rather than code.
            // Refusing here is the whole point: guessing would produce a corrupt binary.
            result.success   = true;
            result.outputSize = size;
            output.assign(code, code + size);
            result.message = "Code did not fully decode, region left untouched";
            return result;
        }

        // Any relative branch means every later displacement in this region would move when
        // a run is inserted ahead of it, and those offsets are not fixable from here.
        // A plain ret is excluded: Zydis classifies it as a near branch, but it carries no
        // displacement, so inserting ahead of one is harmless. Without this exclusion every
        // real function would be refused, because they all end in ret.
        const bool isRelativeBranch =
            insn.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT ||
            insn.meta.branch_type == ZYDIS_BRANCH_TYPE_NEAR;

        if (isRelativeBranch && insn.mnemonic != ZYDIS_MNEMONIC_RET)
        {
            result.success   = true;
            result.outputSize = size;
            output.assign(code, code + size);
            result.message = "Region contains relative branches, left untouched";
            return result;
        }

        offset += insn.length;
        boundaries.push_back(offset);
    }

    if (boundaries.empty())
    {
        result.success   = true;
        result.outputSize = size;
        output.assign(code, code + size);
        return result;
    }

    Rng rng(options.seed);
    const auto& catalog = Catalog();

    // Emit in a single forward pass so every boundary offset stays valid by construction.
    output.clear();
    output.reserve(size + size / 4);

    std::size_t emittedUpTo = 0;

    for (const std::size_t boundary : boundaries)
    {
        output.insert(output.end(), code + emittedUpTo, code + boundary);
        emittedUpTo = boundary;

        if (boundary >= size)
        {
            continue;
        }

        if (!rng.Chance(options.density))
        {
            continue;
        }

        const std::size_t length = rng.Between(options.minRunLength, options.maxRunLength);

        for (std::size_t k = 0; k < length; ++k)
        {
            const auto& shape = catalog[rng.Next() % static_cast<std::uint32_t>(catalog.size())];
            output.insert(output.end(), shape.begin(), shape.end());
        }

        ++result.blocksInserted;
    }

    output.insert(output.end(), code + emittedUpTo, code + size);

    result.outputSize = output.size();
    result.success    = true;
    result.message    = "Inserted " + std::to_string(result.blocksInserted) +
                        " junk run(s) on instruction boundaries, " +
                        std::to_string(size) + " -> " + std::to_string(result.outputSize) +
                        " bytes";

    util::Logger::Info("JunkCodeEngine: " + result.message);
    return result;
}

JunkResult JunkCodeEngine::Apply(const std::vector<std::uint8_t>& input,
                                 const JunkOptions& options,
                                 std::vector<std::uint8_t>& output) const
{
    JunkResult result;
    result.originalSize = input.size();

    output.clear();
    output.reserve(input.size() + input.size() / 4);

    if (input.empty())
    {
        result.success = true;
        result.outputSize = 0;
        result.message = "Nothing to fill";
        return result;
    }

    if (options.minRunLength == 0 || options.maxRunLength < options.minRunLength)
    {
        result.message = "JunkOptions: invalid run length range";
        return result;
    }

    Rng rng(options.seed);

    const auto& catalog = Catalog();

    for (std::size_t i = 0; i < input.size(); ++i)
    {
        const std::uint8_t byte = input[i];
        output.push_back(byte);

        // Never insert before a byte that begins a branch, and never on the last byte, so
        // the run cannot swallow an offset.
        if (i + 1 >= input.size() || IsUnsafeBoundary(input[i + 1]))
        {
            continue;
        }

        if (!rng.Chance(options.density))
        {
            continue;
        }

        const std::size_t length = rng.Between(options.minRunLength, options.maxRunLength);

        for (std::size_t k = 0; k < length; ++k)
        {
            const auto& run = catalog[rng.Next() % static_cast<std::uint32_t>(catalog.size())];
            output.insert(output.end(), run.begin(), run.end());
        }

        ++result.blocksInserted;
    }

    result.outputSize   = output.size();
    result.success      = true;
    result.message      = "Inserted " + std::to_string(result.blocksInserted) + " junk run(s), " +
                          std::to_string(result.originalSize) + " -> " +
                          std::to_string(result.outputSize) + " bytes";

    util::Logger::Info("JunkCodeEngine: " + result.message);
    return result;
}
}
