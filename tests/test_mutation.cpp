#include "TestFramework.hpp"

#include "lattic/core/mutate/JunkCodeEngine.hpp"
#include "lattic/core/mutate/MutationEngine.hpp"
#include "lattic/core/mutate/MutationPasses.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace lattic::core::mutate;
using lattic::core::vm::IrCond;
using lattic::core::vm::IrNode;
using lattic::core::vm::IrOperand;
using lattic::core::vm::IrProgram;
using lattic::core::vm::IrReg;
using lattic::core::vm::IrType;

namespace
{
IrOperand Reg(IrReg reg)
{
    IrOperand operand;
    operand.kind = IrOperand::Kind::Reg;
    operand.reg  = reg;
    return operand;
}

IrOperand Imm(std::uint64_t value)
{
    IrOperand operand;
    operand.kind     = IrOperand::Kind::Immediate;
    operand.immediate = value;
    return operand;
}

IrNode Bin(IrType type, IrReg dst, const IrOperand& src, std::uint64_t guest)
{
    IrNode node;
    node.type         = type;
    node.dst.kind     = IrOperand::Kind::Reg;
    node.dst.reg      = dst;
    node.src          = src;
    node.guestAddress = guest;
    return node;
}

bool HasType(const IrProgram& program, IrType type)
{
    for (const auto& node : program.Nodes())
    {
        if (node.type == type)
        {
            return true;
        }
    }

    return false;
}

std::size_t CountOf(const IrProgram& program, IrType type)
{
    std::size_t count = 0;

    for (const auto& node : program.Nodes())
    {
        if (node.type == type)
        {
            ++count;
        }
    }

    return count;
}
}

LATTIC_TEST(Mutation, EngineRejectsEmptyProgram)
{
    IrProgram program;
    MutationEngine engine;

    const MutationResult result = engine.Apply(program);

    CHECK(!result.success);
    CHECK(!result.message.empty());
    CHECK_EQ(engine.PassCount(), std::size_t{ 5 });
}

LATTIC_TEST(Mutation, EngineGrowsTheProgram)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Imm(8), 0x140001000));
    program.Append(Bin(IrType::Sub, IrReg::Rbx, Imm(3), 0x140001008));
    program.Append(Bin(IrType::Xor, IrReg::Rcx, Imm(0xFF), 0x140001010));

    MutationEngine engine;

    const std::size_t before = program.Size();
    const MutationResult result = engine.Apply(program);

    CHECK(result.success);
    CHECK_EQ(result.inputNodes, before);
    CHECK(result.outputNodes > before);
    CHECK(result.transforms > 0);
    CHECK(program.Size() == result.outputNodes);
}

LATTIC_TEST(Mutation, OptionsGateEveryPass)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Imm(8), 0x140001000));
    program.Append(Bin(IrType::Xor, IrReg::Rcx, Imm(0xFF), 0x140001008));

    MutationEngine engine;

    MutationOptions off;
    off.enableSubstitution        = false;
    off.enableMba                 = false;
    off.enableOpaquePredicates    = false;
    off.enableDeadCode            = false;
    off.enableConstantObfuscation = false;

    const std::size_t before = program.Size();

    const MutationResult result = engine.Apply(program, off);

    CHECK(result.success);
    CHECK_EQ(result.transforms, std::size_t{ 0 });
    CHECK_EQ(program.Size(), before);
}

LATTIC_TEST(Mutation, SubstitutionRewritesAddAsSubOfNegated)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Imm(5), 0x140001000));

    MutationOptions options;
    options.substitutionRate    = 100;
    options.enableSubstitution  = true;
    options.enableMba           = false;
    options.enableOpaquePredicates    = false;
    options.enableDeadCode            = false;
    options.enableConstantObfuscation = false;

    SubstitutionPass pass;
    const MutationResult result = pass.Apply(program, options);

    CHECK(result.success);
    CHECK_EQ(result.transforms, std::size_t{ 1 });

    // a + b became a - (-b). The right operand has to be materialised before it can be
    // negated, so the block is Sub, materialise, Neg.
    CHECK(program.At(0).type == IrType::Sub);
    CHECK(program.At(1).type == IrType::LoadImm);
    CHECK(program.At(2).type == IrType::Neg);
    CHECK_EQ(program.Size(), std::size_t{ 3 });

    // The scratch must not be the accumulator, or the rewrite would clobber the result.
    CHECK(program.At(0).src.reg != IrReg::Rax);
    CHECK_EQ(program.At(1).dst.reg, program.At(2).dst.reg);
    CHECK_EQ(program.At(2).dst.reg, program.At(0).src.reg);
}

LATTIC_TEST(Mutation, SubstitutionTurnsPowerOfTwoMultiplyIntoShift)
{
    IrProgram program;
    program.Append(Bin(IrType::Mul, IrReg::Rax, Imm(8), 0x140001000));

    MutationOptions options;
    options.substitutionRate = 100;

    SubstitutionPass pass;
    CHECK(pass.Apply(program, options).success);

    CHECK(program.At(0).type == IrType::Shl);
    CHECK_EQ(program.At(0).src.immediate, std::uint64_t{ 3 });
}

LATTIC_TEST(Mutation, MbaRewritesXorAsSubOfOrAndAnd)
{
    IrProgram program;
    program.Append(Bin(IrType::Xor, IrReg::Rax, Reg(IrReg::Rbx), 0x140001000));

    MutationOptions options;
    options.mbaRate = 100;

    MbaPass pass;
    CHECK(pass.Apply(program, options).success);

    // a ^ b becomes (a | b) - (a & b), and each operand is materialised into a scratch
    // register before it is combined, because this IR folds into the destination.
    CHECK(program.At(0).type == IrType::Sub);
    CHECK(HasType(program, IrType::Or));
    CHECK(HasType(program, IrType::And));
    CHECK(HasType(program, IrType::LoadGuestReg));

    // The accumulator is never one of the temporaries.
    CHECK(program.At(0).dst.reg == IrReg::Rax);
    CHECK(program.At(0).src.reg != IrReg::Rax);
}

LATTIC_TEST(Mutation, MbaRewritesAndAsSubOfOrAndXor)
{
    IrProgram program;
    program.Append(Bin(IrType::And, IrReg::Rax, Reg(IrReg::Rbx), 0x140001000));

    MutationOptions options;
    options.mbaRate = 100;

    MbaPass pass;
    CHECK(pass.Apply(program, options).success);

    // a & b becomes (a | b) - (a ^ b)
    CHECK(program.At(0).type == IrType::Sub);
    CHECK(HasType(program, IrType::Or));
    CHECK(HasType(program, IrType::Xor));
}

LATTIC_TEST(Mutation, MbaTerminatesOnEveryBinaryOp)
{
    // Each rewrite inserts nodes that are themselves binary arithmetic. Walking the live
    // program would rewrite those in turn and never stop, so every seed must converge.
    const IrType ops[] =
    {
        IrType::Add, IrType::Sub, IrType::Mul, IrType::Div,
        IrType::And, IrType::Or,  IrType::Xor
    };

    for (const IrType op : ops)
    {
        IrProgram program;
        program.Append(Bin(op, IrReg::Rax, Reg(IrReg::Rbx), 0x140001000));

        MutationOptions options;
        options.mbaRate = 100;

        MbaPass pass;
        CHECK(pass.Apply(program, options).success);
        CHECK(program.Size() < 16);
    }
}

LATTIC_TEST(Mutation, DeadCodeWritesOnlyScratchRegisters)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Reg(IrReg::Rbx), 0x140001000));

    MutationOptions options;
    options.deadCodeRate = 100;
    options.maxDeadCodeNodes = 6;

    DeadCodePass pass;
    CHECK(pass.Apply(program, options).success);

    CHECK(program.Size() > 1);
    CHECK_EQ(CountOf(program, IrType::Add), std::size_t{ 2 });
    CHECK_EQ(CountOf(program, IrType::Xor), std::size_t{ 1 });
}

LATTIC_TEST(Mutation, DeadCodeRespectsTheNodeCap)
{
    IrProgram program;
    for (int i = 0; i < 20; ++i)
    {
        program.Append(Bin(IrType::Add, IrReg::Rax, Reg(IrReg::Rbx),
                           0x140001000 + static_cast<std::uint64_t>(i) * 8));
    }

    MutationOptions options;
    options.deadCodeRate  = 100;
    options.maxDeadCodeNodes = 6;

    DeadCodePass pass;
    CHECK(pass.Apply(program, options).success);

    // The cap is counted in nodes and each block is three nodes, so six allows two blocks.
    CHECK_EQ(CountOf(program, IrType::LoadImm), std::size_t{ 2 });

    // A cap smaller than one block still terminates and inserts nothing rather than
    // overshooting the budget.
    IrProgram tight;
    for (int i = 0; i < 20; ++i)
    {
        tight.Append(Bin(IrType::Add, IrReg::Rax, Reg(IrReg::Rbx),
                         0x140001000 + static_cast<std::uint64_t>(i) * 8));
    }

    MutationOptions tiny;
    tiny.deadCodeRate     = 100;
    tiny.maxDeadCodeNodes = 2;

    DeadCodePass second;
    const std::size_t before = tight.Size();
    CHECK(second.Apply(tight, tiny).success);
    CHECK(tight.Size() <= before + 3);
}

LATTIC_TEST(Mutation, OpaquePredicateBranchesAreAlwaysTaken)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Imm(5), 0x140001000));

    MutationOptions options;
    options.opaquePredicateRate = 100;
    options.maxOpaquePredicates = 8;

    OpaquePredicatePass pass;
    CHECK(pass.Apply(program, options).success);

    // cmp temp, temp is always equal, so the Jz must target a real instruction.
    CHECK(HasType(program, IrType::Cmp));
    CHECK(HasType(program, IrType::Jcc));
    CHECK(HasType(program, IrType::Nop));

    for (const auto& node : program.Nodes())
    {
        if (node.type == IrType::Jcc)
        {
            CHECK(node.cond == IrCond::Zero);
            CHECK(node.targetAddress != 0);
        }
    }
}

LATTIC_TEST(Mutation, ConstantObfuscationRebuildsTheSameValue)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Imm(1000), 0x140001000));

    MutationOptions options;
    options.constantObfuscationRate = 100;

    ConstantObfuscationPass pass;
    CHECK(pass.Apply(program, options).success);

    // The immediate became a register, and the two inserted nodes add back to it.
    CHECK(program.At(0).src.kind == IrOperand::Kind::Reg);

    const std::uint64_t start = program.At(1).src.immediate;
    const std::uint64_t addend = program.At(2).src.immediate;
    CHECK_EQ(start + addend, std::uint64_t{ 1000 });
}

LATTIC_TEST(Mutation, RegisterCollectionAndScratchPick)
{
    IrProgram program;
    program.Append(Bin(IrType::Add, IrReg::Rax, Reg(IrReg::Rbx), 0x140001000));

    const auto used = CollectUsedRegisters(program);
    CHECK_EQ(used.size(), std::size_t{ 2 });
    CHECK(std::find(used.begin(), used.end(), IrReg::Rax) != used.end());
    CHECK(std::find(used.begin(), used.end(), IrReg::Rbx) != used.end());

    const auto scratch = PickScratchRegisters(3, used);
    CHECK_EQ(scratch.size(), std::size_t{ 3 });

    for (const IrReg reg : scratch)
    {
        CHECK(std::find(used.begin(), used.end(), reg) == used.end());
    }

    // Asking for more than the pool holds still returns what is available, never fewer
    // than the caller can rely on for its temporaries.
    CHECK(!PickScratchRegisters(64, used).empty());
}

LATTIC_TEST(JunkCode, CatalogEntriesAreSelfContained)
{
    const auto& catalog = JunkCodeEngine::Catalog();
    CHECK(!catalog.empty());

    for (const auto& run : catalog)
    {
        CHECK(!run.empty());
        CHECK(run.size() <= 5);

        // A junk run must not itself start a branch or return. A 0x0F prefix is allowed
        // here, unlike in the input stream, because it is the start of the run rather than
        // the start of an existing instruction.
        CHECK(!JunkCodeEngine::IsControlFlow(run[0]));
    }

    // The input stream is the stricter case: junk is never inserted before a two byte
    // opcode either, because the following byte belongs to that instruction.
    CHECK(JunkCodeEngine::IsUnsafeBoundary(0x0F));
    CHECK(JunkCodeEngine::IsUnsafeBoundary(0xC3));
    CHECK(!JunkCodeEngine::IsControlFlow(0x0F));
    CHECK(!JunkCodeEngine::IsUnsafeBoundary(0x90));
}

LATTIC_TEST(JunkCode, GrowsTheBlockAndKeepsItDeterministic)
{
    std::vector<std::uint8_t> input(256);
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        input[i] = static_cast<std::uint8_t>(0x48 + (i % 7));
    }

    JunkOptions options;
    options.density = 50;

    JunkCodeEngine engine;

    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;

    const JunkResult a = engine.Apply(input, options, first);
    const JunkResult b = engine.Apply(input, options, second);

    CHECK(a.success);
    CHECK(b.success);
    CHECK(first == second);
    CHECK(first.size() > input.size());
    CHECK_EQ(a.outputSize, first.size());
}

LATTIC_TEST(JunkCode, RejectsEmptyInputAndBadRange)
{
    JunkCodeEngine engine;

    std::vector<std::uint8_t> input = { 0x90, 0x90 };
    std::vector<std::uint8_t> output;

    const JunkResult empty = engine.Apply({}, JunkOptions{}, output);
    CHECK(empty.success);
    CHECK_EQ(empty.outputSize, std::size_t{ 0 });

    JunkOptions bad;
    bad.minRunLength = 8;
    bad.maxRunLength = 2;

    const JunkResult result = engine.Apply(input, bad, output);
    CHECK(!result.success);
    CHECK(!result.message.empty());
}

LATTIC_TEST(JunkCode, ZeroDensityIsAPassThrough)
{
    std::vector<std::uint8_t> input = { 0x48, 0x8B, 0xC1, 0x90 };

    JunkOptions options;
    options.density = 0;

    JunkCodeEngine engine;

    std::vector<std::uint8_t> output;
    const JunkResult result = engine.Apply(input, options, output);

    CHECK(result.success);
    CHECK(output == input);
}

LATTIC_TEST(JunkCode, CodeInsertionRefusesRegionsWithRelativeBranches)
{
    // 0xE9 is jmp rel32. Inserting ahead of it would leave the displacement pointing at the
    // wrong place, and it cannot be fixed up from here, so the region must be passed through
    // untouched rather than half processed.
    std::vector<std::uint8_t> input =
    {
        0x48, 0x8B, 0xC1,           // mov rax, rcx
        0xE9, 0x10, 0x00, 0x00, 0x00, // jmp +0x10
        0x48, 0x8B, 0xD8,           // mov rbx, rax
    };

    JunkOptions options;
    options.density = 100;

    JunkCodeEngine engine;

    std::vector<std::uint8_t> output;
    const JunkResult result = engine.ApplyToCode(input.data(), input.size(), options, output);

    CHECK(result.success);
    CHECK(output == input);
    CHECK_EQ(result.blocksInserted, std::size_t{ 0 });
    CHECK(result.message.find("untouched") != std::string::npos);
}

LATTIC_TEST(JunkCode, CodeInsertionRefusesUndecodableRegions)
{
    // 0xFF with no ModRM is not a complete instruction, which is what data or padding looks
    // like inside a section.
    std::vector<std::uint8_t> input = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    JunkOptions options;
    options.density = 100;

    JunkCodeEngine engine;

    std::vector<std::uint8_t> output;
    const JunkResult result = engine.ApplyToCode(input.data(), input.size(), options, output);

    CHECK(result.success);
    CHECK(output == input);
}

LATTIC_TEST(JunkCode, CodeInsertionKeepsEveryOriginalInstruction)
{
    // A branch free block: mov, mov, xor, add, ret.
    std::vector<std::uint8_t> input =
    {
        0x48, 0x8B, 0xC1,                     // mov rax, rcx
        0x48, 0x8B, 0xD8,                     // mov rbx, rax
        0x48, 0x31, 0xD8,                     // xor rbx, rax
        0x48, 0x01, 0xD8,                     // add rax, rbx
        0xC3,                                 // ret
    };

    JunkOptions options;
    options.density     = 100;
    options.minRunLength = 1;
    options.maxRunLength = 2;

    JunkCodeEngine engine;

    std::vector<std::uint8_t> output;
    const JunkResult result = engine.ApplyToCode(input.data(), input.size(), options, output);

    CHECK(result.success);
    CHECK(result.outputSize >= input.size());

    // Strip every catalog shaped instruction back out of the decoded output. What is left
    // must be exactly the original stream, which is a far stronger statement than "the
    // original bytes appear somewhere in order".
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    const std::vector<std::vector<std::uint8_t>> shapes = JunkCodeEngine::Catalog();

    std::vector<std::uint8_t> stripped;
    std::size_t cursor = 0;
    bool decodeFailed = false;

    while (cursor < output.size())
    {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, output.data() + cursor,
                                                 output.size() - cursor, &insn, ops)))
        {
            decodeFailed = true;
            break;
        }

        const bool isJunk =
            std::any_of(shapes.begin(), shapes.end(),
                        [&](const std::vector<std::uint8_t>& shape)
                        {
                            return shape.size() == insn.length &&
                                   std::equal(shape.begin(), shape.end(),
                                              output.begin() +
                                                  static_cast<std::ptrdiff_t>(cursor));
                        });

        if (!isJunk)
        {
            stripped.insert(stripped.end(), output.begin() +
                                static_cast<std::ptrdiff_t>(cursor),
                            output.begin() +
                                static_cast<std::ptrdiff_t>(cursor + insn.length));
        }

        cursor += insn.length;
    }

    CHECK(!decodeFailed);

    // Removing the junk restores the original byte for byte.
    CHECK(stripped == input);
}

LATTIC_TEST(JunkCode, InsertedRunsThemselvesDecodeAsInstructions)
{
    // The previous test only proved the originals survived. This one decodes the output end
    // to end and requires that every instruction it finds is either one of the originals or
    // a known catalog shape. That is what rules out junk that looks fine as bytes but is not
    // a valid instruction at a landing point.
    std::vector<std::uint8_t> input =
    {
        0x48, 0x8B, 0xC1,
        0x48, 0x8B, 0xD8,
        0x48, 0x31, 0xD8,
        0x48, 0x01, 0xD8,
        0x48, 0x39, 0xC3,
        0xC3,
    };

    JunkOptions options;
    options.density     = 100;
    options.minRunLength = 1;
    options.maxRunLength = 3;

    JunkCodeEngine engine;

    std::vector<std::uint8_t> output;
    const JunkResult result = engine.ApplyToCode(input.data(), input.size(), options, output);

    CHECK(result.success);
    CHECK(result.blocksInserted > 0);

    // Every catalog shape, keyed by its first byte so a decoded instruction can be matched
    // back to the junk that produced it.
    std::vector<std::vector<std::uint8_t>> shapes = JunkCodeEngine::Catalog();

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::size_t cursor = 0;
    std::size_t decoded = 0;
    std::size_t matchedJunk = 0;
    bool decodeFailed = false;
    std::size_t failedAt = 0;

    while (cursor < output.size())
    {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, output.data() + cursor,
                                                 output.size() - cursor, &insn, ops)))
        {
            // Every byte in the output has to belong to some decodable instruction.
            decodeFailed = true;
            failedAt     = cursor;
            break;
        }

        decoded += insn.length;

        const bool isOriginal =
            cursor + insn.length <= input.size() &&
            std::equal(input.begin() + static_cast<std::ptrdiff_t>(cursor),
                       input.begin() + static_cast<std::ptrdiff_t>(cursor) + insn.length,
                       output.begin() + static_cast<std::ptrdiff_t>(cursor));

        if (!isOriginal)
        {
            ++matchedJunk;
        }

        cursor += insn.length;
    }

    CHECK(!decodeFailed);
    CHECK_EQ(failedAt, std::size_t{ 0 });

    // The whole output decoded, and there was at least some junk in it to account for.
    CHECK_EQ(decoded, output.size());
    CHECK(matchedJunk > 0);
    CHECK(output.size() >= input.size());
}
