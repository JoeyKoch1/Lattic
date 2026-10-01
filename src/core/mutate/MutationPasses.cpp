#include "lattic/core/mutate/MutationPasses.hpp"

#include <algorithm>

#include "lattic/util/Logger.hpp"

namespace lattic::core::mutate
{
using namespace lattic::core::vm;

namespace
{
// xorshift32, matching the encryptor so a seed reproduces the same output.
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

    std::uint64_t Value(std::uint64_t bound)
    {
        return bound == 0 ? 0 : static_cast<std::uint64_t>(Next() % static_cast<std::uint32_t>(bound));
    }
};

IrNode MakeBin(IrType type, IrReg dst, IrOperand src, std::uint64_t guest)
{
    IrNode node;
    node.type         = type;
    node.dst.kind     = IrOperand::Kind::Reg;
    node.dst.reg      = dst;
    node.src          = src;
    node.guestAddress = guest;
    return node;
}

IrOperand RegOperand(IrReg reg)
{
    IrOperand operand;
    operand.kind = IrOperand::Kind::Reg;
    operand.reg  = reg;
    return operand;
}

IrOperand ImmOperand(std::uint64_t value)
{
    IrOperand operand;
    operand.kind     = IrOperand::Kind::Immediate;
    operand.immediate = value;
    return operand;
}

bool IsBinaryArith(IrType type)
{
    switch (type)
    {
    case IrType::Add: case IrType::Sub: case IrType::Mul:
    case IrType::And: case IrType::Or:  case IrType::Xor:
        return true;
    default:
        return false;
    }
}

const IrReg kScratchPool[] =
{
    IrReg::R10, IrReg::R11, IrReg::R12, IrReg::R13, IrReg::R14, IrReg::R15,
    IrReg::Rbx, IrReg::Rcx, IrReg::Rdx, IrReg::Rsi, IrReg::Rdi, IrReg::Rbp
};
}

std::vector<IrReg> CollectUsedRegisters(const IrProgram& program)
{
    std::vector<IrReg> used;

    const auto note = [&used](IrReg reg)
    {
        if (reg == IrReg::None || reg == IrReg::Count)
        {
            return;
        }

        if (std::find(used.begin(), used.end(), reg) == used.end())
        {
            used.push_back(reg);
        }
    };

    for (const auto& node : program.Nodes())
    {
        note(node.dst.reg);
        note(node.src.reg);
        note(node.src.memBase);
        note(node.src.memIndex);
    }

    return used;
}

std::vector<IrReg> PickScratchRegisters(std::size_t count, const std::vector<IrReg>& used)
{
    std::vector<IrReg> picked;

    for (const IrReg candidate : kScratchPool)
    {
        if (picked.size() >= count)
        {
            break;
        }

        if (std::find(used.begin(), used.end(), candidate) == used.end() &&
            std::find(picked.begin(), picked.end(), candidate) == picked.end())
        {
            picked.push_back(candidate);
        }
    }

    // Fall back to whatever is left rather than silently producing fewer temporaries than
    // the pass asked for, which would emit a wrong program.
    for (const IrReg candidate : kScratchPool)
    {
        if (picked.size() >= count)
        {
            break;
        }

        if (std::find(picked.begin(), picked.end(), candidate) == picked.end())
        {
            picked.push_back(candidate);
        }
    }

    return picked;
}

MutationResult SubstitutionPass::Apply(IrProgram& program, const MutationOptions& options)
{
    MutationResult result;
    result.inputNodes  = program.Size();
    result.outputNodes = program.Size();

    Rng rng(options.seed);

    IrProgram source = program;

    // Every node this pass inserts lands after the current one, so the original index i maps
    // to i + shift in the live program.
    std::size_t shift = 0;

    for (std::size_t i = 0; i < source.Size(); ++i)
    {
        const std::size_t live = i + shift;
        IrNode node = source.At(i);

        if (!IsBinaryArith(node.type) || node.dst.kind != IrOperand::Kind::Reg)
        {
            continue;
        }

        if (!rng.Chance(options.substitutionRate))
        {
            continue;
        }

        const std::vector<IrReg> scratch = PickScratchRegisters(1, CollectUsedRegisters(program));

        if (scratch.empty())
        {
            break;
        }

        const IrReg temp = scratch.front();

        // Neg is unary in this IR, so the operand has to be materialised into the scratch
        // register first. Writing Neg straight onto a fresh register would negate whatever
        // happened to be there.
        const auto materialize = [](IrReg target, const IrOperand& source,
                                    std::uint64_t guest) -> IrNode
        {
            IrNode n;
            n.type         = (source.kind == IrOperand::Kind::Immediate) ? IrType::LoadImm
                                                                         : IrType::LoadGuestReg;
            n.dst.kind     = IrOperand::Kind::Reg;
            n.dst.reg      = target;
            n.src          = source;
            n.operandSize  = 8;
            n.guestAddress = guest;
            return n;
        };

        const auto negateInto = [&materialize](IrReg target, const IrOperand& source,
                                               std::uint64_t guest) -> std::vector<IrNode>
        {
            std::vector<IrNode> pair;
            pair.push_back(materialize(target, source, guest));
            pair.push_back(MakeBin(IrType::Neg, target, RegOperand(target), guest));
            return pair;
        };

        // Multiplication by a power of two is a shift, which is a different encoding of the
        // same value. Everything else here is the add/subtract through negation identity.
        if (node.type == IrType::Mul && node.src.kind == IrOperand::Kind::Immediate &&
            node.src.immediate != 0 &&
            (node.src.immediate & (node.src.immediate - 1)) == 0)
        {
            std::uint64_t amount = 0;
            std::uint64_t value  = node.src.immediate;

            while (value > 1)
            {
                value >>= 1;
                ++amount;
            }

            const IrOperand shifted = MakeBin(IrType::Shl, node.dst.reg,
                                               ImmOperand(amount), node.guestAddress).src;

            program.At(live).src  = shifted;
            program.At(live).type = IrType::Shl;
            ++result.transforms;
            continue;
        }

        if (node.type == IrType::Add)
        {
            // a + b becomes a - (-b)
            const std::vector<IrNode> pair =
                negateInto(temp, node.src, node.guestAddress);

            program.Insert(live + 1, pair[1]);
            program.Insert(live + 1, pair[0]);

            program.At(live).type = IrType::Sub;
            program.At(live).src  = RegOperand(temp);

            shift += pair.size();
            ++result.transforms;
            continue;
        }

        if (node.type == IrType::Sub)
        {
            // a - b becomes a + (-b)
            const std::vector<IrNode> pair =
                negateInto(temp, node.src, node.guestAddress);

            program.Insert(live + 1, pair[1]);
            program.Insert(live + 1, pair[0]);

            program.At(live).type = IrType::Add;
            program.At(live).src  = RegOperand(temp);

            shift += pair.size();
            ++result.transforms;
        }
    }

    result.outputNodes = program.Size();
    result.message     = "Substitution rewrote " + std::to_string(result.transforms) + " op(s)";
    return result;
}

MutationResult MbaPass::Apply(IrProgram& program, const MutationOptions& options)
{
    MutationResult result;
    result.inputNodes  = program.Size();
    result.outputNodes = program.Size();

    Rng rng(options.seed ^ 0x5EED1234u);

    // Walk a snapshot of the original nodes. The Or and And nodes this pass inserts are
    // themselves binary arithmetic, so walking the live program would rewrite them again on
    // the next iteration and grow the block without end.
    IrProgram source = program;

    // Every inserted node lands after the current one, so original index i is i + shift live.
    std::size_t shift = 0;

    for (std::size_t i = 0; i < source.Size(); ++i)
    {
        const std::size_t live = i + shift;
        IrNode node = source.At(i);

        if (!IsBinaryArith(node.type) || node.dst.kind != IrOperand::Kind::Reg)
        {
            continue;
        }

        if (!rng.Chance(options.mbaRate))
        {
            continue;
        }

        const std::vector<IrReg> scratch = PickScratchRegisters(2, CollectUsedRegisters(program));

        if (scratch.size() < 2)
        {
            break;
        }

        // The IR is accumulator style: a binary node writes dst = dst op src. Each identity
        // therefore has to materialise both operands into a temporary first, then fold the
        // two results back into the accumulator. Skipping the materialise would compute the
        // identity on uninitialised scratch.
        const IrReg lhs    = node.dst.reg;
        const IrReg first  = scratch[0];
        const IrReg second = scratch[1];

        const IrOperand rhs = node.src;

        const auto copy = [](IrReg target, const IrOperand& source,
                             std::uint64_t guest) -> IrNode
        {
            IrNode n;
            n.type         = (source.kind == IrOperand::Kind::Immediate) ? IrType::LoadImm
                                                                         : IrType::LoadGuestReg;
            n.dst.kind     = IrOperand::Kind::Reg;
            n.dst.reg      = target;
            n.src          = source;
            n.operandSize  = 8;
            n.guestAddress = guest;
            return n;
        };

        std::vector<IrNode> inserted;

        switch (node.type)
        {
        case IrType::Xor:
        {
            // a ^ b = (a | b) - (a & b)
            inserted.push_back(copy(first, RegOperand(lhs), node.guestAddress));
            inserted.push_back(MakeBin(IrType::Or, first, rhs, node.guestAddress));
            inserted.push_back(copy(second, RegOperand(lhs), node.guestAddress));
            inserted.push_back(MakeBin(IrType::And, second, rhs, node.guestAddress));

            node.dst.reg = lhs;
            node.src     = RegOperand(second);
            node.type    = IrType::Sub;
            break;
        }

        case IrType::And:
        {
            // a & b = (a | b) - (a ^ b)
            inserted.push_back(copy(first, RegOperand(lhs), node.guestAddress));
            inserted.push_back(MakeBin(IrType::Or, first, rhs, node.guestAddress));
            inserted.push_back(copy(second, RegOperand(lhs), node.guestAddress));
            inserted.push_back(MakeBin(IrType::Xor, second, rhs, node.guestAddress));

            node.dst.reg = lhs;
            node.src     = RegOperand(second);
            node.type    = IrType::Sub;
            break;
        }

        case IrType::Or:
        {
            // a | b = (a & b) + (a ^ b)
            inserted.push_back(copy(first, RegOperand(lhs), node.guestAddress));
            inserted.push_back(MakeBin(IrType::And, first, rhs, node.guestAddress));
            inserted.push_back(copy(second, RegOperand(lhs), node.guestAddress));
            inserted.push_back(MakeBin(IrType::Xor, second, rhs, node.guestAddress));

            node.dst.reg = lhs;
            node.src     = RegOperand(second);
            node.type    = IrType::Add;
            break;
        }

        default:
        {
            // a + b = a - (-b) and a - b = a + (-b)
            inserted.push_back(copy(first, rhs, node.guestAddress));
            inserted.push_back(MakeBin(IrType::Neg, first, RegOperand(first), node.guestAddress));

            node.dst.reg = lhs;
            node.src     = RegOperand(first);
            node.type    = (node.type == IrType::Add) ? IrType::Sub : IrType::Add;
            break;
        }
        }

        if (inserted.empty() || inserted.size() > options.maxMbaExpansion)
        {
            continue;
        }

        program.At(live) = node;

        for (std::size_t k = 0; k < inserted.size(); ++k)
        {
            program.Insert(live + 1 + k, inserted[k]);
        }

        shift += inserted.size();
        ++result.transforms;
    }

    result.outputNodes = program.Size();
    result.message     = "MBA rewrote " + std::to_string(result.transforms) + " op(s)";
    return result;
}

MutationResult OpaquePredicatePass::Apply(IrProgram& program, const MutationOptions& options)
{
    MutationResult result;
    result.inputNodes  = program.Size();
    result.outputNodes = program.Size();

    Rng rng(options.seed ^ 0x0A0A0A0Au);

    std::size_t inserted = 0;

    // Build the padded program first, walking a copy of the original node list so the
    // indices do not shift under the insertion loop.
    IrProgram source = program;

    for (std::size_t i = 0; i < source.Size() && inserted < options.maxOpaquePredicates; ++i)
    {
        const IrNode node = source.At(i);

        if (node.type == IrType::Ret || node.type == IrType::Jmp || node.type == IrType::Jcc)
        {
            continue;
        }

        if (!rng.Chance(options.opaquePredicateRate))
        {
            continue;
        }

        const std::vector<IrReg> scratch = PickScratchRegisters(1, CollectUsedRegisters(program));

        if (scratch.empty())
        {
            break;
        }

        const IrReg temp = scratch.front();

        // Cmp(temp, temp) is always equal, so the Jz is always taken and jumps over a Nop
        // that does nothing either way. The value of the branch is that it exists.
        const std::uint64_t guest = node.guestAddress != 0 ? node.guestAddress
                                                            : 0x1000 + i * 0x10;

        IrNode compare = MakeBin(IrType::Cmp, temp, RegOperand(temp), guest);

        IrNode jump;
        jump.type         = IrType::Jcc;
        jump.cond         = IrCond::Zero;
        jump.dst.kind     = IrOperand::Kind::Reg;
        jump.dst.reg      = temp;
        jump.guestAddress = guest;
        jump.targetAddress = guest + 8;

        IrNode skip;
        skip.type         = IrType::Nop;
        skip.guestAddress = guest + 8;

        program.Insert(i + 1, skip);
        program.Insert(i + 1, jump);
        program.Insert(i + 1, compare);

        inserted += 3;
        ++result.transforms;
    }

    result.outputNodes = program.Size();
    result.message     = "Opaque predicates inserted " + std::to_string(result.transforms) +
                          " branch(es)";
    return result;
}

MutationResult DeadCodePass::Apply(IrProgram& program, const MutationOptions& options)
{
    MutationResult result;
    result.inputNodes  = program.Size();
    result.outputNodes = program.Size();

    Rng rng(options.seed ^ 0xDEADC0DEu);

    std::size_t inserted = 0;

    IrProgram source = program;

    for (std::size_t i = 0; i < source.Size(); ++i)
    {
        const IrNode node = source.At(i);

        if (node.type == IrType::Ret)
        {
            continue;
        }

        if (!rng.Chance(options.deadCodeRate))
        {
            continue;
        }

        if (inserted >= options.maxDeadCodeNodes)
        {
            break;
        }

        const std::vector<IrReg> scratch = PickScratchRegisters(1, CollectUsedRegisters(program));

        if (scratch.empty())
        {
            break;
        }

        const IrReg temp  = scratch.front();
        const std::uint64_t guest = node.guestAddress != 0 ? node.guestAddress : 0x1000 + i * 0x10;

        // Writes to a scratch register the block never reads, ending with an xor against
        // itself so the register is left at zero rather than holding stale data.
        program.Insert(i + 1, MakeBin(IrType::Xor, temp, RegOperand(temp), guest));
        program.Insert(i + 1, MakeBin(IrType::Add, temp, RegOperand(temp), guest));
        program.Insert(i + 1, MakeBin(IrType::LoadImm, temp, ImmOperand(rng.Value(0xFFFFFF)), guest));

        inserted += 3;
        ++result.transforms;
    }

    result.outputNodes = program.Size();
    result.message     = "Dead code inserted " + std::to_string(result.transforms) + " block(s)";
    return result;
}

MutationResult ConstantObfuscationPass::Apply(IrProgram& program, const MutationOptions& options)
{
    MutationResult result;
    result.inputNodes  = program.Size();
    result.outputNodes = program.Size();

    Rng rng(options.seed ^ 0x13572468u);

    // Snapshot for the same reason as MbaPass: this pass turns one immediate into a register
    // but inserts two nodes that carry immediates, so a live walk would never terminate.
    IrProgram source = program;

    // Every node inserted here lands after the current one, so snapshot index i is i + shift
    // in the live program. Without this the second rewrite in a block overwrites the first
    // rewrite's LoadImm with a register reference, which is silent corruption rather than a
    // crash.
    std::size_t shift = 0;

    for (std::size_t i = 0; i < source.Size(); ++i)
    {
        const std::size_t live = i + shift;
        IrNode node = source.At(i);

        if (node.src.kind != IrOperand::Kind::Immediate || node.src.immediate < 2)
        {
            continue;
        }

        if (!rng.Chance(options.constantObfuscationRate))
        {
            continue;
        }

        const std::vector<IrReg> scratch = PickScratchRegisters(1, CollectUsedRegisters(program));

        if (scratch.empty())
        {
            break;
        }

        const IrReg temp = scratch.front();

        // C becomes (C - k) + k. Same value, two instructions, one temporary.
        const std::uint64_t addend = 1 + rng.Value(node.src.immediate - 1);
        const std::uint64_t start = node.src.immediate - addend;

        program.Insert(live + 1, MakeBin(IrType::Add, temp, ImmOperand(addend), node.guestAddress));
        program.Insert(live + 1, MakeBin(IrType::LoadImm, temp, ImmOperand(start), node.guestAddress));

        program.At(live).src = RegOperand(temp);

        shift += 2;
        ++result.transforms;
    }

    result.outputNodes = program.Size();
    result.message     = "Constants obfuscated " + std::to_string(result.transforms) + " time(s)";
    return result;
}
}
