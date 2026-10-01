#include "TestFramework.hpp"

#include "lattic/core/vm/Bytecode.hpp"
#include "lattic/core/vm/Ir.hpp"
#include "lattic/core/vm/Translator.hpp"
#include "lattic/core/vm/VmArchitecture.hpp"

#include <string>

using namespace lattic::core::vm;

namespace
{
IrNode MakeRegImm(IrType type, IrReg reg, std::uint64_t imm, std::uint64_t guest)
{
    IrNode node;
    node.type         = type;
    node.dst.kind     = IrOperand::Kind::Reg;
    node.dst.reg      = reg;
    node.src.kind     = IrOperand::Kind::Immediate;
    node.src.immediate = imm;
    node.guestAddress = guest;
    return node;
}

IrNode MakeRegReg(IrType type, IrReg dst, IrReg src, std::uint64_t guest)
{
    IrNode node;
    node.type     = type;
    node.dst.kind = IrOperand::Kind::Reg;
    node.dst.reg  = dst;
    node.src.kind = IrOperand::Kind::Reg;
    node.src.reg  = src;
    node.guestAddress = guest;
    return node;
}
}

LATTIC_TEST(VmTranslator, RejectsEmptyProgram)
{
    IrProgram program;
    Translator translator;

    TranslateResult result = translator.Translate(program, TranslateOptions{});

    CHECK(!result.success);
    CHECK(!result.message.empty());
    CHECK(!translator.LastError().empty());
}

LATTIC_TEST(VmTranslator, LoadImmAndMovEmitPushPop)
{
    IrProgram program;
    program.Append(MakeRegImm(IrType::LoadImm, IrReg::Rax, 0x1234, 0x140001000));

    Translator translator;
    TranslateResult result = translator.Translate(program, TranslateOptions{});

    CHECK(result.success);

    // Index 1 is the zero return-address sentinel the translator always seeds.
    const Bytecode& out = translator.Output();
    CHECK(out.At(0).op == VmOp::Enter);
    CHECK(out.At(1).op == VmOp::PushImm);
    CHECK_EQ(out.At(1).immediate, std::uint64_t{ 0 });
    CHECK(out.At(2).op == VmOp::PushImm);
    CHECK_EQ(out.At(2).immediate, std::uint64_t{ 0x1234 });
    CHECK(out.At(3).op == VmOp::PopReg);
    CHECK(out.At(3).reg == VmReg::R0);
    CHECK(out.At(4).op == VmOp::Exit);
    CHECK_EQ(result.bytecodeSize, std::size_t{ 5 });
}

LATTIC_TEST(VmTranslator, ArithmeticEmitsBothOperands)
{
    IrProgram program;
    program.Append(MakeRegReg(IrType::Add, IrReg::Rax, IrReg::Rbx, 0x140001000));

    Translator translator;
    TranslateResult result = translator.Translate(program, TranslateOptions{});

    CHECK(result.success);
    CHECK(translator.Output().At(4).op == VmOp::Add);
}

LATTIC_TEST(VmTranslator, BranchesResolveToInstructionIndex)
{
    IrProgram program;

    IrNode jump;
    jump.type         = IrType::Jmp;
    jump.guestAddress = 0x140001000;
    jump.targetAddress = 0x140001010;
    program.Append(jump);

    IrNode load;
    load.type     = IrType::LoadImm;
    load.dst.kind = IrOperand::Kind::Reg;
    load.dst.reg  = IrReg::Rcx;
    load.src.kind = IrOperand::Kind::Immediate;
    load.src.immediate = 0x99;
    load.guestAddress = 0x140001010;
    program.Append(load);

    Translator translator;
    TranslateResult result = translator.Translate(program, TranslateOptions{});

    CHECK(result.success);
    CHECK_EQ(result.branchCount, std::size_t{ 1 });

    // The branch operand must point at the VM index of the target guest address, not a byte offset.
    CHECK(translator.Output().At(2).op == VmOp::Jmp);
    CHECK_EQ(translator.Output().At(2).immediate, std::uint64_t{ 3 });
}

LATTIC_TEST(VmTranslator, UnknownBranchTargetIsLeftUnpatched)
{
    IrProgram program;

    IrNode jump;
    jump.type          = IrType::Jmp;
    jump.guestAddress  = 0x140001000;
    jump.targetAddress = 0x140009999;
    program.Append(jump);

    Translator translator;
    CHECK(translator.Translate(program, TranslateOptions{}).success);
    CHECK_EQ(translator.Output().At(2).immediate, std::uint64_t{ 0 });
}

LATTIC_TEST(VmTranslator, ConditionalBranchesMapToMatchingOps)
{
    IrProgram program;

    const IrCond conds[] = { IrCond::Zero, IrCond::NotZero, IrCond::Less, IrCond::LessEqual,
                              IrCond::Greater, IrCond::GreaterEqual };

    for (std::size_t i = 0; i < sizeof(conds) / sizeof(conds[0]); ++i)
    {
        IrNode node;
        node.type          = IrType::Jcc;
        node.cond          = conds[i];
        node.guestAddress  = 0x140001000;
        node.targetAddress = 0x140001000;
        program.Append(node);
    }

    Translator translator;
    CHECK(translator.Translate(program, TranslateOptions{}).success);

    const Bytecode& out = translator.Output();

    CHECK(out.At(2).op == VmOp::Jz);
    CHECK(out.At(3).op == VmOp::Jnz);
    CHECK(out.At(4).op == VmOp::Jl);
    CHECK(out.At(5).op == VmOp::Jle);
    CHECK(out.At(6).op == VmOp::Jg);
    CHECK(out.At(7).op == VmOp::Jge);
}

LATTIC_TEST(VmTranslator, NopInsertionHonoursDensity)
{
    IrProgram program;

    for (int i = 0; i < 8; ++i)
    {
        program.Append(MakeRegImm(IrType::LoadImm, IrReg::Rax, static_cast<std::uint64_t>(i),
                                  0x140001000 + static_cast<std::uint64_t>(i)));
    }

    TranslateOptions options;
    options.insertNops = true;
    options.nopDensity  = 2;

    Translator translator;
    CHECK(translator.Translate(program, options).success);
    CHECK(translator.Output().Size() > 0);

    const auto withoutNops = [] {
        IrProgram plain;
        for (int i = 0; i < 8; ++i)
        {
            plain.Append(MakeRegImm(IrType::LoadImm, IrReg::Rax, static_cast<std::uint64_t>(i),
                                    0x140001000 + static_cast<std::uint64_t>(i)));
        }
        Translator t;
        t.Translate(plain, TranslateOptions{});
        return t.Output().Size();
    }();

    CHECK(translator.Output().Size() > withoutNops);
}

LATTIC_TEST(VmTranslator, MapGuestRegCoversGpRegisters)
{
    CHECK(Translator::MapGuestReg(IrReg::Rax) == VmReg::R0);
    CHECK(Translator::MapGuestReg(IrReg::R15) == VmReg::R15);
    CHECK(Translator::MapGuestReg(IrReg::None) == VmReg::R0);
}

LATTIC_TEST(VmTranslator, BytecodeSerializeRoundTrip)
{
    Bytecode code;

    code.Emit(VmOp::Enter);
    code.EmitImm(VmOp::PushImm, 0xDEADBEEFCAFEBABEull);
    code.EmitReg(VmOp::PopReg, VmReg::R5);
    code.Emit(VmOp::Exit);
    code.SetGuestAddress(1, 0x140001000);

    const auto serialized = code.Serialize();
    CHECK(!serialized.empty());

    Bytecode restored;
    CHECK(restored.Deserialize(serialized));
    CHECK_EQ(restored.Size(), code.Size());
    CHECK(restored.At(1).immediate == 0xDEADBEEFCAFEBABEull);
    CHECK(restored.At(2).reg == VmReg::R5);
}

LATTIC_TEST(VmTranslator, DeserializeRejectsGarbage)
{
    Bytecode code;

    CHECK(!code.Deserialize({}));
    CHECK(!code.Deserialize({ 0x01, 0x02, 0x03 }));

    const std::vector<std::uint8_t> badMagic(16, 0xFF);
    CHECK(!code.Deserialize(badMagic));

    // Valid header claiming one instruction with no body behind it.
    std::vector<std::uint8_t> truncated = code.Serialize();
    truncated[8] = 1;
    CHECK(!code.Deserialize(truncated));
    CHECK(code.Empty());
}

LATTIC_TEST(VmTranslator, EncodedSizeMatchesSerialization)
{
    Bytecode code;

    code.Emit(VmOp::Nop);
    code.EmitReg(VmOp::PopReg, VmReg::R1);
    code.EmitImm(VmOp::PushImm, 0x1000);

    CHECK_EQ(EncodedSize(VmOp::Nop), std::size_t{ 1 });
    CHECK_EQ(EncodedSize(VmOp::PopReg), std::size_t{ 2 });
    CHECK_EQ(EncodedSize(VmOp::PushImm), std::size_t{ 9 });

    // 12 byte header plus the three encodings above.
    CHECK_EQ(code.Serialize().size(), std::size_t{ 12 + 1 + 2 + 9 });
}
