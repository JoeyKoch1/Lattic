#include "PeFixture.hpp"
#include "TestFramework.hpp"

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/vm/CodeVirtualizer.hpp"
#include "lattic/core/vm/Ir.hpp"
#include "lattic/core/vm/Lifter.hpp"

#include <cstdio>
#include <cstring>
#include <string>

using namespace lattic::core::vm;
using lattic::core::Binary;
using lattic::core::PeParser;

namespace
{
// x64 encodings used by the lift cases below.
constexpr std::uint8_t kNop       = 0x90;
constexpr std::uint8_t kRet       = 0xC3;
constexpr std::uint8_t kMovRaxImm[] = { 0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00 };
}

LATTIC_TEST(VmLifter, IrProgramBasics)
{
    IrProgram program;

    CHECK(program.Empty());
    CHECK_EQ(program.Size(), std::size_t{ 0 });

    IrNode node;
    node.type = IrType::Add;
    program.Append(node);

    CHECK(!program.Empty());
    CHECK_EQ(program.Size(), std::size_t{ 1 });
    CHECK(program.At(0).type == IrType::Add);
    CHECK(!program.Dump().empty());

    program.Clear();
    CHECK(program.Empty());
}

LATTIC_TEST(VmIr, NamesAreStable)
{
    CHECK(std::string(IrTypeName(IrType::LoadImm)) == "LoadImm");
    CHECK(std::string(IrTypeName(IrType::StoreGuestReg)) == "StoreReg");
    CHECK(std::string(IrTypeName(static_cast<IrType>(250))) == "?");

    CHECK(std::string(IrCondName(IrCond::NotZero)) == "nz");
    CHECK(std::string(IrRegName(IrReg::R15)) == "r15");
    CHECK(std::string(IrRegName(IrReg::None)) == "-");
}

LATTIC_TEST(VmLifter, RejectsUnparsedImage)
{
    Binary binary;
    PeParser parser;
    Lifter lifter(binary, parser);

    const LiftResult result = lifter.Lift(0x140001000, 0x140001010, LiftOptions{});

    CHECK(!result.success);
    CHECK(!lifter.LastError().empty());
}

LATTIC_TEST(VmLifter, RejectsInvertedRange)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_vmlifter_range.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Lifter lifter(binary, parser);
    const LiftResult result = lifter.Lift(0x140001010, 0x140001000, LiftOptions{});

    CHECK(!result.success);

    std::remove(path.c_str());
}

LATTIC_TEST(VmLifter, LiftsMovImmediateAndRet)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::uint8_t* text = image.bytes.data() + image.textRawOff;
    text[0] = kNop;
    std::memcpy(text + 1, kMovRaxImm, sizeof(kMovRaxImm));
    text[1 + sizeof(kMovRaxImm)] = kRet;

    const std::size_t codeLen = 1 + sizeof(kMovRaxImm) + 1;
    const std::string path = lattic::test::WriteTempFile(image, "test_vmlifter_mov.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Lifter lifter(binary, parser);
    const LiftResult result = lifter.Lift(image.TextVa(), image.TextVa() + codeLen, LiftOptions{});

    CHECK(result.success);
    CHECK_EQ(result.instructionCount, std::size_t{ 3 });
    CHECK_EQ(result.bytesConsumed, codeLen);

    // The IR always opens with Enter and closes with Exit around the lifted body.
    CHECK_EQ(result.irNodeCount, std::size_t{ 5 });
    CHECK(lifter.Program().At(0).type == IrType::Enter);
    CHECK(lifter.Program().At(1).type == IrType::Nop);
    CHECK(lifter.Program().At(2).type == IrType::LoadImm);
    CHECK(lifter.Program().At(3).type == IrType::Ret);
    CHECK(lifter.Program().At(4).type == IrType::Exit);

    CHECK_EQ(lifter.InstructionCount(), std::size_t{ 3 });
    CHECK_EQ(lifter.StartVa(), image.TextVa());

    std::remove(path.c_str());
}

LATTIC_TEST(VmLifter, MaxInstructionsCapsTheBlock)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::uint8_t* text = image.bytes.data() + image.textRawOff;
    for (int i = 0; i < 16; ++i)
    {
        text[i] = kNop;
    }

    const std::string path = lattic::test::WriteTempFile(image, "test_vmlifter_cap.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Lifter lifter(binary, parser);

    LiftOptions options;
    options.maxInstructions = 4;

    const LiftResult result = lifter.Lift(image.TextVa(), image.TextVa() + 16, options);

    CHECK(result.success);
    CHECK_EQ(result.instructionCount, std::size_t{ 4 });

    std::remove(path.c_str());
}

LATTIC_TEST(VmLifter, UndecodableBytesStopTheBlock)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::uint8_t* text = image.bytes.data() + image.textRawOff;

    // 0x06 is PUSH ES, legal in 16/32-bit but not encodable in long mode.
    text[0] = 0x06;
    text[1] = kNop;

    const std::string path = lattic::test::WriteTempFile(image, "test_vmlifter_bad.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Lifter lifter(binary, parser);
    const LiftResult result = lifter.Lift(image.TextVa(), image.TextVa() + 2, LiftOptions{});

    CHECK(!result.success);
    CHECK_EQ(result.instructionCount, std::size_t{ 0 });

    std::remove(path.c_str());
}

LATTIC_TEST(VmVirtualizer, EndToEndProducesSerializableBytecode)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::uint8_t* text = image.bytes.data() + image.textRawOff;
    std::memcpy(text, kMovRaxImm, sizeof(kMovRaxImm));
    text[sizeof(kMovRaxImm)] = kRet;

    const std::size_t  codeLen = sizeof(kMovRaxImm) + 1;
    const std::string path = lattic::test::WriteTempFile(image, "test_vmvirt_e2e.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    CodeVirtualizer virt(binary, parser);

    VirtualizeOptions options;
    const VirtualizeReport report =
        virt.Virtualize(image.TextVa(), image.TextVa() + codeLen, options);

    CHECK(report.success);
    CHECK(!report.message.empty());
    CHECK_EQ(report.instructionsLifted, std::size_t{ 2 });
    CHECK(!report.serializedBytecode.empty());

    std::uint64_t result = 0;
    CHECK(virt.ExecuteInProcess(result));

    std::remove(path.c_str());
}

LATTIC_TEST(VmVirtualizer, FailsCleanlyWithNoBytecode)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_vmvirt_empty.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    CodeVirtualizer virt(binary, parser);

    std::uint64_t result = 0;
    CHECK(!virt.ExecuteInProcess(result));
    CHECK(!virt.LastError().empty());

    std::remove(path.c_str());
}
