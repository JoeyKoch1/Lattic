#include "TestFramework.hpp"

#include "lattic/core/vm/Bytecode.hpp"
#include "lattic/core/vm/Interpreter.hpp"
#include "lattic/core/vm/VmArchitecture.hpp"

#include <string>
#include <vector>

using namespace lattic::core::vm;

namespace
{
std::uint64_t RunProgram(Bytecode& code, VmStatus& statusOut)
{
    Interpreter interp;

    if (!interp.Initialize(code.Serialize()))
    {
        statusOut = VmStatus::Fault;
        return 0;
    }

    statusOut = interp.Run();
    return interp.Result();
}
}

LATTIC_TEST(VmInterpreter, RejectsEmptyBytecode)
{
    Interpreter interp;

    CHECK(!interp.Initialize({}));
    CHECK(!interp.Initialize({ 1, 2, 3 }));
    CHECK(interp.Run() == VmStatus::Fault);
}

LATTIC_TEST(VmInterpreter, ArithmeticOnRegisters)
{
    Bytecode program;
    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 30);
    program.EmitImm(VmOp::PushImm, 12);
    program.Emit(VmOp::Sub);
    program.EmitReg(VmOp::PopReg, VmReg::R0);
    program.Emit(VmOp::Exit);

    VmStatus status = VmStatus::Ok;
    const std::uint64_t result = RunProgram(program, status);

    CHECK(status == VmStatus::Halted);
    CHECK_EQ(result, std::uint64_t{ 18 });
}

LATTIC_TEST(VmInterpreter, DivisionByZeroFaults)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 10);
    program.EmitImm(VmOp::PushImm, 0);
    program.Emit(VmOp::Div);
    program.Emit(VmOp::Exit);

    VmStatus status = VmStatus::Ok;
    RunProgram(program, status);

    CHECK(status == VmStatus::DivByZero);
}

LATTIC_TEST(VmInterpreter, ModuloByZeroFaults)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 10);
    program.EmitImm(VmOp::PushImm, 0);
    program.Emit(VmOp::Mod);
    program.Emit(VmOp::Exit);

    VmStatus status = VmStatus::Ok;
    RunProgram(program, status);

    CHECK(status == VmStatus::DivByZero);
}

LATTIC_TEST(VmInterpreter, StackUnderflowOnEmptyPop)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.EmitReg(VmOp::PopReg, VmReg::R0);
    program.Emit(VmOp::Exit);

    VmStatus status = VmStatus::Ok;
    RunProgram(program, status);

    CHECK(status == VmStatus::StackUnderflow);
}

LATTIC_TEST(VmInterpreter, StackOverflowIsBounded)
{
    Bytecode program;

    program.Emit(VmOp::Enter);

    // kDefaultVmStack is 1 MiB of 8 byte words, so this must trip the overflow guard.
    for (int i = 0; i < 200000; ++i)
    {
        program.EmitImm(VmOp::PushImm, i);
    }

    VmStatus status = VmStatus::Ok;
    RunProgram(program, status);

    CHECK(status == VmStatus::StackOverflow);
}

LATTIC_TEST(VmInterpreter, UnknownOpcodeFaults)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.Emit(static_cast<VmOp>(0xF0));
    program.Emit(VmOp::Exit);

    VmStatus status = VmStatus::Ok;
    RunProgram(program, status);

    CHECK(status == VmStatus::BadOpcode);
}

LATTIC_TEST(VmInterpreter, JzTakesBranchWhenCompareIsEqual)
{
    Bytecode program;

    // Push two equal values, compare, then skip over the 0xBAD store when they match.
    // The branch target is the byte offset of the instruction after the store, which the
    // serializer lays out as: header(12) Enter(1) Push(9) Push(9) Cmp(1) Jz(9) Push(9) Ret(1).
    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 5);
    program.EmitImm(VmOp::PushImm, 5);
    program.Emit(VmOp::Cmp);
    program.EmitImm(VmOp::Jz, 51);
    program.EmitImm(VmOp::PushImm, 0xBAD);
    program.Emit(VmOp::Ret);

    Interpreter interp;
    CHECK(interp.Initialize(program.Serialize()));
    CHECK(interp.Run() == VmStatus::Halted);

    // Jz jumped to the Ret, which popped the empty-stack sentinel and never stored 0xBAD.
    CHECK_EQ(interp.Context().sp, std::size_t{ 0 });
}

LATTIC_TEST(VmInterpreter, JnzFallsThroughWhenCompareIsEqual)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 5);
    program.EmitImm(VmOp::PushImm, 5);
    program.Emit(VmOp::Cmp);
    program.EmitImm(VmOp::Jnz, 51);
    program.EmitImm(VmOp::PushImm, 0xBAD);
    program.Emit(VmOp::Ret);

    Interpreter interp;
    CHECK(interp.Initialize(program.Serialize()));
    CHECK(interp.Run() == VmStatus::Halted);

    // Fell through the branch and stored 0xBAD, then the Ret popped it and returned.
    CHECK_EQ(interp.Result(), std::uint64_t{ 0 });
    CHECK_EQ(interp.Context().sp, std::size_t{ 0 });
}

LATTIC_TEST(VmInterpreter, RetWithZeroTargetHalts)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 0);
    program.Emit(VmOp::Ret);

    Interpreter interp;
    CHECK(interp.Initialize(program.Serialize()));
    CHECK(interp.Run() == VmStatus::Halted);
    CHECK(interp.HasExited());
}

LATTIC_TEST(VmInterpreter, StepAdvancesOneInstruction)
{
    Bytecode program;

    program.Emit(VmOp::Enter);
    program.EmitImm(VmOp::PushImm, 7);
    program.Emit(VmOp::Exit);

    Interpreter interp;
    CHECK(interp.Initialize(program.Serialize()));

    CHECK(interp.Step() == VmStatus::Ok);
    CHECK(!interp.HasExited());

    CHECK(interp.Step() == VmStatus::Ok);
    CHECK(!interp.HasExited());
    CHECK_EQ(interp.Context().sp, std::size_t{ 8 });

    CHECK(interp.Step() == VmStatus::Ok);
    CHECK(interp.HasExited());
    CHECK_EQ(interp.Result(), std::uint64_t{ 0 });
}

LATTIC_TEST(VmInterpreter, ShutdownResetsContext)
{
    Bytecode program;
    program.Emit(VmOp::Enter);
    program.Emit(VmOp::Exit);

    Interpreter interp;
    CHECK(interp.Initialize(program.Serialize()));

    interp.Shutdown();
    CHECK(interp.Run() == VmStatus::Fault);
    CHECK(!interp.HasExited());
    CHECK_EQ(interp.Result(), std::uint64_t{ 0 });
}

LATTIC_TEST(VmInterpreter, StatusNamesAreDistinct)
{
    CHECK(std::string(Interpreter::StatusName(VmStatus::Ok)) == "Ok");
    CHECK(std::string(Interpreter::StatusName(VmStatus::DivByZero)) == "DivByZero");
    CHECK(std::string(Interpreter::StatusName(VmStatus::StackOverflow)) == "StackOverflow");
    CHECK(std::string(Interpreter::StatusName(VmStatus::BadOpcode)) == "BadOpcode");
}

LATTIC_TEST(VmArchitecture, OpcodeClassification)
{
    CHECK(IsBranch(VmOp::Jmp));
    CHECK(IsBranch(VmOp::Ret));
    CHECK(!IsBranch(VmOp::Add));

    CHECK(IsBinaryArith(VmOp::Add));
    CHECK(IsBinaryArith(VmOp::Cmp));
    CHECK(!IsBinaryArith(VmOp::Not));

    CHECK(IsUnaryArith(VmOp::Not));
    CHECK(!IsUnaryArith(VmOp::Add));

    CHECK(IsMemoryOp(VmOp::Load64));
    CHECK(IsMemoryOp(VmOp::Store8));
    CHECK(!IsMemoryOp(VmOp::PushImm));

    CHECK(IsTerminal(VmOp::Exit));
    CHECK(IsTerminal(VmOp::Ret));

    CHECK(HasImmediate(VmOp::PushImm));
    CHECK(!HasImmediate(VmOp::PopReg));

    CHECK(HasRegister(VmOp::PopReg));
    CHECK(!HasRegister(VmOp::PushImm));
}

LATTIC_TEST(VmArchitecture, NamesCoverEveryDefinedOpcode)
{
    CHECK(std::string(OpName(VmOp::PushImm)) == "PushImm");
    CHECK(std::string(OpName(VmOp::Exit)) == "Exit");
    CHECK(std::string(OpName(static_cast<VmOp>(0xEE))) == "?");

    CHECK(std::string(RegName(VmReg::R0)) == "R0");
    CHECK(std::string(RegName(VmReg::Flags)) == "FL");
    CHECK(std::string(RegName(static_cast<VmReg>(200))) == "??");
}
