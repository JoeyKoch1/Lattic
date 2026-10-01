#include "lattic/core/vm/VmArchitecture.hpp"

namespace lattic::core::vm
{
const char* OpName(VmOp op)
{
    switch (op)
    {
    case VmOp::Nop:      return "Nop";
    case VmOp::PushImm:  return "PushImm";
    case VmOp::PushReg:  return "PushReg";
    case VmOp::PopReg:   return "PopReg";
    case VmOp::Dup:      return "Dup";
    case VmOp::Swap:     return "Swap";
    case VmOp::Drop:     return "Drop";
    case VmOp::Add:      return "Add";
    case VmOp::Sub:      return "Sub";
    case VmOp::Mul:      return "Mul";
    case VmOp::Div:      return "Div";
    case VmOp::Mod:      return "Mod";
    case VmOp::And:      return "And";
    case VmOp::Or:       return "Or";
    case VmOp::Xor:      return "Xor";
    case VmOp::Shl:      return "Shl";
    case VmOp::Shr:      return "Shr";
    case VmOp::Sar:      return "Sar";
    case VmOp::Not:      return "Not";
    case VmOp::Neg:      return "Neg";
    case VmOp::Cmp:      return "Cmp";
    case VmOp::Test:     return "Test";
    case VmOp::Load8:    return "Load8";
    case VmOp::Load16:   return "Load16";
    case VmOp::Load32:   return "Load32";
    case VmOp::Load64:   return "Load64";
    case VmOp::Store8:   return "Store8";
    case VmOp::Store16:  return "Store16";
    case VmOp::Store32:  return "Store32";
    case VmOp::Store64:  return "Store64";
    case VmOp::Jmp:      return "Jmp";
    case VmOp::Jz:       return "Jz";
    case VmOp::Jnz:      return "Jnz";
    case VmOp::Jl:       return "Jl";
    case VmOp::Jle:      return "Jle";
    case VmOp::Jg:       return "Jg";
    case VmOp::Jge:      return "Jge";
    case VmOp::Call:     return "Call";
    case VmOp::Ret:      return "Ret";
    case VmOp::Enter:    return "Enter";
    case VmOp::Exit:     return "Exit";
    default:             return "?";
    }
}

const char* RegName(VmReg reg)
{
    static const char* kNames[] = {
        "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "SP", "IP", "FL"
    };

    const auto idx = static_cast<std::size_t>(reg);

    if (idx >= kRegisterCount)
    {
        return "??";
    }

    return kNames[idx];
}

bool IsBranch(VmOp op)
{
    switch (op)
    {
    case VmOp::Jmp: case VmOp::Jz: case VmOp::Jnz:
    case VmOp::Jl: case VmOp::Jle: case VmOp::Jg: case VmOp::Jge:
    case VmOp::Call: case VmOp::Ret:
        return true;
    default:
        return false;
    }
}

bool IsBinaryArith(VmOp op)
{
    switch (op)
    {
    case VmOp::Add: case VmOp::Sub: case VmOp::Mul:
    case VmOp::Div: case VmOp::Mod:
    case VmOp::And: case VmOp::Or: case VmOp::Xor:
    case VmOp::Shl: case VmOp::Shr: case VmOp::Sar:
    case VmOp::Cmp: case VmOp::Test:
        return true;
    default:
        return false;
    }
}

bool IsUnaryArith(VmOp op)
{
    return op == VmOp::Not || op == VmOp::Neg || op == VmOp::Drop;
}

bool IsMemoryOp(VmOp op)
{
    switch (op)
    {
    case VmOp::Load8: case VmOp::Load16: case VmOp::Load32: case VmOp::Load64:
    case VmOp::Store8: case VmOp::Store16: case VmOp::Store32: case VmOp::Store64:
        return true;
    default:
        return false;
    }
}

bool HasImmediate(VmOp op)
{
    switch (op)
    {
    case VmOp::PushImm: case VmOp::Jmp:
    case VmOp::Jz: case VmOp::Jnz:
    case VmOp::Jl: case VmOp::Jle: case VmOp::Jg: case VmOp::Jge:
    case VmOp::Call:
        return true;
    default:
        return false;
    }
}

bool HasRegister(VmOp op)
{
    return op == VmOp::PushReg || op == VmOp::PopReg;
}

bool IsTerminal(VmOp op)
{
    return op == VmOp::Exit || op == VmOp::Ret;
}
}