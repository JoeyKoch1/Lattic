#pragma once

#include <cstddef>
#include <cstdint>

namespace lattic::core::vm
{
enum class VmOp : std::uint8_t
{
    Nop = 0x00,

    PushImm, PushReg, PopReg,
    Dup, Swap, Drop,

    Add, Sub, Mul, Div, Mod,
    And, Or, Xor,
    Shl, Shr, Sar,
    Not, Neg,

    Cmp, Test,

    Load8, Load16, Load32, Load64,
    Store8, Store16, Store32, Store64,

    Jmp, Jz, Jnz, Jl, Jle, Jg, Jge,
    Call, Ret,

    Enter, Exit,

    Count
};

enum class VmReg : std::uint8_t
{
    R0 = 0, R1, R2, R3,
    R4, R5, R6, R7,
    R8, R9, R10, R11,
    R12, R13, R14, R15,
    Sp, Ip, Flags,
    Count
};

constexpr std::size_t kRegisterCount  = static_cast<std::size_t>(VmReg::Count);
constexpr std::size_t kStackWordSize  = 8;
constexpr std::size_t kDefaultVmStack = 1024 * 1024;

const char* OpName(VmOp op);
const char* RegName(VmReg reg);

bool IsBranch(VmOp op);
bool IsBinaryArith(VmOp op);
bool IsUnaryArith(VmOp op);
bool IsMemoryOp(VmOp op);
bool HasImmediate(VmOp op);
bool HasRegister(VmOp op);
bool IsTerminal(VmOp op);
}