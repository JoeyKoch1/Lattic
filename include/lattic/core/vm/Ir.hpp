#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lattic::core::vm
{
enum class IrType
{
    Nop,
    LoadImm,
    LoadGuestReg,
    StoreGuestReg,
    LoadMem,
    StoreMem,
    Lea,
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor,
    Shl, Shr, Sar,
    Not, Neg,
    Cmp, Test,
    Push, Pop,
    Jmp, Jcc, Call, Ret,
    Enter, Exit
};

enum class IrCond
{
    Zero, NotZero,
    Equal, NotEqual,
    Less, LessEqual,
    Greater, GreaterEqual
};

enum class IrReg : std::uint8_t
{
    Rax, Rbx, Rcx, Rdx,
    Rsi, Rdi, Rbp, Rsp,
    R8, R9, R10, R11,
    R12, R13, R14, R15,
    Rip, None, Count
};

struct IrOperand
{
    enum class Kind { None, Immediate, Reg, Mem, RipRel } kind = Kind::None;

    std::uint64_t immediate = 0;
    IrReg         reg       = IrReg::Rax;

    IrReg         memBase   = IrReg::None;
    IrReg         memIndex  = IrReg::None;
    int           memScale  = 1;
    std::int64_t  memDisp   = 0;

    std::uint64_t ripTarget = 0;
};

struct IrNode
{
    IrType    type = IrType::Nop;
    IrOperand dst;
    IrOperand src;
    IrCond    cond = IrCond::Equal;

    std::uint64_t guestAddress  = 0;
    std::uint64_t targetAddress = 0;

    std::uint8_t operandSize = 8;
};

class IrProgram
{
public:
    void Clear();
    void Append(const IrNode& node);

    // Insertion points, needed by the passes that expand or pad a block.
    void Insert(std::size_t index, const IrNode& node);
    void Erase(std::size_t index);

    std::size_t Size() const;
    bool        Empty() const;

    const IrNode& At(std::size_t index) const;
    IrNode&       At(std::size_t index);

    const std::vector<IrNode>& Nodes() const;

    std::string Dump() const;

private:
    std::vector<IrNode> m_nodes;
};

const char* IrTypeName(IrType type);
const char* IrCondName(IrCond cond);
const char* IrRegName(IrReg reg);
}