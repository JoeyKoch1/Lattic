#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/vm/VmArchitecture.hpp"

namespace lattic::core::vm
{
struct Instruction
{
    VmOp     op          = VmOp::Nop;
    VmReg    reg         = VmReg::R0;
    std::uint64_t immediate = 0;
    std::uint64_t guestAddress = 0;
};

class Bytecode
{
public:
    void Clear();

    void Emit(VmOp op);
    void EmitReg(VmOp op, VmReg reg);
    void EmitImm(VmOp op, std::uint64_t imm);

    void SetGuestAddress(std::size_t index, std::uint64_t guest);

    std::size_t Size() const;
    bool        Empty() const;

    const Instruction& At(std::size_t index) const;
    Instruction&       At(std::size_t index);

    const std::vector<Instruction>& Instructions() const;

    std::vector<std::uint8_t> Serialize() const;
    bool Deserialize(const std::vector<std::uint8_t>& data);

    std::string Disassemble() const;

private:
    std::vector<Instruction> m_instructions;
};

std::size_t EncodedSize(VmOp op);
}