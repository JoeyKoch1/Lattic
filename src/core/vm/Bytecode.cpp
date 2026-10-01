#include "lattic/core/vm/Bytecode.hpp"

#include <cstring>
#include <sstream>

namespace lattic::core::vm
{
namespace
{
constexpr std::uint32_t kMagic   = 0x4C415456;
constexpr std::uint32_t kVersion = 2;
constexpr std::size_t   kHeaderSize = 12;

void WriteU32(std::vector<std::uint8_t>& out, std::uint32_t v)
{
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

void WriteU64(std::vector<std::uint8_t>& out, std::uint64_t v)
{
    for (int i = 0; i < 8; ++i)
    {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

std::uint32_t ReadU32(const std::vector<std::uint8_t>& data, std::size_t& cursor, bool& ok)
{
    if (cursor + 4 > data.size())
    {
        ok = false;
        return 0;
    }

    std::uint32_t value = 0;

    for (int i = 0; i < 4; ++i)
    {
        value |= static_cast<std::uint32_t>(data[cursor++]) << (i * 8);
    }

    return value;
}

std::uint64_t ReadU64(const std::vector<std::uint8_t>& data, std::size_t& cursor, bool& ok)
{
    if (cursor + 8 > data.size())
    {
        ok = false;
        return 0;
    }

    std::uint64_t value = 0;

    for (int i = 0; i < 8; ++i)
    {
        value |= static_cast<std::uint64_t>(data[cursor++]) << (i * 8);
    }

    return value;
}
}

std::size_t EncodedSize(VmOp op)
{
    std::size_t size = 1;

    if (HasRegister(op))
    {
        size += 1;
    }

    if (HasImmediate(op))
    {
        size += 8;
    }

    return size;
}

void Bytecode::Clear()
{
    m_instructions.clear();
}

void Bytecode::Emit(VmOp op)
{
    Instruction inst;
    inst.op = op;
    m_instructions.push_back(inst);
}

void Bytecode::EmitReg(VmOp op, VmReg reg)
{
    Instruction inst;
    inst.op  = op;
    inst.reg = reg;
    m_instructions.push_back(inst);
}

void Bytecode::EmitImm(VmOp op, std::uint64_t imm)
{
    Instruction inst;
    inst.op        = op;
    inst.immediate = imm;
    m_instructions.push_back(inst);
}

void Bytecode::SetGuestAddress(std::size_t index, std::uint64_t guest)
{
    if (index < m_instructions.size())
    {
        m_instructions[index].guestAddress = guest;
    }
}

std::size_t Bytecode::Size() const
{
    return m_instructions.size();
}

bool Bytecode::Empty() const
{
    return m_instructions.empty();
}

const Instruction& Bytecode::At(std::size_t index) const
{
    return m_instructions.at(index);
}

Instruction& Bytecode::At(std::size_t index)
{
    return m_instructions.at(index);
}

const std::vector<Instruction>& Bytecode::Instructions() const
{
    return m_instructions;
}

std::vector<std::uint8_t> Bytecode::Serialize() const
{
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + m_instructions.size() * 10);

    WriteU32(out, kMagic);
    WriteU32(out, kVersion);
    WriteU32(out, static_cast<std::uint32_t>(m_instructions.size()));

    for (const auto& inst : m_instructions)
    {
        out.push_back(static_cast<std::uint8_t>(inst.op));

        if (HasRegister(inst.op))
        {
            out.push_back(static_cast<std::uint8_t>(inst.reg));
        }

        if (HasImmediate(inst.op))
        {
            WriteU64(out, inst.immediate);
        }
    }

    return out;
}

bool Bytecode::Deserialize(const std::vector<std::uint8_t>& data)
{
    Clear();

    if (data.size() < kHeaderSize)
    {
        return false;
    }

    std::size_t cursor = 0;
    bool        ok     = true;

    if (ReadU32(data, cursor, ok) != kMagic || !ok)
    {
        return false;
    }

    if (ReadU32(data, cursor, ok) != kVersion || !ok)
    {
        return false;
    }

    const std::uint32_t count = ReadU32(data, cursor, ok);

    if (!ok)
    {
        return false;
    }

    for (std::uint32_t i = 0; i < count; ++i)
    {
        if (cursor >= data.size())
        {
            Clear();
            return false;
        }

        Instruction inst;
        inst.op = static_cast<VmOp>(data[cursor++]);

        if (HasRegister(inst.op))
        {
            if (cursor >= data.size())
            {
                Clear();
                return false;
            }
            inst.reg = static_cast<VmReg>(data[cursor++]);
        }

        if (HasImmediate(inst.op))
        {
            inst.immediate = ReadU64(data, cursor, ok);

            if (!ok)
            {
                Clear();
                return false;
            }
        }

        m_instructions.push_back(inst);
    }

    return true;
}

std::string Bytecode::Disassemble() const
{
    std::ostringstream oss;

    for (std::size_t i = 0; i < m_instructions.size(); ++i)
    {
        const auto& inst = m_instructions[i];

        oss << '[' << i << "] " << OpName(inst.op);

        if (HasRegister(inst.op))
        {
            oss << ' ' << RegName(inst.reg);
        }

        if (HasImmediate(inst.op))
        {
            oss << " 0x" << std::hex << inst.immediate << std::dec;
        }

        if (inst.guestAddress != 0)
        {
            oss << "  ; guest=0x" << std::hex << inst.guestAddress << std::dec;
        }

        oss << '\n';
    }

    return oss.str();
}
}