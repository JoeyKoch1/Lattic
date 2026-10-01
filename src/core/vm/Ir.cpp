#include "lattic/core/vm/Ir.hpp"

#include <sstream>

namespace lattic::core::vm
{
void IrProgram::Clear()
{
    m_nodes.clear();
}

void IrProgram::Append(const IrNode& node)
{
    m_nodes.push_back(node);
}

void IrProgram::Insert(std::size_t index, const IrNode& node)
{
    // Append rather than throw: an out of range index on a block being rewritten should
    // not take the process down.
    if (index > m_nodes.size())
    {
        m_nodes.push_back(node);
        return;
    }

    m_nodes.insert(m_nodes.begin() + static_cast<std::ptrdiff_t>(index), node);
}

void IrProgram::Erase(std::size_t index)
{
    if (index < m_nodes.size())
    {
        m_nodes.erase(m_nodes.begin() + static_cast<std::ptrdiff_t>(index));
    }
}

std::size_t IrProgram::Size() const
{
    return m_nodes.size();
}

bool IrProgram::Empty() const
{
    return m_nodes.empty();
}

const IrNode& IrProgram::At(std::size_t index) const
{
    return m_nodes.at(index);
}

IrNode& IrProgram::At(std::size_t index)
{
    return m_nodes.at(index);
}

const std::vector<IrNode>& IrProgram::Nodes() const
{
    return m_nodes;
}

std::string IrProgram::Dump() const
{
    std::ostringstream oss;

    for (std::size_t i = 0; i < m_nodes.size(); ++i)
    {
        const auto& n = m_nodes[i];
        oss << '[' << i << "] " << IrTypeName(n.type) << '.' << static_cast<int>(n.operandSize);

        if (n.src.kind == IrOperand::Kind::Immediate)
        {
            oss << " imm=0x" << std::hex << n.src.immediate << std::dec;
        }
        else if (n.src.kind == IrOperand::Kind::Reg)
        {
            oss << " src=" << IrRegName(n.src.reg);
        }

        if (n.dst.kind == IrOperand::Kind::Reg)
        {
            oss << " dst=" << IrRegName(n.dst.reg);
        }

        if (n.targetAddress != 0)
        {
            oss << " -> 0x" << std::hex << n.targetAddress << std::dec;
        }

        oss << '\n';
    }

    return oss.str();
}

const char* IrTypeName(IrType type)
{
    switch (type)
    {
    case IrType::Nop:          return "Nop";
    case IrType::LoadImm:      return "LoadImm";
    case IrType::LoadGuestReg: return "LoadReg";
    case IrType::StoreGuestReg:return "StoreReg";
    case IrType::LoadMem:      return "LoadMem";
    case IrType::StoreMem:     return "StoreMem";
    case IrType::Lea:          return "Lea";
    case IrType::Add:          return "Add";
    case IrType::Sub:          return "Sub";
    case IrType::Mul:          return "Mul";
    case IrType::Div:          return "Div";
    case IrType::Mod:          return "Mod";
    case IrType::And:          return "And";
    case IrType::Or:           return "Or";
    case IrType::Xor:          return "Xor";
    case IrType::Shl:          return "Shl";
    case IrType::Shr:          return "Shr";
    case IrType::Sar:          return "Sar";
    case IrType::Not:          return "Not";
    case IrType::Neg:          return "Neg";
    case IrType::Cmp:          return "Cmp";
    case IrType::Test:         return "Test";
    case IrType::Push:         return "Push";
    case IrType::Pop:          return "Pop";
    case IrType::Jmp:          return "Jmp";
    case IrType::Jcc:          return "Jcc";
    case IrType::Call:         return "Call";
    case IrType::Ret:          return "Ret";
    case IrType::Enter:        return "Enter";
    case IrType::Exit:         return "Exit";
    default:                   return "?";
    }
}

const char* IrCondName(IrCond cond)
{
    switch (cond)
    {
    case IrCond::Zero:         return "z";
    case IrCond::NotZero:      return "nz";
    case IrCond::Equal:        return "eq";
    case IrCond::NotEqual:     return "ne";
    case IrCond::Less:         return "lt";
    case IrCond::LessEqual:    return "le";
    case IrCond::Greater:      return "gt";
    case IrCond::GreaterEqual: return "ge";
    default:                   return "?";
    }
}

const char* IrRegName(IrReg reg)
{
    switch (reg)
    {
    case IrReg::Rax: return "rax";
    case IrReg::Rbx: return "rbx";
    case IrReg::Rcx: return "rcx";
    case IrReg::Rdx: return "rdx";
    case IrReg::Rsi: return "rsi";
    case IrReg::Rdi: return "rdi";
    case IrReg::Rbp: return "rbp";
    case IrReg::Rsp: return "rsp";
    case IrReg::R8:  return "r8";
    case IrReg::R9:  return "r9";
    case IrReg::R10: return "r10";
    case IrReg::R11: return "r11";
    case IrReg::R12: return "r12";
    case IrReg::R13: return "r13";
    case IrReg::R14: return "r14";
    case IrReg::R15: return "r15";
    case IrReg::Rip: return "rip";
    case IrReg::None: return "-";
    default:          return "?";
    }
}
}