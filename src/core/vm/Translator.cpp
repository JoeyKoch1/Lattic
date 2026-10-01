#include "lattic/core/vm/Translator.hpp"

#include <algorithm>

namespace lattic::core::vm
{
VmReg Translator::MapGuestReg(IrReg reg)
{
    switch (reg)
    {
    case IrReg::Rax: return VmReg::R0;
    case IrReg::Rbx: return VmReg::R1;
    case IrReg::Rcx: return VmReg::R2;
    case IrReg::Rdx: return VmReg::R3;
    case IrReg::Rsi: return VmReg::R4;
    case IrReg::Rdi: return VmReg::R5;
    case IrReg::Rbp: return VmReg::R6;
    case IrReg::Rsp: return VmReg::R7;
    case IrReg::R8:  return VmReg::R8;
    case IrReg::R9:  return VmReg::R9;
    case IrReg::R10: return VmReg::R10;
    case IrReg::R11: return VmReg::R11;
    case IrReg::R12: return VmReg::R12;
    case IrReg::R13: return VmReg::R13;
    case IrReg::R14: return VmReg::R14;
    case IrReg::R15: return VmReg::R15;
    default:         return VmReg::R0;
    }
}

void Translator::EmitAddressOf(const IrOperand& op)
{
    if (op.kind == IrOperand::Kind::Mem)
    {
        bool pushed = false;

        if (op.memBase != IrReg::None)
        {
            m_output.EmitReg(VmOp::PushReg, MapGuestReg(op.memBase));
            pushed = true;
        }

        if (op.memIndex != IrReg::None)
        {
            m_output.EmitReg(VmOp::PushReg, MapGuestReg(op.memIndex));

            if (op.memScale > 1)
            {
                m_output.EmitImm(VmOp::PushImm, static_cast<std::uint64_t>(op.memScale));
                m_output.Emit(VmOp::Mul);
            }

            if (pushed)
            {
                m_output.Emit(VmOp::Add);
            }
            else
            {
                pushed = true;
            }
        }

        if (op.memDisp != 0 || !pushed)
        {
            m_output.EmitImm(VmOp::PushImm, static_cast<std::uint64_t>(op.memDisp));

            if (pushed)
            {
                m_output.Emit(VmOp::Add);
            }
        }

        return;
    }

    if (op.kind == IrOperand::Kind::Reg)
    {
        m_output.EmitReg(VmOp::PushReg, MapGuestReg(op.reg));
        return;
    }

    if (op.kind == IrOperand::Kind::Immediate)
    {
        m_output.EmitImm(VmOp::PushImm, op.immediate);
        return;
    }

    m_output.EmitImm(VmOp::PushImm, 0);
}

void Translator::EmitLoadToStack(const IrOperand& op)
{
    switch (op.kind)
    {
    case IrOperand::Kind::Reg:
        m_output.EmitReg(VmOp::PushReg, MapGuestReg(op.reg));
        break;

    case IrOperand::Kind::Immediate:
        m_output.EmitImm(VmOp::PushImm, op.immediate);
        break;

    case IrOperand::Kind::Mem:
        EmitAddressOf(op);
        m_output.Emit(VmOp::Load64);
        break;

    default:
        m_output.EmitImm(VmOp::PushImm, 0);
        break;
    }
}

void Translator::EmitStoreFromStack(const IrOperand& op)
{
    switch (op.kind)
    {
    case IrOperand::Kind::Reg:
        m_output.EmitReg(VmOp::PopReg, MapGuestReg(op.reg));
        break;

    case IrOperand::Kind::Mem:
        EmitAddressOf(op);
        m_output.Emit(VmOp::Swap);
        m_output.Emit(VmOp::Store64);
        break;

    default:
        m_output.Emit(VmOp::Drop);
        break;
    }
}

void Translator::FixupBranches()
{
    for (std::size_t i = 0; i < m_branchIndices.size(); ++i)
    {
        const std::size_t instIndex = m_branchIndices[i];
        const std::uint64_t target  = m_branchTargets[i];

        const auto it = m_guestToVm.find(target);

        if (it == m_guestToVm.end())
        {
            continue;
        }

        m_output.At(instIndex).immediate = it->second;
    }
}

TranslateResult Translator::Translate(const IrProgram& program, const TranslateOptions& options)
{
    m_output.Clear();
    m_lastError.clear();
    m_guestToVm.clear();
    m_branchIndices.clear();
    m_branchTargets.clear();
    m_nopCursor = 0;

    TranslateResult result;

    if (program.Empty())
    {
        m_lastError = "Translator: empty program";
        result.message = m_lastError;
        return result;
    }

    m_output.Emit(VmOp::Enter);

    // The interpreter's Ret pops a return address and treats zero as "return to caller".
    // The translated block is the entry point, so seed the frame with a zero sentinel to
    // give a trailing Ret something to pop. Nested Call/Ret pairs still balance because
    // Call pushes its own address above this.
    m_output.EmitImm(VmOp::PushImm, 0);

    for (std::size_t i = 0; i < program.Size(); ++i)
    {
        const auto& node = program.At(i);

        if (node.guestAddress != 0)
        {
            m_guestToVm[node.guestAddress] = m_output.Size();
        }

        switch (node.type)
        {
        case IrType::Enter:
        case IrType::Exit:
        case IrType::Nop:
            break;

        case IrType::LoadImm:
        {
            m_output.EmitImm(VmOp::PushImm, node.src.immediate);
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::LoadGuestReg:
        {
            m_output.EmitReg(VmOp::PushReg, MapGuestReg(node.src.reg));
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::StoreGuestReg:
        {
            EmitLoadToStack(node.dst);
            EmitStoreFromStack(node.src);
            break;
        }

        case IrType::Lea:
        {
            EmitAddressOf(node.src);
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::LoadMem:
        {
            EmitAddressOf(node.src);
            m_output.Emit(VmOp::Load64);
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::StoreMem:
        {
            EmitAddressOf(node.dst);
            EmitLoadToStack(node.src);
            m_output.Emit(VmOp::Swap);
            m_output.Emit(VmOp::Store64);
            break;
        }

        case IrType::Add: case IrType::Sub: case IrType::Mul:
        case IrType::Div: case IrType::Mod:
        case IrType::And: case IrType::Or: case IrType::Xor:
        case IrType::Shl: case IrType::Shr: case IrType::Sar:
        {
            EmitLoadToStack(node.dst);
            EmitLoadToStack(node.src);

            switch (node.type)
            {
            case IrType::Add: m_output.Emit(VmOp::Add); break;
            case IrType::Sub: m_output.Emit(VmOp::Sub); break;
            case IrType::Mul: m_output.Emit(VmOp::Mul); break;
            case IrType::Div: m_output.Emit(VmOp::Div); break;
            case IrType::Mod: m_output.Emit(VmOp::Mod); break;
            case IrType::And: m_output.Emit(VmOp::And); break;
            case IrType::Or:  m_output.Emit(VmOp::Or);  break;
            case IrType::Xor: m_output.Emit(VmOp::Xor); break;
            case IrType::Shl: m_output.Emit(VmOp::Shl); break;
            case IrType::Shr: m_output.Emit(VmOp::Shr); break;
            case IrType::Sar: m_output.Emit(VmOp::Sar); break;
            default: break;
            }

            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::Cmp:
        case IrType::Test:
        {
            EmitLoadToStack(node.dst);
            EmitLoadToStack(node.src);
            m_output.Emit(node.type == IrType::Cmp ? VmOp::Cmp : VmOp::Test);
            break;
        }

        case IrType::Not:
        {
            EmitLoadToStack(node.dst);
            m_output.Emit(VmOp::Not);
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::Neg:
        {
            EmitLoadToStack(node.dst);
            m_output.Emit(VmOp::Neg);
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::Push:
        {
            EmitLoadToStack(node.src);
            break;
        }

        case IrType::Pop:
        {
            EmitStoreFromStack(node.dst);
            break;
        }

        case IrType::Jmp:
        {
            m_output.EmitImm(VmOp::Jmp, 0);
            m_branchIndices.push_back(m_output.Size() - 1);
            m_branchTargets.push_back(node.targetAddress);
            break;
        }

        case IrType::Jcc:
        {
            VmOp op = VmOp::Jnz;

            switch (node.cond)
            {
            case IrCond::Zero:         op = VmOp::Jz;  break;
            case IrCond::NotZero:      op = VmOp::Jnz; break;
            case IrCond::Equal:        op = VmOp::Jz;  break;
            case IrCond::NotEqual:     op = VmOp::Jnz; break;
            case IrCond::Less:         op = VmOp::Jl;  break;
            case IrCond::LessEqual:    op = VmOp::Jle; break;
            case IrCond::Greater:      op = VmOp::Jg;  break;
            case IrCond::GreaterEqual: op = VmOp::Jge; break;
            default:                   op = VmOp::Jnz; break;
            }

            m_output.EmitImm(op, 0);
            m_branchIndices.push_back(m_output.Size() - 1);
            m_branchTargets.push_back(node.targetAddress);
            break;
        }

        case IrType::Call:
        {
            m_output.EmitImm(VmOp::Call, 0);
            m_branchIndices.push_back(m_output.Size() - 1);
            m_branchTargets.push_back(node.targetAddress);
            break;
        }

        case IrType::Ret:
        {
            m_output.Emit(VmOp::Ret);
            break;
        }

        default:
            break;
        }

        if (options.insertNops && options.nopDensity > 0)
        {
            if ((m_nopCursor++ % options.nopDensity) == 0)
            {
                m_output.Emit(VmOp::Nop);
            }
        }
    }

    m_output.Emit(VmOp::Exit);

    FixupBranches();

    result.success      = true;
    result.bytecodeSize = m_output.Size();
    result.blockCount   = m_guestToVm.size();
    result.branchCount  = m_branchIndices.size();
    result.message = "Translated " + std::to_string(program.Size()) + " IR nodes into " +
                     std::to_string(m_output.Size()) + " VM ops (" +
                     std::to_string(result.branchCount) + " branches)";
    return result;
}

Bytecode& Translator::Output()
{
    return m_output;
}

const Bytecode& Translator::Output() const
{
    return m_output;
}

const std::string& Translator::LastError() const
{
    return m_lastError;
}
}