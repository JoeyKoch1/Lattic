#include "lattic/core/vm/Lifter.hpp"

#include <cstring>

#include <Zydis/Zydis.h>

#include "lattic/util/Logger.hpp"

namespace lattic::core::vm
{
namespace
{
IrReg MapZydisRegister(ZydisRegister reg)
{
    switch (reg)
    {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_AL:  case ZYDIS_REGISTER_AH:
        return IrReg::Rax;
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_BL:  case ZYDIS_REGISTER_BH:
        return IrReg::Rbx;
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_CL:  case ZYDIS_REGISTER_CH:
        return IrReg::Rcx;
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_DL:  case ZYDIS_REGISTER_DH:
        return IrReg::Rdx;
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_SIL:
        return IrReg::Rsi;
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_DIL:
        return IrReg::Rdi;
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_BPL:
        return IrReg::Rbp;
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_SPL:
        return IrReg::Rsp;
    case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:  case ZYDIS_REGISTER_R8W:  case ZYDIS_REGISTER_R8B:  return IrReg::R8;
    case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:  case ZYDIS_REGISTER_R9W:  case ZYDIS_REGISTER_R9B:  return IrReg::R9;
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return IrReg::R10;
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return IrReg::R11;
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return IrReg::R12;
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return IrReg::R13;
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return IrReg::R14;
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return IrReg::R15;
    case ZYDIS_REGISTER_RIP: case ZYDIS_REGISTER_EIP: return IrReg::Rip;
    default: return IrReg::None;
    }
}

IrCond MapCondition(ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_JZ:
        return IrCond::Zero;
    case ZYDIS_MNEMONIC_JNZ:
        return IrCond::NotZero;
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
        return mnemonic == ZYDIS_MNEMONIC_JL  ? IrCond::Less :
               mnemonic == ZYDIS_MNEMONIC_JLE ? IrCond::LessEqual :
               mnemonic == ZYDIS_MNEMONIC_JB  ? IrCond::Less :
                                                IrCond::LessEqual;
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNL:
        return mnemonic == ZYDIS_MNEMONIC_JNLE ? IrCond::Greater :
               mnemonic == ZYDIS_MNEMONIC_JNL  ? IrCond::GreaterEqual :
               mnemonic == ZYDIS_MNEMONIC_JNBE ? IrCond::Greater :
                                                IrCond::GreaterEqual;
    default:
        return IrCond::NotZero;
    }
}

bool IsConditionalJump(ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_JZ:   case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JB:   case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JNB:  case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JL:   case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNL:  case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JS:   case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JO:   case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JP:   case ZYDIS_MNEMONIC_JNP:
        return true;
    default:
        return false;
    }
}

void FillMemoryOperand(IrOperand& out, const ZydisDecodedOperand& op)
{
    out.kind = IrOperand::Kind::Mem;

    if (op.mem.base != ZYDIS_REGISTER_NONE)
    {
        out.memBase = MapZydisRegister(op.mem.base);
    }

    if (op.mem.index != ZYDIS_REGISTER_NONE)
    {
        out.memIndex = MapZydisRegister(op.mem.index);
    }

    out.memScale = static_cast<int>(op.mem.scale);
    out.memDisp  = static_cast<std::int64_t>(op.mem.disp.value);
}

void FillOperand(IrOperand& out, const ZydisDecodedOperand& op)
{
    switch (op.type)
    {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        out.kind = IrOperand::Kind::Reg;
        out.reg  = MapZydisRegister(op.reg.value);
        break;

    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        out.kind = IrOperand::Kind::Immediate;
        out.immediate = op.imm.is_signed
            ? static_cast<std::uint64_t>(op.imm.value.s)
            : static_cast<std::uint64_t>(op.imm.value.u);
        break;

    case ZYDIS_OPERAND_TYPE_MEMORY:
        FillMemoryOperand(out, op);
        break;

    default:
        out.kind = IrOperand::Kind::None;
        break;
    }
}

std::uint8_t OperandSize(const ZydisDecodedOperand& op)
{
    if (op.size == 0)
    {
        return 8;
    }
    return static_cast<std::uint8_t>(op.size);
}
}

Lifter::Lifter(const Binary& binary, const PeParser& parser)
    : m_binary(binary), m_parser(parser)
{
}

void Lifter::Reset()
{
    m_program.Clear();
    m_instructionCount = 0;
    m_lastError.clear();
}

LiftResult Lifter::Lift(std::uint64_t startVa, std::uint64_t endVa, const LiftOptions& options)
{
    Reset();

    m_startVa = startVa;
    m_endVa   = endVa;

    LiftResult result;

    if (!m_parser.IsParsed())
    {
        m_lastError = "Lifter: parser not initialized";
        result.message = m_lastError;
        return result;
    }

    if (endVa <= startVa)
    {
        m_lastError = "Lifter: invalid range";
        result.message = m_lastError;
        return result;
    }

    ZydisDecoder decoder;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                                       ZYDIS_STACK_WIDTH_64)))
    {
        m_lastError = "Lifter: failed to init Zydis decoder";
        result.message = m_lastError;
        return result;
    }

    (void)decoder;

    IrNode enter;
    enter.type         = IrType::Enter;
    enter.guestAddress = startVa;
    m_program.Append(enter);

    std::uint64_t va = startVa;
    std::size_t   bytes = 0;

    while (va < endVa && m_instructionCount < options.maxInstructions)
    {
        std::size_t consumed = 0;

        if (!DecodeOne(va, consumed))
        {
            break;
        }

        va += consumed;
        bytes += consumed;
        ++m_instructionCount;

        if (options.maxBlockBytes > 0 && bytes >= options.maxBlockBytes)
        {
            break;
        }
    }

    IrNode exit;
    exit.type = IrType::Exit;
    m_program.Append(exit);

    result.success          = m_instructionCount > 0;
    result.instructionCount = m_instructionCount;
    result.irNodeCount      = m_program.Size();
    result.bytesConsumed    = bytes;
    result.message = "Lifted " + std::to_string(m_instructionCount) + " instructions (" +
                     std::to_string(bytes) + " bytes) into " +
                     std::to_string(m_program.Size()) + " IR nodes";

    util::Logger::Info("Lifter: " + result.message);
    return result;
}

bool Lifter::DecodeOne(std::uint64_t va, std::size_t& consumed)
{
    consumed = 0;

    std::uint32_t fileOffset = 0;

    if (!m_parser.VaToOffset(va, fileOffset))
    {
        return false;
    }

    const std::size_t remaining = m_binary.Size() - fileOffset;

    if (remaining < 1)
    {
        return false;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

    const std::uint8_t* code = m_binary.Data() + fileOffset;

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code, remaining, &insn, ops)))
    {
        return false;
    }

    const auto mnemonic = insn.mnemonic;
    const std::uint8_t length = static_cast<std::uint8_t>(insn.length);

    auto emit = [&](IrNode node)
    {
        node.guestAddress = va;
        m_program.Append(node);
    };

    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_NOP:
    {
        IrNode n;
        n.type = IrType::Nop;
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_MOV:
    {
        if (insn.operand_count < 2)
        {
            return false;
        }

        IrNode n;
        FillOperand(n.dst, ops[0]);
        FillOperand(n.src, ops[1]);
        n.operandSize = OperandSize(ops[0]);

        if (n.dst.kind == IrOperand::Kind::Reg && n.src.kind == IrOperand::Kind::Reg)
        {
            n.type = IrType::LoadGuestReg;
        }
        else if (n.dst.kind == IrOperand::Kind::Reg && n.src.kind == IrOperand::Kind::Immediate)
        {
            n.type = IrType::LoadImm;
        }
        else if (n.dst.kind == IrOperand::Kind::Reg && n.src.kind == IrOperand::Kind::Mem)
        {
            n.type = IrType::LoadMem;
        }
        else if (n.dst.kind == IrOperand::Kind::Mem && n.src.kind == IrOperand::Kind::Reg)
        {
            n.type = IrType::StoreMem;
        }
        else if (n.dst.kind == IrOperand::Kind::Mem && n.src.kind == IrOperand::Kind::Immediate)
        {
            n.type = IrType::StoreMem;
        }
        else
        {
            return false;
        }

        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_LEA:
    {
        if (insn.operand_count < 2)
        {
            return false;
        }

        IrNode n;
        n.type = IrType::Lea;
        FillOperand(n.dst, ops[0]);
        FillOperand(n.src, ops[1]);
        n.operandSize = OperandSize(ops[0]);
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_AND: case ZYDIS_MNEMONIC_OR:
    case ZYDIS_MNEMONIC_XOR: case ZYDIS_MNEMONIC_CMP:
    case ZYDIS_MNEMONIC_TEST: case ZYDIS_MNEMONIC_SHL:
    case ZYDIS_MNEMONIC_SHR: case ZYDIS_MNEMONIC_SAR:
    {
        if (insn.operand_count < 2)
        {
            return false;
        }

        IrNode n;
        n.operandSize = OperandSize(ops[0]);
        FillOperand(n.dst, ops[0]);
        FillOperand(n.src, ops[1]);

        switch (mnemonic)
        {
        case ZYDIS_MNEMONIC_ADD:  n.type = IrType::Add; break;
        case ZYDIS_MNEMONIC_SUB:  n.type = IrType::Sub; break;
        case ZYDIS_MNEMONIC_AND:  n.type = IrType::And; break;
        case ZYDIS_MNEMONIC_OR:   n.type = IrType::Or;  break;
        case ZYDIS_MNEMONIC_XOR:  n.type = IrType::Xor; break;
        case ZYDIS_MNEMONIC_CMP:  n.type = IrType::Cmp; break;
        case ZYDIS_MNEMONIC_TEST: n.type = IrType::Test; break;
        case ZYDIS_MNEMONIC_SHL:  n.type = IrType::Shl; break;
        case ZYDIS_MNEMONIC_SHR:  n.type = IrType::Shr; break;
        case ZYDIS_MNEMONIC_SAR:  n.type = IrType::Sar; break;
        default: return false;
        }

        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_INC: case ZYDIS_MNEMONIC_DEC:
    {
        if (insn.operand_count < 1)
        {
            return false;
        }

        IrNode n;
        n.type = mnemonic == ZYDIS_MNEMONIC_INC ? IrType::Add : IrType::Sub;
        n.operandSize = OperandSize(ops[0]);
        FillOperand(n.dst, ops[0]);
        n.src.kind = IrOperand::Kind::Immediate;
        n.src.immediate = 1;
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_NOT: case ZYDIS_MNEMONIC_NEG:
    {
        if (insn.operand_count < 1)
        {
            return false;
        }

        IrNode n;
        n.type = mnemonic == ZYDIS_MNEMONIC_NOT ? IrType::Not : IrType::Neg;
        n.operandSize = OperandSize(ops[0]);
        FillOperand(n.dst, ops[0]);
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_PUSH:
    {
        if (insn.operand_count < 1)
        {
            return false;
        }

        IrNode n;
        n.type = IrType::Push;
        n.operandSize = 8;
        FillOperand(n.src, ops[0]);
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_POP:
    {
        if (insn.operand_count < 1)
        {
            return false;
        }

        IrNode n;
        n.type = IrType::Pop;
        n.operandSize = 8;
        FillOperand(n.dst, ops[0]);
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_JMP:
    {
        IrNode n;
        n.type = IrType::Jmp;

        if (insn.operand_count >= 1 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            const auto& imm = ops[0].imm.value;
            const std::int64_t rel = imm.s;
            n.targetAddress = va + length + rel;
            emit(n);
        }
        else
        {
            IrOperand target;
            FillOperand(target, ops[0]);
            n.src = target;
            emit(n);
        }

        break;
    }

    case ZYDIS_MNEMONIC_CALL:
    {
        IrNode n;
        n.type = IrType::Call;

        if (insn.operand_count >= 1 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            const std::int64_t rel = ops[0].imm.value.s;
            n.targetAddress = va + length + rel;
        }
        else if (insn.operand_count >= 1)
        {
            FillOperand(n.src, ops[0]);
        }

        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_RET:
    {
        IrNode n;
        n.type = IrType::Ret;
        emit(n);
        break;
    }

    case ZYDIS_MNEMONIC_LEAVE:
    {
        IrNode mov;
        mov.type = IrType::LoadGuestReg;
        mov.dst.kind = IrOperand::Kind::Reg;
        mov.dst.reg  = IrReg::Rsp;
        mov.src.kind = IrOperand::Kind::Reg;
        mov.src.reg  = IrReg::Rbp;
        mov.operandSize = 8;
        emit(mov);

        IrNode pop;
        pop.type = IrType::Pop;
        pop.dst.kind = IrOperand::Kind::Reg;
        pop.dst.reg  = IrReg::Rbp;
        pop.operandSize = 8;
        emit(pop);
        break;
    }

    default:
    {
        if (IsConditionalJump(mnemonic))
        {
            IrNode n;
            n.type = IrType::Jcc;
            n.cond = MapCondition(mnemonic);

            if (insn.operand_count >= 1 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                const std::int64_t rel = ops[0].imm.value.s;
                n.targetAddress = va + length + rel;
            }

            emit(n);
            break;
        }

        return false;
    }
    }

    consumed = length;
    return true;
}

IrProgram& Lifter::Program()
{
    return m_program;
}

const IrProgram& Lifter::Program() const
{
    return m_program;
}

std::uint64_t Lifter::StartVa() const
{
    return m_startVa;
}

std::uint64_t Lifter::EndVa() const
{
    return m_endVa;
}

std::size_t Lifter::InstructionCount() const
{
    return m_instructionCount;
}

const std::string& Lifter::LastError() const
{
    return m_lastError;
}
}