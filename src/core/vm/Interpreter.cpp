#include "lattic/core/vm/Interpreter.hpp"

#include <cstring>

#include "lattic/util/Logger.hpp"

namespace lattic::core::vm
{
namespace
{
constexpr std::size_t kHeaderSize = 12;
}

Interpreter::Interpreter() = default;

Interpreter::~Interpreter()
{
    Shutdown();
}

bool Interpreter::Initialize(const std::vector<std::uint8_t>& serializedBytecode)
{
    Shutdown();

    if (serializedBytecode.size() < kHeaderSize)
    {
        return false;
    }

    m_bytecode = serializedBytecode;
    m_stack.assign(kDefaultVmStack, 0);

    std::memset(m_ctx.regs, 0, sizeof(m_ctx.regs));

    m_ctx.bytecodeBase = m_bytecode.data();
    m_ctx.bytecodeSize = m_bytecode.size();
    m_ctx.stackBase    = m_stack.data();
    m_ctx.stackSize    = m_stack.size();
    m_ctx.ip           = kHeaderSize;
    m_ctx.sp           = 0;
    m_ctx.status       = VmStatus::Ok;
    m_ctx.lastCmp      = 0;

    m_exited      = false;
    m_result      = 0;
    m_initialized = true;

    util::Logger::Info("VmInterpreter initialized (" + std::to_string(m_bytecode.size()) +
                       " bytes)");
    return true;
}

void Interpreter::Shutdown()
{
    m_bytecode.clear();
    m_stack.clear();
    m_ctx = VmContext{};
    m_initialized = false;
    m_exited      = false;
    m_result      = 0;
}

VmContext& Interpreter::Context()
{
    return m_ctx;
}

const VmContext& Interpreter::Context() const
{
    return m_ctx;
}

bool Interpreter::Push(std::uint64_t value)
{
    if (m_ctx.sp + kStackWordSize > m_ctx.stackSize)
    {
        m_ctx.status = VmStatus::StackOverflow;
        return false;
    }

    std::memcpy(m_ctx.stackBase + m_ctx.sp, &value, kStackWordSize);
    m_ctx.sp += kStackWordSize;
    return true;
}

bool Interpreter::Pop(std::uint64_t& out)
{
    if (m_ctx.sp < kStackWordSize)
    {
        m_ctx.status = VmStatus::StackUnderflow;
        return false;
    }

    m_ctx.sp -= kStackWordSize;
    std::memcpy(&out, m_ctx.stackBase + m_ctx.sp, kStackWordSize);
    return true;
}

VmStatus Interpreter::Run()
{
    if (!m_initialized)
    {
        return VmStatus::Fault;
    }

    while (m_ctx.status == VmStatus::Ok && !m_exited)
    {
        Step();
    }

    if (m_exited)
    {
        return VmStatus::Halted;
    }

    return m_ctx.status;
}

VmStatus Interpreter::Step()
{
    if (!m_initialized || m_exited)
    {
        return m_ctx.status;
    }

    if (m_ctx.ip >= m_ctx.bytecodeSize)
    {
        m_ctx.status = VmStatus::Halted;
        return m_ctx.status;
    }

    Instruction inst;
    inst.op = static_cast<VmOp>(m_ctx.bytecodeBase[m_ctx.ip++]);

    if (HasRegister(inst.op))
    {
        if (m_ctx.ip >= m_ctx.bytecodeSize)
        {
            m_ctx.status = VmStatus::Fault;
            return m_ctx.status;
        }
        inst.reg = static_cast<VmReg>(m_ctx.bytecodeBase[m_ctx.ip++]);
    }

    if (HasImmediate(inst.op))
    {
        if (m_ctx.ip + 8 > m_ctx.bytecodeSize)
        {
            m_ctx.status = VmStatus::Fault;
            return m_ctx.status;
        }
        std::memcpy(&inst.immediate, m_ctx.bytecodeBase + m_ctx.ip, 8);
        m_ctx.ip += 8;
    }

    Dispatch(inst);
    return m_ctx.status;
}

bool Interpreter::Dispatch(const Instruction& inst)
{
    auto regIdx = [](VmReg r) { return static_cast<std::size_t>(r); };

    switch (inst.op)
    {
    case VmOp::Nop:
        break;

    case VmOp::PushImm:
        Push(inst.immediate);
        break;

    case VmOp::PushReg:
        Push(m_ctx.regs[regIdx(inst.reg)]);
        break;

    case VmOp::PopReg:
    {
        std::uint64_t v = 0;
        if (Pop(v))
        {
            m_ctx.regs[regIdx(inst.reg)] = v;
        }
        break;
    }

    case VmOp::Dup:
    {
        std::uint64_t v = 0;
        if (Pop(v))
        {
            Push(v);
            Push(v);
        }
        break;
    }

    case VmOp::Swap:
    {
        std::uint64_t a = 0;
        std::uint64_t b = 0;
        if (Pop(a) && Pop(b))
        {
            Push(a);
            Push(b);
        }
        break;
    }

    case VmOp::Drop:
    {
        std::uint64_t v = 0;
        Pop(v);
        break;
    }

    case VmOp::Add: case VmOp::Sub: case VmOp::Mul:
    case VmOp::Div: case VmOp::Mod:
    case VmOp::And: case VmOp::Or: case VmOp::Xor:
    case VmOp::Shl: case VmOp::Shr: case VmOp::Sar:
    {
        std::uint64_t rhs = 0;
        std::uint64_t lhs = 0;

        if (!Pop(rhs) || !Pop(lhs))
        {
            break;
        }

        std::uint64_t result = 0;

        switch (inst.op)
        {
        case VmOp::Add: result = lhs + rhs; break;
        case VmOp::Sub: result = lhs - rhs; break;
        case VmOp::Mul: result = lhs * rhs; break;
        case VmOp::Div:
            if (rhs == 0) { m_ctx.status = VmStatus::DivByZero; return false; }
            result = lhs / rhs;
            break;
        case VmOp::Mod:
            if (rhs == 0) { m_ctx.status = VmStatus::DivByZero; return false; }
            result = lhs % rhs;
            break;
        case VmOp::And: result = lhs & rhs; break;
        case VmOp::Or:  result = lhs | rhs; break;
        case VmOp::Xor: result = lhs ^ rhs; break;
        case VmOp::Shl: result = lhs << (rhs & 63); break;
        case VmOp::Shr: result = lhs >> (rhs & 63); break;
        case VmOp::Sar:
            result = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(lhs) >> (rhs & 63));
            break;
        default: break;
        }

        m_ctx.lastCmp = lhs - rhs;
        Push(result);
        break;
    }

    case VmOp::Not:
    {
        std::uint64_t v = 0;
        if (Pop(v)) Push(~v);
        break;
    }

    case VmOp::Neg:
    {
        std::uint64_t v = 0;
        if (Pop(v)) Push(static_cast<std::uint64_t>(-static_cast<std::int64_t>(v)));
        break;
    }

    case VmOp::Cmp:
    case VmOp::Test:
    {
        std::uint64_t rhs = 0;
        std::uint64_t lhs = 0;

        if (!Pop(rhs) || !Pop(lhs))
        {
            break;
        }

        m_ctx.lastCmp = inst.op == VmOp::Cmp ? (lhs - rhs) : (lhs & rhs);
        break;
    }

    case VmOp::Load8: case VmOp::Load16:
    case VmOp::Load32: case VmOp::Load64:
    {
        std::uint64_t addr = 0;
        if (!Pop(addr)) break;

        const auto* base = reinterpret_cast<const std::uint8_t*>(addr);
        std::uint64_t value = 0;

        switch (inst.op)
        {
        case VmOp::Load8:  value = *base; break;
        case VmOp::Load16: { std::uint16_t v; std::memcpy(&v, base, 2); value = v; break; }
        case VmOp::Load32: { std::uint32_t v; std::memcpy(&v, base, 4); value = v; break; }
        case VmOp::Load64: { std::uint64_t v; std::memcpy(&v, base, 8); value = v; break; }
        default: break;
        }

        Push(value);
        break;
    }

    case VmOp::Store8: case VmOp::Store16:
    case VmOp::Store32: case VmOp::Store64:
    {
        std::uint64_t addr = 0;
        std::uint64_t value = 0;

        if (!Pop(addr) || !Pop(value)) break;

        auto* base = reinterpret_cast<std::uint8_t*>(addr);

        switch (inst.op)
        {
        case VmOp::Store8:  { std::uint8_t v = static_cast<std::uint8_t>(value); std::memcpy(base, &v, 1); break; }
        case VmOp::Store16: { std::uint16_t v = static_cast<std::uint16_t>(value); std::memcpy(base, &v, 2); break; }
        case VmOp::Store32: { std::uint32_t v = static_cast<std::uint32_t>(value); std::memcpy(base, &v, 4); break; }
        case VmOp::Store64: { std::memcpy(base, &value, 8); break; }
        default: break;
        }
        break;
    }

    case VmOp::Jmp:
        m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Jz:
        if (m_ctx.lastCmp == 0) m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Jnz:
        if (m_ctx.lastCmp != 0) m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Jl:
        if (static_cast<std::int64_t>(m_ctx.lastCmp) < 0)
            m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Jle:
        if (static_cast<std::int64_t>(m_ctx.lastCmp) <= 0)
            m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Jg:
        if (static_cast<std::int64_t>(m_ctx.lastCmp) > 0)
            m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Jge:
        if (static_cast<std::int64_t>(m_ctx.lastCmp) >= 0)
            m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Call:
        Push(m_ctx.ip);
        m_ctx.ip = static_cast<std::size_t>(inst.immediate);
        break;

    case VmOp::Ret:
    {
        std::uint64_t target = 0;

        if (Pop(target))
        {
            if (target == 0)
            {
                m_exited = true;
                m_result = m_ctx.regs[regIdx(VmReg::R0)];
                break;
            }

            m_ctx.ip = static_cast<std::size_t>(target);
        }
        break;
    }

    case VmOp::Enter:
        break;

    case VmOp::Exit:
        m_result = m_ctx.regs[regIdx(VmReg::R0)];
        m_exited = true;
        break;

    default:
        m_ctx.status = VmStatus::BadOpcode;
        return false;
    }

    return true;
}

bool Interpreter::HasExited() const
{
    return m_exited;
}

std::uint64_t Interpreter::Result() const
{
    return m_result;
}

const char* Interpreter::StatusName(VmStatus status)
{
    switch (status)
    {
    case VmStatus::Ok:             return "Ok";
    case VmStatus::Halted:         return "Halted";
    case VmStatus::Fault:          return "Fault";
    case VmStatus::DivByZero:      return "DivByZero";
    case VmStatus::StackOverflow:  return "StackOverflow";
    case VmStatus::StackUnderflow: return "StackUnderflow";
    case VmStatus::BadOpcode:      return "BadOpcode";
    case VmStatus::BadBranch:      return "BadBranch";
    default:                       return "?";
    }
}
}