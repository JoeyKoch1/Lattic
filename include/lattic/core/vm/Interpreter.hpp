#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/vm/Bytecode.hpp"
#include "lattic/core/vm/VmArchitecture.hpp"

namespace lattic::core::vm
{
enum class VmStatus
{
    Ok,
    Halted,
    Fault,
    DivByZero,
    StackOverflow,
    StackUnderflow,
    BadOpcode,
    BadBranch
};

struct VmContext
{
    std::uint64_t regs[kRegisterCount] = {};
    std::uint8_t* bytecodeBase = nullptr;
    std::size_t   bytecodeSize = 0;
    std::uint8_t* stackBase = nullptr;
    std::size_t   stackSize = 0;
    std::size_t   ip = 0;
    std::size_t   sp = 0;
    VmStatus      status = VmStatus::Ok;
    std::uint64_t lastCmp = 0;
};

class Interpreter
{
public:
    Interpreter();
    ~Interpreter();

    bool Initialize(const std::vector<std::uint8_t>& serializedBytecode);
    void Shutdown();

    VmContext&       Context();
    const VmContext& Context() const;

    VmStatus Run();
    VmStatus Step();

    bool          HasExited() const;
    std::uint64_t Result() const;

    static const char* StatusName(VmStatus status);

private:
    bool Dispatch(const Instruction& inst);
    bool Push(std::uint64_t value);
    bool Pop(std::uint64_t& out);

    std::vector<std::uint8_t> m_bytecode;
    std::vector<std::uint8_t> m_stack;
    VmContext                 m_ctx;
    bool                      m_initialized = false;
    bool                      m_exited      = false;
    std::uint64_t             m_result      = 0;
};
}