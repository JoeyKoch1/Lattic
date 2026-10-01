#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "lattic/core/vm/Bytecode.hpp"
#include "lattic/core/vm/Ir.hpp"

namespace lattic::core::vm
{
struct TranslateOptions
{
    bool insertNops        = false;
    int  nopDensity        = 6;
    bool splitImmediates   = true;
};

struct TranslateResult
{
    bool        success = false;
    std::string message;

    std::size_t bytecodeSize = 0;
    std::size_t blockCount   = 0;
    std::size_t branchCount  = 0;
};

class Translator
{
public:
    TranslateResult Translate(const IrProgram& program, const TranslateOptions& options);

    Bytecode&       Output();
    const Bytecode& Output() const;

    const std::string& LastError() const;

    static VmReg MapGuestReg(IrReg reg);

private:
    void EmitLoadToStack(const IrOperand& op);
    void EmitStoreFromStack(const IrOperand& op);
    void EmitAddressOf(const IrOperand& op);

    void FixupBranches();

    Bytecode   m_output;
    std::string m_lastError;

    std::unordered_map<std::uint64_t, std::size_t> m_guestToVm;
    std::vector<std::size_t> m_branchIndices;
    std::vector<std::uint64_t> m_branchTargets;
    int m_nopCursor = 0;
};
}