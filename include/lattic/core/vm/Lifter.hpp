#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/vm/Ir.hpp"

namespace lattic::core::vm
{
struct LiftOptions
{
    bool        stopAtRet        = true;
    bool        stopAtCall       = false;
    bool        stopAtIndirect   = true;
    std::size_t maxInstructions  = 8192;
    std::size_t maxBlockBytes    = 0;
};

struct LiftResult
{
    bool        success = false;
    std::string message;

    std::size_t instructionCount = 0;
    std::size_t irNodeCount      = 0;
    std::size_t bytesConsumed    = 0;
};

class Lifter
{
public:
    Lifter(const Binary& binary, const PeParser& parser);

    LiftResult Lift(std::uint64_t startVa, std::uint64_t endVa, const LiftOptions& options);

    IrProgram&       Program();
    const IrProgram& Program() const;

    std::uint64_t StartVa() const;
    std::uint64_t EndVa() const;

    std::size_t InstructionCount() const;

    const std::string& LastError() const;

private:
    const Binary&   m_binary;
    const PeParser& m_parser;

    IrProgram   m_program;
    std::uint64_t m_startVa = 0;
    std::uint64_t m_endVa   = 0;
    std::size_t   m_instructionCount = 0;
    std::string   m_lastError;

    bool DecodeOne(std::uint64_t va, std::size_t& consumed);
    void Reset();
};
}