#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/vm/Bytecode.hpp"
#include "lattic/core/vm/Lifter.hpp"
#include "lattic/core/vm/Translator.hpp"

namespace lattic::core::vm
{
struct VirtualizeOptions
{
    LiftOptions      lift;
    TranslateOptions translate;

    bool        obfuscateOpcodes = true;
    std::uint32_t obfuscationSeed = 0x1337BEEF;

    std::string sectionName = ".lattic";
};

struct VirtualizeReport
{
    bool        success = false;
    std::string message;

    std::uint64_t startVa = 0;
    std::uint64_t endVa   = 0;

    std::size_t instructionsLifted = 0;
    std::size_t irNodes            = 0;
    std::size_t vmOps              = 0;
    std::size_t branchesPatched    = 0;

    std::vector<std::uint8_t> serializedBytecode;
};

class CodeVirtualizer
{
public:
    CodeVirtualizer(Binary& binary, PeParser& parser);

    VirtualizeReport Virtualize(std::uint64_t startVa, std::uint64_t endVa,
                                const VirtualizeOptions& options);

    const Bytecode& LastBytecode() const;

    const std::string& LastError() const;

    bool ExecuteInProcess(std::uint64_t& resultOut);

private:
    Binary&   m_binary;
    PeParser& m_parser;

    Bytecode    m_lastBytecode;
    std::string m_lastError;
};
}