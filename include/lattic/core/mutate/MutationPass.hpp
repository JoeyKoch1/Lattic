#pragma once

#include <cstdint>
#include <string>

#include "lattic/core/vm/Ir.hpp"

namespace lattic::core::mutate
{
using vm::IrProgram;

struct MutationOptions
{
    bool enableSubstitution        = true;
    bool enableMba                 = true;
    bool enableOpaquePredicates    = true;
    bool enableDeadCode            = true;
    bool enableConstantObfuscation = true;

    int substitutionRate        = 100;
    int mbaRate                 = 40;
    int opaquePredicateRate     = 25;
    int deadCodeRate            = 35;
    int constantObfuscationRate = 60;

    std::size_t maxDeadCodeNodes   = 6;
    std::size_t maxMbaExpansion    = 24;
    std::size_t maxOpaquePredicates = 64;

    std::uint32_t seed = 0xCAFEBABE;
};

struct MutationResult
{
    bool        success = true;
    std::string message;

    std::size_t inputNodes    = 0;
    std::size_t outputNodes   = 0;
    std::size_t transforms    = 0;
};

class MutationPass
{
public:
    virtual ~MutationPass() = default;

    virtual const char* Name() const = 0;
    virtual MutationResult Apply(IrProgram& program, const MutationOptions& options) = 0;
};
}