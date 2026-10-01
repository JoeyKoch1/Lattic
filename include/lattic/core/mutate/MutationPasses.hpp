#pragma once

#include "lattic/core/mutate/MutationPass.hpp"

namespace lattic::core::mutate
{
class SubstitutionPass final : public MutationPass
{
public:
    const char* Name() const override { return "Substitution"; }
    MutationResult Apply(IrProgram& program, const MutationOptions& options) override;
};

class MbaPass final : public MutationPass
{
public:
    const char* Name() const override { return "Mba"; }
    MutationResult Apply(IrProgram& program, const MutationOptions& options) override;
};

class OpaquePredicatePass final : public MutationPass
{
public:
    const char* Name() const override { return "OpaquePredicate"; }
    MutationResult Apply(IrProgram& program, const MutationOptions& options) override;
};

class DeadCodePass final : public MutationPass
{
public:
    const char* Name() const override { return "DeadCode"; }
    MutationResult Apply(IrProgram& program, const MutationOptions& options) override;
};

class ConstantObfuscationPass final : public MutationPass
{
public:
    const char* Name() const override { return "ConstantObfuscation"; }
    MutationResult Apply(IrProgram& program, const MutationOptions& options) override;
};

std::vector<vm::IrReg> CollectUsedRegisters(const IrProgram& program);
std::vector<vm::IrReg> PickScratchRegisters(std::size_t count,
                                            const std::vector<vm::IrReg>& used);
}