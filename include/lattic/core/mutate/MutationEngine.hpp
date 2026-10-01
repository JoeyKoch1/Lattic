#pragma once

#include <memory>
#include <string>
#include <vector>

#include "lattic/core/mutate/MutationPass.hpp"

namespace lattic::core::mutate
{
class MutationEngine
{
public:
    MutationEngine();

    void AddPass(std::unique_ptr<MutationPass> pass);
    void AddDefaultPasses();
    void ClearPasses();

    MutationResult Apply(IrProgram& program);
    MutationResult Apply(IrProgram& program, const MutationOptions& options);

    const MutationOptions& Options() const;
    void SetOptions(const MutationOptions& options);

    std::size_t PassCount() const;

    const std::string& LastError() const;

private:
    std::vector<std::unique_ptr<MutationPass>> m_passes;
    MutationOptions m_options;
    std::string m_lastError;
};
}