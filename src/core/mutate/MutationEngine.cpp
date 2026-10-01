#include "lattic/core/mutate/MutationEngine.hpp"

#include "lattic/core/mutate/MutationPasses.hpp"
#include "lattic/util/Logger.hpp"

namespace lattic::core::mutate
{
MutationEngine::MutationEngine()
{
    AddDefaultPasses();
}

void MutationEngine::AddPass(std::unique_ptr<MutationPass> pass)
{
    if (pass != nullptr)
    {
        m_passes.push_back(std::move(pass));
    }
}

void MutationEngine::AddDefaultPasses()
{
    ClearPasses();

    // Order matters. Dead code first so the later passes rewrite real operations, then
    // constant and arithmetic rewriting, then opaque predicates on the result.
    AddPass(std::make_unique<DeadCodePass>());
    AddPass(std::make_unique<ConstantObfuscationPass>());
    AddPass(std::make_unique<SubstitutionPass>());
    AddPass(std::make_unique<MbaPass>());
    AddPass(std::make_unique<OpaquePredicatePass>());
}

void MutationEngine::ClearPasses()
{
    m_passes.clear();
}

const MutationOptions& MutationEngine::Options() const
{
    return m_options;
}

void MutationEngine::SetOptions(const MutationOptions& options)
{
    m_options = options;
}

std::size_t MutationEngine::PassCount() const
{
    return m_passes.size();
}

MutationResult MutationEngine::Apply(IrProgram& program)
{
    return Apply(program, m_options);
}

MutationResult MutationEngine::Apply(IrProgram& program, const MutationOptions& options)
{
    m_lastError.clear();

    MutationResult total;
    total.inputNodes = program.Size();

    if (program.Empty())
    {
        m_lastError   = "MutationEngine: nothing to mutate";
        total.success = false;
        total.message = m_lastError;
        return total;
    }

    for (const auto& pass : m_passes)
    {
        const std::string name = pass->Name();

        const bool enabled =
            (name == "DeadCode"             && options.enableDeadCode) ||
            (name == "ConstantObfuscation"  && options.enableConstantObfuscation) ||
            (name == "Substitution"         && options.enableSubstitution) ||
            (name == "Mba"                  && options.enableMba) ||
            (name == "OpaquePredicate"      && options.enableOpaquePredicates);

        if (!enabled)
        {
            continue;
        }

        const MutationResult result = pass->Apply(program, options);

        if (!result.success)
        {
            m_lastError   = std::string("MutationEngine: ") + name + ": " + result.message;
            total.success = false;
            total.message = m_lastError;
            return total;
        }

        total.transforms += result.transforms;
    }

    total.outputNodes = program.Size();
    total.success     = true;
    total.message     = "Mutated " + std::to_string(total.inputNodes) + " nodes into " +
                       std::to_string(total.outputNodes) + " with " +
                       std::to_string(total.transforms) + " transform(s)";

    util::Logger::Info("MutationEngine: " + total.message);
    return total;
}

const std::string& MutationEngine::LastError() const
{
    return m_lastError;
}
}
