#include "lattic/core/vm/CodeVirtualizer.hpp"

#include "lattic/core/vm/Interpreter.hpp"
#include "lattic/util/Logger.hpp"

namespace lattic::core::vm
{
CodeVirtualizer::CodeVirtualizer(Binary& binary, PeParser& parser)
    : m_binary(binary), m_parser(parser)
{
}

VirtualizeReport CodeVirtualizer::Virtualize(std::uint64_t startVa, std::uint64_t endVa,
                                             const VirtualizeOptions& options)
{
    m_lastError.clear();
    m_lastBytecode.Clear();

    VirtualizeReport report;
    report.startVa = startVa;
    report.endVa   = endVa;

    Lifter lifter(m_binary, m_parser);
    LiftResult lifted = lifter.Lift(startVa, endVa, options.lift);

    if (!lifted.success)
    {
        m_lastError = "Lift failed: " + lifted.message;
        report.message = m_lastError;
        return report;
    }

    report.instructionsLifted = lifted.instructionCount;
    report.irNodes            = lifted.irNodeCount;

    Translator translator;
    TranslateResult translated = translator.Translate(lifter.Program(), options.translate);

    if (!translated.success)
    {
        m_lastError = "Translate failed: " + translated.message;
        report.message = m_lastError;
        return report;
    }

    report.vmOps           = translated.bytecodeSize;
    report.branchesPatched = translated.branchCount;

    m_lastBytecode = translator.Output();
    report.serializedBytecode = m_lastBytecode.Serialize();

    report.success = true;
    report.message = "Virtualized " + std::to_string(report.instructionsLifted) +
                     " instructions into " + std::to_string(report.vmOps) + " VM ops";

    util::Logger::Info("CodeVirtualizer: " + report.message);
    return report;
}

const Bytecode& CodeVirtualizer::LastBytecode() const
{
    return m_lastBytecode;
}

const std::string& CodeVirtualizer::LastError() const
{
    return m_lastError;
}

bool CodeVirtualizer::ExecuteInProcess(std::uint64_t& resultOut)
{
    if (m_lastBytecode.Empty())
    {
        m_lastError = "No bytecode available to execute";
        return false;
    }

    Interpreter interp;

    if (!interp.Initialize(m_lastBytecode.Serialize()))
    {
        m_lastError = "Interpreter init failed";
        return false;
    }

    const VmStatus status = interp.Run();

    if (status != VmStatus::Halted && status != VmStatus::Ok)
    {
        m_lastError = std::string("VM status: ") + Interpreter::StatusName(status);
        return false;
    }

    resultOut = interp.Result();
    return true;
}
}