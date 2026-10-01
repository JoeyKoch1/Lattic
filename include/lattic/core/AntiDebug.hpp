#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lattic::core
{
enum class DebugResponse
{
    Ignore,      // keep running and do nothing
    Dialog,      // tell the user and exit, the friendly form
    Terminate    // exit immediately with no dialog
};

struct AntiDebugOptions
{
    // Compared case insensitively against the executable name of every running process.
    std::vector<std::string> debuggerNames;

    // A timer, not a spin loop: one poll is a full process enumeration, so polling too
    // tightly pins a core for the life of the process.
    std::uint32_t pollIntervalMs = 10;

    // Independent, because the checks have different false positive profiles under
    // virtualisation and emulation.
    bool checkDebugPort         = true;
    bool checkDebugObjectHandle = true;
    bool checkDebugFlags        = true;
    bool checkHardwareBreakpoints = true;
    bool checkRemoteDebugger    = true;
    bool checkDebuggerProcesses = true;

    DebugResponse response = DebugResponse::Dialog;

    std::string dialogTitle   = "LatticProtect";
    std::string dialogMessage = "This application cannot run in a debugging environment.";
    std::uint32_t exitCode    = 0xC0000005u;
};

struct DebuggerCheck
{
    bool detected = false;

    std::string method;

    // Only populated when the process scan is what found it.
    std::vector<std::string> foundProcesses;
};

// Anti-debugging checks, all of them read only: they inspect this process and the process
// list, and never touch a debugger or anything else attached to the target.
class AntiDebug
{
public:
    AntiDebug() = default;
    ~AntiDebug() = default;

    AntiDebug(const AntiDebug&)            = delete;
    AntiDebug& operator=(const AntiDebug&) = delete;

    // Runs every check the options enable and reports the first hit.
    static DebuggerCheck Check(const AntiDebugOptions& options);

    static bool IsDebuggerPresent();
    static bool HasDebugPort();
    static bool HasDebugObjectHandle();
    static bool HasDebugFlags();
    static bool HasHardwareBreakpoints();
    static bool HasRemoteDebugger();

    // Returns only the names that actually matched, so the caller reports what it found
    // rather than what it guessed.
    static std::vector<std::string> FindDebuggerProcesses(
        const std::vector<std::string>& names);

    // Only Dialog shows a window. Ignore returns, Terminate falls through to ExitProcess.
    static void Respond(const AntiDebugOptions& options, const DebuggerCheck& check);

    static const char* ResponseName(DebugResponse response);
};
}
