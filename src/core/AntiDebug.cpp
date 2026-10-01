#include "lattic/core/AntiDebug.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>

#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

#include <psapi.h>
#include <tlhelp32.h>

namespace lattic::core
{
namespace
{
// ProcessDebugPort, ProcessDebugObjectHandle and ProcessDebugFlags. Resolved from ntdll at
// run time so no import table entry gives the check away, and so the build needs no extra
// library.
constexpr int kProcessDebugPort         = 7;
constexpr int kProcessDebugObjectHandle = 0x1E;
constexpr int kProcessDebugFlags        = 0x1F;

using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, int, void*, ULONG, PULONG);

NtQueryInformationProcessFn ResolveNtQuery()
{
    static NtQueryInformationProcessFn cached = nullptr;
    static bool attempted = false;

    if (attempted)
    {
        return cached;
    }

    attempted = true;

    if (HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll"))
    {
        cached = reinterpret_cast<NtQueryInformationProcessFn>(
            reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtQueryInformationProcess")));
    }

    return cached;
}

bool QueryProcessClass(int infoClass, void* buffer, ULONG length)
{
    NtQueryInformationProcessFn query = ResolveNtQuery();

    if (query == nullptr || buffer == nullptr || length == 0)
    {
        return false;
    }

    ULONG returned = 0;

    if (query(::GetCurrentProcess(), infoClass, buffer, length, &returned) != 0)
    {
        return false;
    }

    return returned == length;
}

std::string LowerAscii(std::string text)
{
    for (char& c : text)
    {
        if (c >= 'A' && c <= 'Z')
        {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }

    return text;
}

// Strips a trailing ".exe" so "x64dbg" and "x64dbg.exe" match the same process.
std::string NormaliseProcessName(const std::string& name)
{
    std::string lowered = LowerAscii(name);

    if (lowered.size() > 4 && lowered.compare(lowered.size() - 4, 4, ".exe") == 0)
    {
        lowered.erase(lowered.size() - 4);
    }

    return lowered;
}
}

bool AntiDebug::IsDebuggerPresent()
{
    // Not the interesting signal, but free, and it still fires when only the ntdll
    // ProcessDebugPort path has been patched out.
    return ::IsDebuggerPresent() != FALSE;
}

bool AntiDebug::HasDebugPort()
{
    ULONG_PTR port = 0;

    if (!QueryProcessClass(kProcessDebugPort, &port, sizeof(port)))
    {
        return false;
    }

    return port != 0;
}

bool AntiDebug::HasDebugObjectHandle()
{
    ULONG_PTR handle = 0;

    if (!QueryProcessClass(kProcessDebugObjectHandle, &handle, sizeof(handle)))
    {
        return false;
    }

    return handle != 0;
}

bool AntiDebug::HasDebugFlags()
{
    ULONG flags = 0;

    if (!QueryProcessClass(kProcessDebugFlags, &flags, sizeof(flags)))
    {
        return false;
    }

    // NoDebugInherit is not a debugging signal, it just means debug children were not
    // inherited. Everything else in this class means something is attached.
    return (flags & 0x01u) == 0;
}

bool AntiDebug::HasHardwareBreakpoints()
{
    // DR0 to DR3 through CONTEXT. This is the one check with a real false positive risk on
    // some virtual machines, which is why it can be turned off on its own.
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!::GetThreadContext(::GetCurrentThread(), &context))
    {
        return false;
    }

    return context.Dr0 != 0 || context.Dr1 != 0 ||
           context.Dr2 != 0 || context.Dr3 != 0;
}

bool AntiDebug::HasRemoteDebugger()
{
    BOOL remote = FALSE;

    if (!::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &remote))
    {
        return false;
    }

    return remote != FALSE;
}

std::vector<std::string> AntiDebug::FindDebuggerProcesses(
    const std::vector<std::string>& names)
{
    std::vector<std::string> found;

    if (names.empty())
    {
        return found;
    }

    std::vector<std::string> wanted;
    wanted.reserve(names.size());

    for (const auto& name : names)
    {
        const std::string normalised = NormaliseProcessName(name);

        if (!normalised.empty())
        {
            wanted.push_back(normalised);
        }
    }

    if (wanted.empty())
    {
        return found;
    }

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return found;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (::Process32FirstW(snapshot, &entry))
    {
        do
        {
            const std::string name = NormaliseProcessName(
                util::str::Narrow(entry.szExeFile).c_str());

            if (name.empty())
            {
                continue;
            }

            const bool match = std::find(wanted.begin(), wanted.end(), name) != wanted.end();

            if (match)
            {
                // A debugger running several processes is reported once, not once each.
                const bool already = std::find(found.begin(), found.end(), name) != found.end();

                if (!already)
                {
                    found.push_back(name);
                }
            }
        }
        while (::Process32NextW(snapshot, &entry));
    }

    ::CloseHandle(snapshot);
    return found;
}

DebuggerCheck AntiDebug::Check(const AntiDebugOptions& options)
{
    DebuggerCheck result;

    if (options.checkDebugPort && HasDebugPort())
    {
        result.detected = true;
        result.method   = "ProcessDebugPort";
        return result;
    }

    if (options.checkDebugObjectHandle && HasDebugObjectHandle())
    {
        result.detected = true;
        result.method   = "ProcessDebugObjectHandle";
        return result;
    }

    if (options.checkDebugFlags && HasDebugFlags())
    {
        result.detected = true;
        result.method   = "ProcessDebugFlags";
        return result;
    }

    if (options.checkRemoteDebugger && HasRemoteDebugger())
    {
        result.detected = true;
        result.method   = "CheckRemoteDebuggerPresent";
        return result;
    }

    if (options.checkHardwareBreakpoints && HasHardwareBreakpoints())
    {
        result.detected = true;
        result.method   = "Hardware debug registers";
        return result;
    }

    if (options.checkDebuggerProcesses)
    {
        result.foundProcesses = FindDebuggerProcesses(options.debuggerNames);

        if (!result.foundProcesses.empty())
        {
            result.detected = true;
            result.method   = "Debugger process running";
            return result;
        }
    }

    return result;
}

void AntiDebug::Respond(const AntiDebugOptions& options, const DebuggerCheck& check)
{
    if (!check.detected)
    {
        return;
    }

    util::Logger::Warn("AntiDebug: detected via " + check.method);

    switch (options.response)
    {
    case DebugResponse::Ignore:
        return;

    case DebugResponse::Dialog:
    {
        std::string text = options.dialogMessage;

        if (!check.foundProcesses.empty())
        {
            std::string list;

            for (const auto& name : check.foundProcesses)
            {
                if (!list.empty())
                {
                    list += ", ";
                }

                list += name;
            }

            text += "\n\nRunning: " + list;
        }

        ::MessageBoxA(nullptr, text.c_str(),
                      options.dialogTitle.c_str(),
                      MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        break;
    }

    case DebugResponse::Terminate:
        break;
    }

    ::ExitProcess(options.exitCode);
}

const char* AntiDebug::ResponseName(DebugResponse response)
{
    switch (response)
    {
    case DebugResponse::Ignore:     return "Ignore";
    case DebugResponse::Dialog: return "Dialog";
    case DebugResponse::Terminate:  return "Terminate";
    default:                        return "Unknown";
    }
}
}
