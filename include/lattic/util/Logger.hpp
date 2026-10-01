#pragma once

#include <string>
#include <vector>

namespace lattic::util
{
struct LogEntry
{
    std::string level;
    std::string message;
};

class Logger
{
public:
    static void Init(const std::string& filePath);
    static void Shutdown();

    static void Info(const std::string& message);
    static void Warn(const std::string& message);
    static void Error(const std::string& message);

    // Recent lines, newest last, capped at a fixed ring size so a long session cannot
    // grow without bound. Safe to call before Init. Returns a copy: the MCP thread writes
    // to the ring while the UI thread reads it, so exposing the live vector was a race.
    static std::vector<LogEntry> Recent();

    static void ClearRecent();
};
}
