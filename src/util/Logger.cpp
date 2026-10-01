#include "lattic/util/Logger.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <mutex>

namespace lattic::util
{
namespace
{
constexpr std::size_t kRingCapacity = 2000;

std::mutex     g_mutex;
std::ofstream  g_file;
std::vector<LogEntry> g_recent;

std::string TimeStamp()
{
    const auto         now = std::chrono::system_clock::now();
    const std::time_t   t   = std::chrono::system_clock::to_time_t(now);

    std::tm parts = {};
    ::localtime_s(&parts, &t);

    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &parts);
    return std::string(buffer);
}

void Write(const char* level, const std::string& message)
{
    const std::string line = "[" + TimeStamp() + "] [" + level + "] " + message;

    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_file.is_open())
    {
        g_file << line << '\n';
        g_file.flush();
    }

    g_recent.push_back(LogEntry{ level, line });

    if (g_recent.size() > kRingCapacity)
    {
        g_recent.erase(g_recent.begin(),
                       g_recent.begin() +
                           static_cast<std::vector<LogEntry>::difference_type>(
                               g_recent.size() - kRingCapacity));
    }
}
}

void Logger::Init(const std::string& filePath)
{
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_file.is_open())
    {
        g_file.close();
    }

    if (filePath.empty())
    {
        return;
    }

    g_file.open(filePath, std::ios::out | std::ios::app);
}

void Logger::Shutdown()
{
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_file.is_open())
    {
        g_file.flush();
        g_file.close();
    }
}

void Logger::Info(const std::string& message)
{
    Write("INFO", message);
}

void Logger::Warn(const std::string& message)
{
    Write("WARN", message);
}

void Logger::Error(const std::string& message)
{
    Write("ERR ", message);
}

std::vector<LogEntry> Logger::Recent()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_recent;
}

void Logger::ClearRecent()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_recent.clear();
}
}
