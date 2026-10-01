#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "lattic/Lattic.hpp"
#include "lattic/util/Json.hpp"

namespace lattic::mcp
{
struct ServerStats
{
    std::uint64_t requests    = 0;
    std::uint64_t toolCalls   = 0;
    std::uint64_t errors      = 0;
    std::uint64_t connections = 0;

    std::string lastMethod;
    std::string lastClient;
};

struct LogLine
{
    std::string time;
    std::string text;
    bool        isError = false;
};

// A local Model Context Protocol endpoint. It speaks JSON-RPC 2.0 over HTTP and binds to
// the loopback interface only, so nothing off this machine can reach the tool.
//
// Every tool routes through the Lattic facade, which keeps the same boundary the UI uses.
class McpServer
{
public:
    McpServer();
    ~McpServer();

    McpServer(const McpServer&)            = delete;
    McpServer& operator=(const McpServer&) = delete;

    // The server borrows the core and never outlives it, so the UI must stop the server
    // before tearing the facade down.
    void Attach(Lattic* core);

    bool Start(std::uint16_t port);
    void Stop();
    bool IsRunning() const;

    std::uint16_t Port() const;
    std::string   Url() const;
    std::string   LastError() const;

    ServerStats Stats() const;
    void        ClearLog();

    // Newest last, capped so a long session cannot grow without bound.
    std::vector<LogLine> RecentLog() const;

    // Exposed for tests: handles one JSON-RPC request and returns the response body. An
    // empty string means the request was a notification and needs no reply.
    std::string HandleMessage(const std::string& body, const std::string& client);

    std::string ToolListJson() const;
    bool        HasTool(const std::string& name) const;

private:
    void Run();
    void ServeConnection(std::uintptr_t client);
    void Log(const std::string& text, bool isError = false);

    std::string Dispatch(const util::Json& request, bool& isNotification);
    util::Json  CallTool(const std::string& name, const util::Json& arguments,
                         bool& failed);

    util::Json  ToolResult(const std::string& text, bool isError) const;
    util::Json  ToolError(const std::string& text) const;

    void RegisterTools();

    struct ToolEntry
    {
        std::string name;
        std::string description;
        util::Json  schema;
    };

    Lattic* m_core = nullptr;

    std::thread      m_thread;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_stopping{ false };

    std::uint16_t m_port    = 0;
    std::uintptr_t m_listen = static_cast<std::uintptr_t>(-1);
    std::string    m_lastError;

    std::vector<ToolEntry> m_tools;

    mutable std::mutex      m_mutex;
    ServerStats              m_stats;
    std::vector<LogLine>    m_log;
};
}
