#include "lattic/mcp/McpServer.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cstring>
#include <ctime>

#include "lattic/core/PeParser.hpp"
#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

namespace lattic::mcp
{
namespace
{
using util::Json;

constexpr std::size_t kMaxBodyBytes  = 1u << 20;
constexpr std::size_t kMaxLogLines   = 500;
constexpr const char* kProtocolName  = "lattic";
constexpr const char* kProtocolVer   = "2024-11-05";

Json Tool(const char* type, const std::string& value)
{
    Json object = Json::Object();
    object.Set("type", Json::From(type));
    object.Set("text", Json::From(value));
    return object;
}

std::string Timestamp()
{
    const std::time_t now = std::time(nullptr);
    std::tm parts = {};
    ::localtime_s(&parts, &now);

    char buffer[16] = {};
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &parts);
    return std::string(buffer);
}

// Accepts decimal or 0x prefixed hex. Junk in, zero out.
std::uint64_t ParseAddress(const std::string& text)
{
    if (text.empty())
    {
        return 0;
    }

    const int base = (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
                         ? 16
                         : 10;

    return std::strtoull(text.c_str(), nullptr, base);
}

std::string Str(const Json& object, const char* key, const std::string& fallback = {})
{
    const Json* value = object.Find(key);
    return value != nullptr ? value->AsString() : fallback;
}

std::int64_t Int(const Json& object, const char* key, std::int64_t fallback = 0)
{
    const Json* value = object.Find(key);
    return value != nullptr ? value->AsInt() : fallback;
}

bool Bool(const Json& object, const char* key, bool fallback = false)
{
    const Json* value = object.Find(key);
    return value != nullptr ? value->AsBool() : fallback;
}

Json Schema(const std::vector<std::pair<std::string, std::string>>& properties,
            const std::vector<std::string>& required)
{
    Json props = Json::Object();

    for (const auto& property : properties)
    {
        Json entry = Json::Object();
        entry.Set("type", Json::From("string"));
        entry.Set("description", Json::From(property.second));
        props.Set(property.first, std::move(entry));
    }

    Json list = Json::Array();
    for (const auto& name : required)
    {
        list.Push(Json::From(name));
    }

    Json schema = Json::Object();
    schema.Set("type", Json::From("object"));
    schema.Set("properties", std::move(props));
    schema.Set("required", std::move(list));
    return schema;
}
}

McpServer::McpServer()
{
    RegisterTools();
}

McpServer::~McpServer()
{
    Stop();
}

void McpServer::Attach(Lattic* core)
{
    m_core = core;
}

void McpServer::RegisterTools()
{
    const auto add = [this](const char* name, const char* description, Json schema)
    {
        m_tools.push_back(ToolEntry{ name, description, std::move(schema) });
    };

    add("lattic_status", "Report whether a binary is loaded, its section count, the number "
                         "of string candidates and how many patches are staged.",
        Schema({}, {}));

    add("lattic_load", "Load an EXE or DLL by absolute path. Replaces anything already loaded.",
        Schema({ { "path", "Absolute path to the PE file to load." } }, { "path" }));

    add("lattic_sections", "List the sections of the loaded image with their RVA, virtual "
                           "and raw size, and permission flags.",
        Schema({}, {}));

    add("lattic_imports", "List the imported DLLs and function names of the loaded image.",
        Schema({}, {}));

    add("lattic_exports", "List the exported names of the loaded image.",
        Schema({}, {}));

    add("lattic_strings", "List string candidates found in the loaded image.",
        Schema({ { "filter", "Case insensitive substring filter on the string text." },
                 { "offset", "Index of the first candidate to return." },
                 { "limit", "Maximum number of candidates to return." } },
               {}));

    add("lattic_rescan_strings", "Re-run the string scanner with a new minimum length.",
        Schema({ { "minLength", "Minimum characters for a run to count as a string." } }, {}));

    add("lattic_read_bytes", "Read raw bytes from the loaded image at a virtual address.",
        Schema({ { "va", "Virtual address, decimal or 0x prefixed hex." },
                 { "length", "How many bytes to read." } },
               { "va" }));

    add("lattic_stage_patch", "Stage a byte write at a virtual address. Nothing is written "
                              "until lattic_patch_and_save runs.",
        Schema({ { "va", "Virtual address to patch." },
                 { "bytes", "Hex bytes to write, for example DE AD BE EF." } },
               { "va", "bytes" }));

    add("lattic_staged_patches", "List the staged patch regions and their bytes.",
        Schema({}, {}));

    add("lattic_unstage_patch", "Drop one staged region by virtual address.",
        Schema({ { "va", "Virtual address of the staged region to drop." } }, { "va" }));

    add("lattic_encrypt_strings", "Encrypt the selected string candidates in memory. The "
                                    "image gains a .lattic section and its entry point is "
                                    "redirected to a decryptor runtime. Nothing is written "
                                    "to disk until lattic_patch_and_save runs.",
        Schema({ { "rvas", "Virtual addresses to encrypt. Omit to encrypt every candidate." } },
               {}));

    add("lattic_patch_and_save", "Apply the staged patches and options, then write the output "
                                 "file. A .bak copy is made when overwriting the input.",
        Schema({ { "outputPath", "Where to write. Omit to overwrite the loaded file." },
                 { "encryptStrings", "Encrypt the selected strings." },
                 { "stripDebugInfo", "Clear the debug directory and COFF symbol table." },
                 { "preserveChecksum", "Recompute the PE checksum." } },
               {}));
}

std::string McpServer::ToolListJson() const
{
    Json tools = Json::Array();

    for (const auto& tool : m_tools)
    {
        Json entry = Json::Object();
        entry.Set("name", Json::From(tool.name));
        entry.Set("description", Json::From(tool.description));
        entry.Set("inputSchema", tool.schema);
        tools.Push(std::move(entry));
    }

    return tools.Dump();
}

bool McpServer::IsRunning() const
{
    return m_running.load();
}

std::uint16_t McpServer::Port() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_port;
}

std::string McpServer::Url() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_running.load() ? "http://127.0.0.1:" + std::to_string(m_port) + "/mcp" : "";
}

std::string McpServer::LastError() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}

ServerStats McpServer::Stats() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

void McpServer::ClearLog()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_log.clear();
}

std::vector<LogLine> McpServer::RecentLog() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_log;
}

void McpServer::Log(const std::string& text, bool isError)
{
    LogLine line;
    line.time    = Timestamp();
    line.text    = text;
    line.isError = isError;

    std::lock_guard<std::mutex> lock(m_mutex);

    m_log.push_back(std::move(line));

    if (m_log.size() > kMaxLogLines)
    {
        m_log.erase(m_log.begin(),
                    m_log.begin() + static_cast<std::ptrdiff_t>(m_log.size() - kMaxLogLines));
    }

    if (isError)
    {
        util::Logger::Error("MCP: " + text);
    }
    else
    {
        util::Logger::Info("MCP: " + text);
    }
}

bool McpServer::Start(std::uint16_t port)
{
    if (m_running.load())
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = "The server is already running";
        return false;
    }

    if (m_core == nullptr)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = "No core attached";
        return false;
    }

    WSADATA wsa = {};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = "WSAStartup failed";
        return false;
    }

    const SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (listener == INVALID_SOCKET)
    {
        ::WSACleanup();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = "socket failed";
        return false;
    }

    // Loopback only. Binding INADDR_ANY would expose the tool to the whole network.
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port   = ::htons(port);
    address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);

    if (::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
    {
        ::closesocket(listener);
        ::WSACleanup();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = "Port " + std::to_string(port) + " is already in use";
        return false;
    }

    if (::listen(listener, 16) != 0)
    {
        ::closesocket(listener);
        ::WSACleanup();
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastError = "listen failed";
        return false;
    }

    sockaddr_in bound = {};
    int         boundLength = sizeof(bound);

    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &boundLength) == 0)
    {
        m_port = ::ntohs(bound.sin_port);
    }
    else
    {
        m_port = port;
    }

    m_listen    = static_cast<std::uintptr_t>(listener);
    m_stopping  = false;
    m_running   = true;
    m_lastError.clear();

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats = ServerStats();
    }

    m_thread = std::thread(&McpServer::Run, this);

    Log("Listening on http://127.0.0.1:" + std::to_string(m_port) + "/mcp");
    return true;
}

void McpServer::Stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    m_stopping = true;

    // Closing the listening socket is what unblocks accept().
    if (m_listen != static_cast<std::uintptr_t>(-1))
    {
        ::closesocket(static_cast<SOCKET>(m_listen));
        m_listen = static_cast<std::uintptr_t>(-1);
    }

    if (m_thread.joinable())
    {
        m_thread.join();
    }

    ::WSACleanup();
    Log("Stopped");
}

void McpServer::Run()
{
    while (!m_stopping.load())
    {
        const SOCKET listener = static_cast<SOCKET>(m_listen);

        if (listener == INVALID_SOCKET)
        {
            break;
        }

        sockaddr_in remote = {};
        int         remoteLength = sizeof(remote);

        const SOCKET client = ::accept(listener, reinterpret_cast<sockaddr*>(&remote),
                                       &remoteLength);

        if (client == INVALID_SOCKET)
        {
            if (m_stopping.load())
            {
                break;
            }

            continue;
        }

        char address[64] = {};
        ::inet_ntop(AF_INET, &remote.sin_addr, address, sizeof(address));

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_stats.connections;
        }

        ServeConnection(static_cast<std::uintptr_t>(client));
        Log(std::string("Connection from ") + address);
    }
}

void McpServer::ServeConnection(std::uintptr_t handle)
{
    const SOCKET client = static_cast<SOCKET>(handle);

    std::string request;
    char        buffer[4096];

    // Read until the headers are complete, then whatever body prefix follows.
    std::size_t contentLength = 0;
    bool        headersDone   = false;

    while (request.size() < kMaxBodyBytes)
    {
        const int received = ::recv(client, buffer, sizeof(buffer), 0);

        if (received <= 0)
        {
            break;
        }

        request.append(buffer, static_cast<std::size_t>(received));

        if (!headersDone)
        {
            const std::size_t split = request.find("\r\n\r\n");

            if (split == std::string::npos)
            {
                continue;
            }

            const std::string        head = request.substr(0, split);
            const std::string lowered = util::str::ToLower(head);

            const std::size_t pos = lowered.find("content-length:");

            if (pos != std::string::npos)
            {
                const unsigned long long claimed =
                    std::strtoull(head.c_str() + pos + 15, nullptr, 10);

                // Clamp on parse. The loop guard only bounds the buffer, so an unclamped
                // value here would let a local caller ask for an unbounded allocation.
                if (claimed > kMaxBodyBytes)
                {
                    Log("Rejected request with Content-Length " +
                        std::to_string(claimed) + ", limit is " +
                        std::to_string(kMaxBodyBytes), true);

                    const std::string tooLarge =
                        "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n"
                        "Connection: close\r\n\r\n";

                    ::send(client, tooLarge.data(), static_cast<int>(tooLarge.size()), 0);
                    ::shutdown(client, SD_SEND);
                    ::closesocket(client);
                    return;
                }

                contentLength = static_cast<std::size_t>(claimed);
            }

            headersDone = true;

            // Drop the headers, keep the body prefix.
            request.erase(0, split + 4);
        }

        if (headersDone && request.size() >= contentLength)
        {
            break;
        }
    }

    if (!headersDone)
    {
        // The peer sent no complete header block. Passing the raw header text to the JSON
        // parser just produces a confusing parse error, so reject it explicitly.
        const std::string bad = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                                "Connection: close\r\n\r\n";

        ::send(client, bad.data(), static_cast<int>(bad.size()), 0);
        ::shutdown(client, SD_SEND);
        ::closesocket(client);
        return;
    }

    const std::string response = HandleMessage(request, "local");

    if (!response.empty())
    {
        std::string head = "HTTP/1.1 200 OK\r\n";
        head += "Content-Type: application/json\r\n";
        head += "Content-Length: " + std::to_string(response.size()) + "\r\n";
        head += "Connection: close\r\n\r\n";
        head += response;

        // Send before closing. The socket must still be open here: closing first makes
        // every reply go to a dead handle and the endpoint silently never answers.
        const int sent = ::send(client, head.data(), static_cast<int>(head.size()), 0);

        if (sent != static_cast<int>(head.size()))
        {
            Log("Send failed with " + std::to_string(::WSAGetLastError()), true);
        }
    }

    ::shutdown(client, SD_SEND);
    ::closesocket(client);
}

std::string McpServer::HandleMessage(const std::string& body, const std::string& client)
{
    Json request;
    std::string error;

    if (!Json::Parse(body, request, error))
    {
        Log("Malformed request from " + client + ": " + error, true);

        Json response = Json::Object();
        response.Set("jsonrpc", Json::From("2.0"));
        response.Set("id", Json::Null());

        Json failure = Json::Object();
        failure.Set("code", Json::From(-32700));
        failure.Set("message", Json::From("Parse error: " + error));
        response.Set("error", std::move(failure));

        return response.Dump();
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_stats.requests;
    }

    bool isNotification = false;
    const std::string response = Dispatch(request, isNotification);

    if (!isNotification)
    {
        Log(std::string("Request: ") + Str(request, "method", "?") + " -> " +
            std::to_string(response.size()) + " bytes");
    }

    return response;
}

Json McpServer::ToolResult(const std::string& text, bool isError) const
{
    Json content = Json::Array();
    content.Push(Tool("text", text));

    Json result = Json::Object();
    result.Set("content", std::move(content));
    result.Set("isError", Json::From(isError));
    return result;
}

Json McpServer::ToolError(const std::string& text) const
{
    return ToolResult(text, true);
}

std::string McpServer::Dispatch(const Json& request, bool& isNotification)
{
    const std::string method = Str(request, "method");
    const Json*       id     = request.Find("id");

    isNotification = (id == nullptr);

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.lastMethod = method;
    }

    auto makeResponse = [&id](const Json& result) -> std::string
    {
        Json response = Json::Object();
        response.Set("jsonrpc", Json::From("2.0"));
        response.Set("id", id != nullptr ? *id : Json::Null());
        response.Set("result", result);
        return response.Dump();
    };

    auto makeError = [&id](int code, const std::string& message) -> std::string
    {
        Json failure = Json::Object();
        failure.Set("code", Json::From(code));
        failure.Set("message", Json::From(message));

        Json response = Json::Object();
        response.Set("jsonrpc", Json::From("2.0"));
        response.Set("id", id != nullptr ? *id : Json::Null());
        response.Set("error", std::move(failure));
        return response.Dump();
    };

    if (method == "initialize")
    {
        Json info = Json::Object();
        info.Set("name", Json::From(kProtocolName));
        info.Set("version", Json::From(Lattic::Version()));

        Json tools = Json::Object();
        tools.Set("listChanged", Json::From(false));

        Json capabilities = Json::Object();
        capabilities.Set("tools", std::move(tools));

        Json result = Json::Object();
        result.Set("protocolVersion", Json::From(kProtocolVer));
        result.Set("capabilities", std::move(capabilities));
        result.Set("serverInfo", std::move(info));
        return makeResponse(result);
    }

    if (method == "tools/list")
    {
        Json result = Json::Object();
        result.Set("tools", Json::Null());

        Json list = Json::Array();

        for (const auto& tool : m_tools)
        {
            Json entry = Json::Object();
            entry.Set("name", Json::From(tool.name));
            entry.Set("description", Json::From(tool.description));
            entry.Set("inputSchema", tool.schema);
            list.Push(std::move(entry));
        }

        result.Set("tools", std::move(list));
        return makeResponse(result);
    }

    if (method == "tools/call")
    {
        const Json* params = request.Find("params");
        const Json* name   = params != nullptr ? params->Find("name") : nullptr;
        const Json* args   = params != nullptr ? params->Find("arguments") : nullptr;

        if (name == nullptr)
        {
            return makeError(-32602, "params.name is required");
        }

        const Json empty = Json::Object();

        // An unknown tool name is a protocol error rather than a tool execution error, so
        // a client can tell "there is no such tool" from "the tool ran and failed".
        if (!HasTool(name->AsString()))
        {
            return makeError(-32602, "Unknown tool: " + name->AsString());
        }

        bool failed = false;
        const Json result = CallTool(name->AsString(),
                                     args != nullptr ? *args : empty, failed);

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_stats.toolCalls;

            if (failed)
            {
                ++m_stats.errors;
            }
        }

        return makeResponse(result);
    }

    if (method == "ping")
    {
        return makeResponse(Json::Object());
    }

    // notifications/initialized and any other notification is accepted silently, with no
    // reply. Answering one would desynchronise a client that is not expecting a body.
    if (isNotification)
    {
        return {};
    }

    return makeError(-32601, "Unknown method: " + method);
}

bool McpServer::HasTool(const std::string& name) const
{
    for (const auto& tool : m_tools)
    {
        if (tool.name == name)
        {
            return true;
        }
    }

    return false;
}

Json McpServer::CallTool(const std::string& name, const Json& arguments, bool& failed)
{
    failed = false;

    if (m_core == nullptr)
    {
        failed = true;
        return ToolError("No core attached to the server");
    }

    const bool needsImage = name != "lattic_load" && name != "lattic_status";

    if (needsImage && !m_core->IsLoaded())
    {
        failed = true;
        return ToolError("No binary loaded. Call lattic_load first.");
    }

    if (name == "lattic_status")
    {
        Json result = Json::Object();
        result.Set("loaded", Json::From(m_core->IsLoaded()));

        if (m_core->IsLoaded())
        {
            result.Set("path", Json::From(m_core->LoadedPath()));
            result.Set("stringCandidates", Json::From(static_cast<std::int64_t>(m_core->StringCandidateCount())));
            result.Set("selectedStrings", Json::From(static_cast<std::int64_t>(m_core->SelectedStrings().size())));
            result.Set("stagedPatches", Json::From(static_cast<std::int64_t>(m_core->StagedPatchCount())));
        }

        return ToolResult(result.Dump(true), false);
    }

    if (name == "lattic_load")
    {
        const std::string path = Str(arguments, "path");

        if (path.empty())
        {
            failed = true;
            return ToolError("path is required");
        }

        if (!m_core->LoadBinary(path))
        {
            failed = true;
            return ToolError(m_core->LastError());
        }

        Json result = Json::Object();
        result.Set("path", Json::From(m_core->LoadedPath()));
        result.Set("stringCandidates", Json::From(static_cast<std::int64_t>(m_core->StringCandidateCount())));
        return ToolResult(result.Dump(true), false);
    }

    if (name == "lattic_sections")
    {
        Json list = Json::Array();

        for (const auto& section : m_core->Sections())
        {
            Json entry = Json::Object();
            entry.Set("name", Json::From(section.name));
            entry.Set("rva", Json::From(util::str::FormatVA(section.rva)));
            entry.Set("virtualSize", Json::From(static_cast<std::int64_t>(section.virtualSize)));
            entry.Set("rawOffset", Json::From(static_cast<std::int64_t>(section.rawOffset)));
            entry.Set("rawSize", Json::From(static_cast<std::int64_t>(section.rawSize)));
            entry.Set("readable", Json::From(section.Readable()));
            entry.Set("writable", Json::From(section.Writable()));
            entry.Set("executable", Json::From(section.Executable()));
            list.Push(std::move(entry));
        }

        return ToolResult(list.Dump(true), false);
    }

    if (name == "lattic_imports")
    {
        Json list = Json::Array();

        for (const auto& import : m_core->Imports())
        {
            Json entry = Json::Object();
            entry.Set("dll", Json::From(import.dllName));

            Json functions = Json::Array();
            for (const auto& fn : import.functions)
            {
                functions.Push(Json::From(fn));
            }

            entry.Set("functions", std::move(functions));
            list.Push(std::move(entry));
        }

        return ToolResult(list.Dump(true), false);
    }

    if (name == "lattic_exports")
    {
        Json list = Json::Array();

        for (const auto& entry : m_core->Exports())
        {
            Json item = Json::Object();
            item.Set("name", Json::From(entry.name));
            item.Set("ordinal", Json::From(static_cast<std::int64_t>(entry.ordinal)));
            item.Set("rva", Json::From(util::str::FormatVA(entry.rva)));
            list.Push(std::move(item));
        }

        return ToolResult(list.Dump(true), false);
    }

    if (name == "lattic_strings")
    {
        const std::string filter = Str(arguments, "filter");
        const std::int64_t offset = Int(arguments, "offset", 0);
        std::int64_t       limit  = Int(arguments, "limit", 100);

        if (limit <= 0 || limit > 5000)
        {
            limit = 100;
        }

        const auto&       candidates = m_core->StringCandidates();
        const std::string lowered    = util::str::ToLower(filter);

        Json list = Json::Array();
        std::int64_t seen = 0;

        for (const auto& info : candidates)
        {
            if (!lowered.empty() &&
                util::str::ToLower(info.preview).find(lowered) == std::string::npos)
            {
                continue;
            }

            if (seen++ < offset)
            {
                continue;
            }

            if (static_cast<std::int64_t>(list.Items().size()) >= limit)
            {
                break;
            }

            Json entry = Json::Object();
            entry.Set("rva", Json::From(util::str::FormatVA(info.rva)));
            entry.Set("section", Json::From(info.section));
            entry.Set("length", Json::From(static_cast<std::int64_t>(info.byteLength)));
            entry.Set("utf16", Json::From(info.utf16));
            entry.Set("text", Json::From(info.preview));
            list.Push(std::move(entry));
        }

        Json result = Json::Object();
        result.Set("totalCandidates", Json::From(static_cast<std::int64_t>(candidates.size())));
        result.Set("returned", Json::From(static_cast<std::int64_t>(list.Items().size())));
        result.Set("strings", std::move(list));

        return ToolResult(result.Dump(true), false);
    }

    if (name == "lattic_read_bytes")
    {
        const std::uint64_t va     = ParseAddress(Str(arguments, "va"));
        const std::size_t   length = static_cast<std::size_t>(Int(arguments, "length", 16));

        if (length == 0 || length > 4096)
        {
            failed = true;
            return ToolError("length must be between 1 and 4096");
        }

        std::vector<std::uint8_t> bytes;

        if (!m_core->ReadAt(va, length, bytes))
        {
            failed = true;
            return ToolError("Address is not mapped or the read runs past the image");
        }

        Json result = Json::Object();
        result.Set("va", Json::From(util::str::FormatVA(va)));
        result.Set("length", Json::From(static_cast<std::int64_t>(bytes.size())));
        result.Set("hex", Json::From(util::str::BytesToHex(bytes)));

        return ToolResult(result.Dump(true), false);
    }

    if (name == "lattic_stage_patch")
    {
        const std::uint64_t va = ParseAddress(Str(arguments, "va"));

        std::vector<std::uint8_t> bytes;

        if (!util::str::HexToBytes(Str(arguments, "bytes"), bytes) || bytes.empty())
        {
            failed = true;
            return ToolError("bytes must be non empty hex, for example DE AD BE EF");
        }

        if (!m_core->StagePatch(va, bytes))
        {
            failed = true;
            return ToolError(m_core->LastError());
        }

        Json result = Json::Object();
        result.Set("va", Json::From(util::str::FormatVA(va)));
        result.Set("staged", Json::From(static_cast<std::int64_t>(m_core->StagedPatchCount())));
        return ToolResult(result.Dump(true), false);
    }

    if (name == "lattic_staged_patches")
    {
        Json list = Json::Array();

        for (const auto& patch : m_core->StagedPatches())
        {
            Json entry = Json::Object();
            entry.Set("va", Json::From(util::str::FormatVA(patch.va)));
            entry.Set("section", Json::From(patch.section));
            entry.Set("length", Json::From(static_cast<std::int64_t>(patch.length)));
            entry.Set("bytes", Json::From(patch.preview));
            list.Push(std::move(entry));
        }

        return ToolResult(list.Dump(true), false);
    }

    if (name == "lattic_unstage_patch")
    {
        const std::uint64_t va = ParseAddress(Str(arguments, "va"));

        if (!m_core->UnstagePatch(va))
        {
            failed = true;
            return ToolError(m_core->LastError());
        }

        return ToolResult("Removed staged region at " + util::str::FormatVA(va), false);
    }

    if (name == "lattic_rescan_strings")
    {
        const std::size_t minLength = static_cast<std::size_t>(Int(arguments, "minLength", 6));
        const std::size_t count     = m_core->RescanStrings(minLength, 4096);

        if (!m_core->LastError().empty())
        {
            failed = true;
            return ToolError(m_core->LastError());
        }

        Json result = Json::Object();
        result.Set("candidates", Json::From(count));
        return ToolResult(result.Dump(true), false);
    }

    if (name == "lattic_encrypt_strings")
    {
        std::vector<std::uint32_t> rvas;

        const Json* list = arguments.Find("rvas");

        if (list != nullptr)
        {
            for (const auto& item : list->Items())
            {
                rvas.push_back(static_cast<std::uint32_t>(item.AsInt()));
            }
        }

        if (!m_core->SelectStrings(rvas))
        {
            failed = true;
            return ToolError(m_core->LastError());
        }

        return ToolResult("Selected " + std::to_string(rvas.size()) +
                              " string(s) for encryption. Run lattic_patch_and_save with "
                              "encryptStrings to apply it.",
                          false);
    }

    if (name == "lattic_patch_and_save")
    {
        PatchOptions options;
        options.encryptStrings   = Bool(arguments, "encryptStrings");
        options.stripDebugInfo   = Bool(arguments, "stripDebugInfo");
        options.backupOnSave     = true;
        options.preserveChecksum = Bool(arguments, "preserveChecksum", true);

        const PatchResult result =
            m_core->ApplyAndSave(Str(arguments, "outputPath"), options);

        if (!result.success)
        {
            failed = true;
            return ToolError(result.message.empty() ? m_core->LastError() : result.message);
        }

        Json payload = Json::Object();
        payload.Set("message", Json::From(result.message));
        payload.Set("bytesWritten", Json::From(static_cast<std::int64_t>(result.bytesWritten)));
        payload.Set("patchesApplied", Json::From(static_cast<std::int64_t>(result.patchesApplied)));
        payload.Set("stringsEncrypted", Json::From(static_cast<std::int64_t>(result.stringsEncrypted)));
        return ToolResult(payload.Dump(true), false);
    }

    failed = true;
    return ToolError("Unknown tool: " + name);
}
}