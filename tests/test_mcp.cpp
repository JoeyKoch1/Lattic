#include "TestFramework.hpp"

#include "lattic/mcp/McpServer.hpp"

#include "PeFixture.hpp"

#include <string>

using lattic::Lattic;
using lattic::mcp::McpServer;
using lattic::util::Json;

namespace
{
Json ParseOrNull(const std::string& text, std::string& error)
{
    Json value;
    if (!Json::Parse(text, value, error))
    {
        return Json::Null();
    }

    return value;
}

std::string Handle(const std::string& body)
{
    McpServer server;
    return server.HandleMessage(body, "test");
}
}

LATTIC_TEST(Mcp, InitializeReturnsProtocolAndServerInfo)
{
    std::string error;
    const Json response = ParseOrNull(Handle(R"({"jsonrpc":"2.0","id":1,"method":"initialize"})"), error);

    CHECK(error.empty());
    CHECK(response.GetType() == Json::Type::Object);
    CHECK_EQ(response.Find("jsonrpc")->AsString(), std::string("2.0"));
    CHECK_EQ(response.Find("id")->AsInt(), std::int64_t{ 1 });

    const Json* info = response.Find("result");
    CHECK(info != nullptr);

    // The client protocol version must be echoed so the handshake completes.
    CHECK(info->Find("protocolVersion") != nullptr);
    CHECK(info->Find("capabilities") != nullptr);
    CHECK_EQ(info->Find("serverInfo")->Find("name")->AsString(), std::string("lattic"));
}

LATTIC_TEST(Mcp, NotificationsGetNoReply)
{
    McpServer server;

    // A notification carries no id, so replying at all would confuse a strict client.
    CHECK(server.HandleMessage(R"({"jsonrpc":"2.0","method":"notifications/initialized"})",
                               "test").empty());
}

LATTIC_TEST(Mcp, UnknownMethodReturnsJsonRpcError)
{
    std::string error;
    const Json response = ParseOrNull(Handle(R"({"jsonrpc":"2.0","id":7,"method":"nope"})"), error);

    CHECK(error.empty());

    const Json* rpcError = response.Find("error");
    CHECK(rpcError != nullptr);
    CHECK(rpcError->Find("code") != nullptr);
    CHECK(rpcError->Find("message") != nullptr);
}

LATTIC_TEST(Mcp, MalformedJsonIsRejectedNotCrashed)
{
    McpServer server;

    // The server must answer a bad body rather than throwing out of the request thread.
    const std::string response = server.HandleMessage("{ this is not json", "test");
    CHECK(!response.empty());

    std::string error;
    const Json parsed = ParseOrNull(response, error);
    CHECK(error.empty());
    CHECK(parsed.Find("error") != nullptr);
}

LATTIC_TEST(Mcp, ToolsListDescribesEveryTool)
{
    McpServer server;

    std::string error;
    const Json parsed = ParseOrNull(server.ToolListJson(), error);

    CHECK(error.empty());
    CHECK(parsed.GetType() == Json::Type::Array);
    CHECK(!parsed.Items().empty());

    bool sawSections = false;
    bool sawStrings  = false;

    for (const auto& tool : parsed.Items())
    {
        CHECK(!tool.Find("name")->AsString().empty());
        CHECK(!tool.Find("description")->AsString().empty());
        CHECK(tool.Find("inputSchema") != nullptr);

        if (tool.Find("name")->AsString() == "lattic_sections")
        {
            sawSections = true;
        }

        if (tool.Find("name")->AsString() == "lattic_strings")
        {
            sawStrings = true;
        }
    }

    CHECK(sawSections);
    CHECK(sawStrings);
}

LATTIC_TEST(Mcp, ToolListJsonIsStableAcrossCalls)
{
    McpServer server;
    CHECK_EQ(server.ToolListJson(), server.ToolListJson());
}

LATTIC_TEST(Mcp, ToolCallWithoutCoreFailsCleanly)
{
    // No core is attached, so every tool must report an error instead of dereferencing null.
    std::string error;
    const Json response =
        ParseOrNull(Handle(R"({"jsonrpc":"2.0","id":2,"method":"tools/call",)"
                          R"("params":{"name":"lattic_sections","arguments":{}}})"),
                    error);

    CHECK(error.empty());

    const Json* result = response.Find("result");
    CHECK(result != nullptr);
    CHECK(result->Find("isError") != nullptr);
}

LATTIC_TEST(Mcp, ToolCallWithUnknownToolIsAnError)
{
    McpServer server;

    std::string error;
    const Json response =
        ParseOrNull(server.HandleMessage(R"({"jsonrpc":"2.0","id":3,"method":"tools/call",)"
                                         R"("params":{"name":"lattic_does_not_exist"}})",
                                         "test"),
                    error);

    CHECK(error.empty());
    CHECK(response.Find("error") != nullptr);
}

LATTIC_TEST(Mcp, SectionsToolDescribesAParsedImage)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_mcp_image.bin");

    lattic::Lattic core;
    CHECK(core.LoadBinary(path));
    CHECK(!path.empty());

    McpServer server;
    server.Attach(&core);

    std::string error;
    const Json response =
        ParseOrNull(server.HandleMessage(R"({"jsonrpc":"2.0","id":4,"method":"tools/call",)"
                                         R"("params":{"name":"lattic_sections","arguments":{}}})",
                                         "test"),
                    error);

    CHECK(error.empty());

    const Json* content = response.Find("result")->Find("content");
    CHECK(content != nullptr);
    CHECK_EQ(content->Items().size(), std::size_t{ 1 });
    CHECK_EQ(content->Items()[0].Find("type")->AsString(), std::string("text"));

    // The payload has to survive a round trip through JSON text.
    const Json sections = ParseOrNull(content->Items()[0].Find("text")->AsString(), error);

    CHECK(error.empty());
    CHECK(sections.GetType() == Json::Type::Array);
    CHECK(!sections.Items().empty());

    const Json& first = sections.Items()[0];
    CHECK(!first.Find("name")->AsString().empty());
    CHECK(first.Find("rva") != nullptr);
    CHECK(first.Find("virtualSize") != nullptr);
}

LATTIC_TEST(Mcp, ReadBytesToolValidatesLength)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_mcp_image.bin");
    CHECK(!path.empty());

    lattic::Lattic core;
    CHECK(core.LoadBinary(path));

    McpServer server;
    server.Attach(&core);

    // An unbounded read is exactly how a tool gets used to map the whole address space.
    std::string error;
    const Json response =
        ParseOrNull(server.HandleMessage(R"({"jsonrpc":"2.0","id":5,"method":"tools/call",)"
                                         R"("params":{"name":"lattic_read_bytes",)"
                                         R"("arguments":{"va":"0x140001000","length":999999}}})",
                                         "test"),
                    error);

    CHECK(error.empty());
    CHECK(response.Find("result")->Find("isError")->AsBool());
}

LATTIC_TEST(Mcp, ReadBytesToolRejectsUnmappedAddress)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_mcp_image.bin");
    CHECK(!path.empty());

    lattic::Lattic core;
    CHECK(core.LoadBinary(path));

    McpServer server;
    server.Attach(&core);

    std::string error;
    const Json response =
        ParseOrNull(server.HandleMessage(R"({"jsonrpc":"2.0","id":6,"method":"tools/call",)"
                                         R"("params":{"name":"lattic_read_bytes",)"
                                         R"("arguments":{"va":"0xdeadbeef0000","length":16}}})",
                                         "test"),
                    error);

    CHECK(error.empty());
    CHECK(response.Find("result")->Find("isError")->AsBool());
}

LATTIC_TEST(Mcp, StagePatchToolRejectsBadHex)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_mcp_image.bin");
    CHECK(!path.empty());

    lattic::Lattic core;
    CHECK(core.LoadBinary(path));

    McpServer server;
    server.Attach(&core);

    std::string error;
    const Json response =
        ParseOrNull(server.HandleMessage(R"({"jsonrpc":"2.0","id":7,"method":"tools/call",)"
                                         R"("params":{"name":"lattic_stage_patch",)"
                                         R"("arguments":{"va":"0x140001000","bytes":"ZZZZ"}}})",
                                         "test"),
                    error);

    CHECK(error.empty());
    CHECK(response.Find("result")->Find("isError")->AsBool());
}

LATTIC_TEST(Mcp, StatsAndLogTrackTraffic)
{
    McpServer server;

    server.HandleMessage(R"({"jsonrpc":"2.0","id":1,"method":"initialize"})", "127.0.0.1");

    const auto stats = server.Stats();
    CHECK(stats.requests > 0);
    CHECK_EQ(stats.lastMethod, std::string("initialize"));

    CHECK(!server.RecentLog().empty());

    server.ClearLog();
    CHECK(server.RecentLog().empty());
}

LATTIC_TEST(Mcp, PortDefaultsToLoopbackOnlyUrl)
{
    McpServer server;

    // Before anything is started there is no port to advertise.
    CHECK(!server.IsRunning());
    CHECK_EQ(server.Port(), std::uint16_t{ 0 });
    CHECK(server.Url().empty());
}
