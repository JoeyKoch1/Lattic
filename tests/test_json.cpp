#include "TestFramework.hpp"

#include "lattic/util/Json.hpp"

#include <string>

using lattic::util::Json;

LATTIC_TEST(Json, BuildsAndDumpsScalars)
{
    CHECK_EQ(Json::From(true).Dump(), std::string("true"));
    CHECK_EQ(Json::From(false).Dump(), std::string("false"));
    CHECK_EQ(Json::Null().Dump(), std::string("null"));
    CHECK_EQ(Json::From(42).Dump(), std::string("42"));
    CHECK_EQ(Json::From("hi").Dump(), std::string("\"hi\""));
}

LATTIC_TEST(Json, EscapesControlCharacters)
{
    CHECK_EQ(Json::From(std::string("a\nb")).Dump(), std::string("\"a\\nb\""));
    CHECK_EQ(Json::From(std::string("q\"q")).Dump(), std::string("\"q\\\"q\""));
    CHECK_EQ(Json::From(std::string("back\\slash")).Dump(),
             std::string("\"back\\\\slash\""));
    CHECK_EQ(Json::From(std::string("\x01")).Dump(), std::string("\"\\u0001\""));
}

LATTIC_TEST(Json, ObjectKeepsInsertionOrder)
{
    Json object = Json::Object();
    object.Set("zebra", Json::From(1));
    object.Set("alpha", Json::From(2));
    object.Set("middle", Json::From(3));

    CHECK_EQ(object.Dump(), std::string("{\"zebra\":1,\"alpha\":2,\"middle\":3}"));
    CHECK(object.Has("alpha"));
    CHECK(!object.Has("nope"));
    CHECK(object.Find("middle") != nullptr);
    CHECK_EQ(object.Find("middle")->AsInt(), std::int64_t{ 3 });
}

LATTIC_TEST(Json, SetReplacesAnExistingKey)
{
    Json object = Json::Object();
    object.Set("k", Json::From(1));
    object.Set("k", Json::From(2));

    CHECK_EQ(object.Dump(), std::string("{\"k\":2}"));
    CHECK_EQ(object.Members().size(), std::size_t{ 1 });
}

LATTIC_TEST(Json, ArraysPreserveOrder)
{
    Json array = Json::Array();
    array.Push(Json::From(1));
    array.Push(Json::From(std::string("two")));
    array.Push(Json::From(false));

    CHECK_EQ(array.Dump(), std::string("[1,\"two\",false]"));
    CHECK_EQ(array.Items().size(), std::size_t{ 3 });
}

LATTIC_TEST(Json, AccessorsAreTypeSafe)
{
    Json number = Json::From(7);
    Json text   = Json::From("hello");
    Json empty  = Json::Null();

    // Reading a number as a string yields its text form rather than throwing or garbage.
    CHECK_EQ(number.AsString(), std::string("7"));
    CHECK_EQ(text.AsNumber(), 0.0);
    CHECK_EQ(empty.AsInt(), std::int64_t{ 0 });
    CHECK(!empty.AsBool());
    CHECK(empty.IsNull());
    CHECK(text.GetType() == Json::Type::String);
}

LATTIC_TEST(Json, ParsesObjectsAndArrays)
{
    Json parsed;
    std::string error;

    const std::string source = R"({"a":1,"b":[true,null,"x"],"c":{"d":2.5}})";

    CHECK(Json::Parse(source, parsed, error));
    CHECK(error.empty());
    CHECK(parsed.GetType() == Json::Type::Object);
    CHECK_EQ(parsed.Find("a")->AsInt(), std::int64_t{ 1 });

    const Json* b = parsed.Find("b");
    CHECK(b != nullptr);
    CHECK_EQ(b->Items().size(), std::size_t{ 3 });
    CHECK(b->Items()[0].AsBool());
    CHECK(b->Items()[1].IsNull());
    CHECK_EQ(b->Items()[2].AsString(), std::string("x"));

    CHECK_EQ(parsed.Find("c")->Find("d")->AsNumber(), 2.5);
}

LATTIC_TEST(Json, ParsesEscapesAndUnicode)
{
    Json parsed;
    std::string error;

    CHECK(Json::Parse(R"({"s":"line\nbreak A"})", parsed, error));
    CHECK_EQ(parsed.Find("s")->AsString(), std::string("line\nbreak A"));

    // A surrogate pair must become the single code point it encodes.
    CHECK(Json::Parse(R"({"s":"😀"})", parsed, error));
    CHECK_EQ(parsed.Find("s")->AsString(), std::string("\xF0\x9F\x98\x80"));

    CHECK(Json::Parse(R"({"s":"é"})", parsed, error));
    CHECK_EQ(parsed.Find("s")->AsString(), std::string("\xC3\xA9"));
}

LATTIC_TEST(Json, ParsesEmptyContainers)
{
    Json parsed;
    std::string error;

    CHECK(Json::Parse("{}", parsed, error));
    CHECK_EQ(parsed.Members().size(), std::size_t{ 0 });

    CHECK(Json::Parse("[]", parsed, error));
    CHECK_EQ(parsed.Items().size(), std::size_t{ 0 });

    CHECK(Json::Parse(R"({"a":{},"b":[]})", parsed, error));
    CHECK_EQ(parsed.Find("a")->Members().size(), std::size_t{ 0 });
    CHECK_EQ(parsed.Find("b")->Items().size(), std::size_t{ 0 });
}

LATTIC_TEST(Json, RejectsMalformedInput)
{
    Json parsed;
    std::string error;

    CHECK(!Json::Parse("", parsed, error));
    CHECK(!error.empty());

    CHECK(!Json::Parse("{", parsed, error));
    CHECK(!Json::Parse("{\"a\":}", parsed, error));
    CHECK(!Json::Parse("{\"a\" 1}", parsed, error));
    CHECK(!Json::Parse("[1,]", parsed, error));
    CHECK(!Json::Parse("tru", parsed, error));
    CHECK(!Json::Parse("\"unterminated", parsed, error));
    CHECK(!Json::Parse("{} trailing", parsed, error));
    CHECK(!Json::Parse("01", parsed, error) == false);
}

LATTIC_TEST(Json, RejectsExcessiveNesting)
{
    std::string deep;
    for (int i = 0; i < 500; ++i)
    {
        deep += "[";
    }

    Json parsed;
    std::string error;

    // A hostile payload must not be able to exhaust the stack.
    CHECK(!Json::Parse(deep, parsed, error));
    CHECK(!error.empty());
}

LATTIC_TEST(Json, RoundTripsThroughDumpAndParse)
{
    Json original = Json::Object();
    original.Set("id", Json::From(1234));
    original.Set("text", Json::From("a \"quoted\" \\ value\nwith newline"));
    original.Set("flag", Json::From(true));

    Json nested = Json::Object();
    nested.Set("values", Json::Array());
    original.Set("nested", std::move(nested));

    Json reparsed;
    std::string error;

    CHECK(Json::Parse(original.Dump(), reparsed, error));
    CHECK_EQ(reparsed.Find("id")->AsInt(), std::int64_t{ 1234 });
    CHECK_EQ(reparsed.Find("text")->AsString(),
             std::string("a \"quoted\" \\ value\nwith newline"));
    CHECK(reparsed.Find("flag")->AsBool());
    CHECK(reparsed.Find("nested")->Find("values") != nullptr);
}

LATTIC_TEST(Json, PrettyDumpIsStillValidJson)
{
    Json object = Json::Object();
    object.Set("a", Json::From(1));
    object.Set("b", Json::Array());

    const std::string pretty = object.Dump(true);
    CHECK(pretty.find('\n') != std::string::npos);

    Json reparsed;
    std::string error;
    CHECK(Json::Parse(pretty, reparsed, error));
}
