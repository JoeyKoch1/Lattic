#include "TestFramework.hpp"

#include "lattic/util/StringUtil.hpp"

#include <string>
#include <vector>

namespace str = lattic::util::str;

LATTIC_TEST(StringUtil, ToLowerAndToUpper)
{
    CHECK_EQ(str::ToLower("HeLLo"), std::string("hello"));
    CHECK_EQ(str::ToUpper("HeLLo"), std::string("HELLO"));
    CHECK_EQ(str::ToLower(""), std::string(""));
    CHECK_EQ(str::ToLower("123-_."), std::string("123-_."));
}

LATTIC_TEST(StringUtil, Trim)
{
    CHECK_EQ(str::Trim("  padded  "), std::string("padded"));
    CHECK_EQ(str::TrimLeft("  padded  "), std::string("padded  "));
    CHECK_EQ(str::TrimRight("  padded  "), std::string("  padded"));
    CHECK_EQ(str::Trim("     "), std::string(""));
    CHECK_EQ(str::Trim("none"), std::string("none"));
    CHECK_EQ(str::Trim(""), std::string(""));
}

LATTIC_TEST(StringUtil, StartsAndEndsWith)
{
    CHECK(str::StartsWith("kernel32.dll", "kernel"));
    CHECK(!str::StartsWith("kernel32.dll", "KERNEL"));
    CHECK(str::StartsWith("abc", "abc"));
    CHECK(str::StartsWith("abc", ""));
    CHECK(!str::StartsWith("ab", "abc"));

    CHECK(str::EndsWith("kernel32.dll", ".dll"));
    CHECK(!str::EndsWith("kernel32.dll", ".DLL"));
    CHECK(str::EndsWith("abc", "abc"));
    CHECK(str::EndsWith("abc", ""));
    CHECK(!str::EndsWith("bc", "abc"));
}

LATTIC_TEST(StringUtil, SplitAndJoin)
{
    const auto parts = str::Split("a,b,,c", ',');

    CHECK_EQ(parts.size(), std::size_t{ 4 });
    CHECK_EQ(parts[0], std::string("a"));
    CHECK_EQ(parts[2], std::string(""));
    CHECK_EQ(parts[3], std::string("c"));

    CHECK_EQ(str::Join(parts, ","), std::string("a,b,,c"));
    CHECK_EQ(str::Join({}, ","), std::string(""));

    const auto single = str::Split("noseparator", ',');
    CHECK_EQ(single.size(), std::size_t{ 1 });
    CHECK_EQ(single[0], std::string("noseparator"));
}

LATTIC_TEST(StringUtil, HexRoundTrip)
{
    const std::vector<std::uint8_t> bytes = { 0xDE, 0xAD, 0xBE, 0xEF };

    CHECK_EQ(str::BytesToHex(bytes), std::string("DEADBEEF"));
    CHECK_EQ(str::BytesToHexSpaced(bytes), std::string("DE AD BE EF"));
    CHECK_EQ(str::BytesToHexSpaced({}), std::string(""));

    std::vector<std::uint8_t> decoded;
    CHECK(str::HexToBytes("DEADBEEF", decoded));
    CHECK(decoded == bytes);

    CHECK(str::HexToBytes("0xDEADBEEF", decoded));
    CHECK(decoded == bytes);

    CHECK(str::HexToBytes("de ad be ef", decoded));
    CHECK(decoded == bytes);
}

LATTIC_TEST(StringUtil, HexToBytesRejectsBadInput)
{
    std::vector<std::uint8_t> decoded = { 0xFF };

    CHECK(!str::HexToBytes("", decoded));
    CHECK(decoded.empty());

    CHECK(!str::HexToBytes("ABC", decoded));
    CHECK(!str::HexToBytes("ZZ", decoded));
    CHECK(!str::HexToBytes("0x", decoded));
    CHECK(decoded.empty());
}

LATTIC_TEST(StringUtil, FormatVA)
{
    CHECK_EQ(str::FormatVA(0x140001000), std::string("0x0000000140001000"));
    CHECK_EQ(str::FormatVA(0), std::string("0x0000000000000000"));
}

LATTIC_TEST(StringUtil, FormatBytes)
{
    CHECK_EQ(str::FormatBytes(0), std::string("0 B"));
    CHECK_EQ(str::FormatBytes(1023), std::string("1023 B"));
    CHECK_EQ(str::FormatBytes(1024), std::string("1.00 KB"));
    CHECK_EQ(str::FormatBytes(1024ull * 1024ull), std::string("1.00 MB"));
    CHECK_EQ(str::FormatBytes(1024ull * 1024ull * 1024ull), std::string("1.00 GB"));
}

LATTIC_TEST(StringUtil, PathHelpers)
{
    const std::string path = "C:\\tools\\sample.exe";

    CHECK_EQ(str::FileName(path), std::string("sample.exe"));
    CHECK_EQ(str::FileExtension(path), std::string(".exe"));
    CHECK_EQ(str::DirectoryOf(path), std::string("C:\\tools"));

    CHECK_EQ(str::FileName("noext"), std::string("noext"));
    CHECK_EQ(str::FileExtension("noext"), std::string(""));
    CHECK_EQ(str::DirectoryOf("noext"), std::string(""));

    // A dot in a directory name must not be mistaken for an extension.
    CHECK_EQ(str::FileExtension("C:\\dir.name\\file"), std::string(""));
}

LATTIC_TEST(StringUtil, Printable)
{
    CHECK_EQ(str::Printable("ok"), std::string("ok"));
    CHECK_EQ(str::Printable(std::string("a\tb\nc", 5)), std::string("a.b.c"));
    CHECK_EQ(str::Printable(std::string("\x01\x7F", 2)), std::string(".."));
}

LATTIC_TEST(StringUtil, Ellipsize)
{
    CHECK_EQ(str::Ellipsize("short", 10), std::string("short"));
    CHECK_EQ(str::Ellipsize("abcdefghij", 5), std::string("ab..."));
    CHECK_EQ(str::Ellipsize("abcdefghij", 3), std::string("abc"));
    CHECK_EQ(str::Ellipsize("abcdefghij", 2), std::string("ab"));
    CHECK_EQ(str::Ellipsize("abc", 3), std::string("abc"));
}

LATTIC_TEST(StringUtil, NarrowAndWiden)
{
    const std::string ascii = "Lattic";

    CHECK_EQ(str::Narrow(str::Widen(ascii)), ascii);
    CHECK(str::Widen("").empty());
    CHECK_EQ(str::Narrow(L"abc"), std::string("abc"));
}
