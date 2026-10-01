#include "PeFixture.hpp"
#include "TestFramework.hpp"

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/StringScanner.hpp"

#include <cstdio>
#include <cstring>
#include <string>

using lattic::core::Binary;
using lattic::core::PeParser;
using lattic::core::StringEncoding;
using lattic::core::StringScanner;

// PutAscii copies the terminator as well, so these are the printable byte counts.
constexpr std::uint32_t kHelloLength = 16;
constexpr std::uint32_t kTextLength  = 17;
constexpr std::uint32_t kRvaLength   = 19;

// The fixture plants a 24 byte marker at .rdata+0, so test strings start clear of it.
constexpr std::size_t kStr = 0x40;

namespace
{
void PutAscii(lattic::test::PeImage& image, std::size_t rvaOffset, const char* text)
{
    std::memcpy(image.bytes.data() + image.rdataRawOff + rvaOffset, text, std::strlen(text) + 1);
}

void PutUtf16(lattic::test::PeImage& image, std::size_t rvaOffset, const wchar_t* text)
{
    std::size_t at = image.rdataRawOff + rvaOffset;

    for (const wchar_t* p = text; *p != L'\0'; ++p, at += 2)
    {
        image.bytes[at]     = static_cast<std::uint8_t>(*p & 0xFF);
        image.bytes[at + 1] = static_cast<std::uint8_t>((*p >> 8) & 0xFF);
    }

    image.bytes[at]     = 0;
    image.bytes[at + 1] = 0;
}
}

LATTIC_TEST(StringScanner, RejectsUnparsedImage)
{
    Binary binary;
    PeParser parser;
    StringScanner scanner;

    const auto report = scanner.Scan(binary, parser, lattic::core::ScanOptions{});

    CHECK(!report.success);
    CHECK(!report.message.empty());
    CHECK(!scanner.LastError().empty());
}

LATTIC_TEST(StringScanner, FindsAsciiStrings)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "HelloLatticWorld");

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_ascii.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.minLength = 6;

    const auto report = scanner.Scan(binary, parser, options);

    CHECK(report.success);
    CHECK(report.candidates > 0);

    const auto& candidates = scanner.Candidates();

    bool found = false;
    for (const auto& candidate : candidates)
    {
        if (candidate.section == ".rdata" && candidate.byteLength == kHelloLength &&
            candidate.encoding == StringEncoding::Ascii)
        {
            found = true;
        }
    }

    CHECK(found);

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, RespectsMinLength)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "abc");
    PutAscii(image, kStr + 0x10, "abcdefgh");

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_minlen.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.minLength    = 8;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);

    for (const auto& candidate : scanner.Candidates())
    {
        CHECK(candidate.byteLength >= 8);
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, RespectsMaxLength)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::string longRun(200, 'A');
    PutAscii(image, kStr, longRun.c_str());

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_maxlen.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.minLength    = 6;
    options.maxLength    = 32;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);

    for (const auto& candidate : scanner.Candidates())
    {
        CHECK(candidate.byteLength <= 32);
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, SkipsExecutableSectionsByDefault)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::memcpy(image.bytes.data() + image.textRawOff, "TextSectionString", kTextLength + 1);

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_exec.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);

    for (const auto& candidate : scanner.Candidates())
    {
        CHECK(candidate.section != ".text");
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, IncludesExecutableSectionsWhenAsked)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    std::memcpy(image.bytes.data() + image.textRawOff, "TextSectionString", kTextLength + 1);

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_exec2.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.includeUtf16            = false;
    options.includeExecutableSections = true;

    CHECK(scanner.Scan(binary, parser, options).success);

    bool inText = false;
    for (const auto& candidate : scanner.Candidates())
    {
        if (candidate.section == ".text")
        {
            inText = true;
        }
    }

    CHECK(inText);

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, SkipsImportDirectory)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    // Point the import directory at a run of bytes inside .rdata, then plant a string
    // there. The scanner must not report it because the loader reads that region first.
    const std::uint32_t importRva = image.rdataRva + 0x80;

    const std::size_t lfanew = image.bytes[0x3C] | (image.bytes[0x3D] << 8) |
                               (image.bytes[0x3E] << 16) |
                               (static_cast<std::size_t>(image.bytes[0x3F]) << 24);

    const std::size_t opt = lfanew + 4 + 20;

    lattic::test::PutU32(image.bytes, opt + 112 + 1 * 8, importRva);
    lattic::test::PutU32(image.bytes, opt + 112 + 1 * 8 + 4, 0x40u);

    PutAscii(image, 0x80, "ProtectedImportString");

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_import.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.includeUtf16 = false;

    const auto report = scanner.Scan(binary, parser, options);

    CHECK(report.success);
    CHECK(report.skippedProtected > 0);

    for (const auto& candidate : scanner.Candidates())
    {
        CHECK(candidate.rva < importRva || candidate.rva >= importRva + 0x40);
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, SkipsExportDirectory)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    const std::uint32_t exportRva = image.rdataRva + 0x80;

    const std::size_t lfanew = image.bytes[0x3C] | (image.bytes[0x3D] << 8) |
                               (image.bytes[0x3E] << 16) |
                               (static_cast<std::size_t>(image.bytes[0x3F]) << 24);

    const std::size_t opt = lfanew + 4 + 20;

    lattic::test::PutU32(image.bytes, opt + 112 + 0 * 8, exportRva);
    lattic::test::PutU32(image.bytes, opt + 112 + 0 * 8 + 4, 0x40u);

    PutAscii(image, 0x80, "ProtectedExportString");

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_export.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);

    for (const auto& candidate : scanner.Candidates())
    {
        CHECK(candidate.rva < exportRva || candidate.rva >= exportRva + 0x40);
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, FindsUtf16Strings)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutUtf16(image, kStr, L"UnicodeLatticMarker");

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_utf16.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.minLength    = 6;
    options.includeUtf16 = true;

    CHECK(scanner.Scan(binary, parser, options).success);

    bool found = false;
    for (const auto& candidate : scanner.Candidates())
    {
        if (candidate.encoding == StringEncoding::Utf16)
        {
            found = true;
            CHECK_EQ(candidate.byteLength % 2, std::uint32_t{ 0 });
        }
    }

    CHECK(found);

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, ReportsCorrectRva)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    const std::size_t rvaOffset = kStr;
    PutAscii(image, rvaOffset, "RvaCheckStringValue");
    CHECK_EQ(kRvaLength, std::uint32_t{ 19 });

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_rva.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);

    const std::uint32_t expectedRva = image.rdataRva + static_cast<std::uint32_t>(rvaOffset);

    bool found = false;
    for (const auto& candidate : scanner.Candidates())
    {
        if (candidate.rva == expectedRva)
        {
            found = true;
            CHECK_EQ(candidate.fileOffset, image.rdataRawOff + rvaOffset);
            CHECK_EQ(candidate.charLength, static_cast<std::uint16_t>(kRvaLength));
            CHECK(candidate.encoding == StringEncoding::Ascii);
        }
    }

    CHECK(found);

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, UnterminatedRunIsNotReported)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    // Printable bytes with no terminator, so no run ever ends.
    std::memset(image.bytes.data() + image.rdataRawOff, 'A', image.rdataRawSize);

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_unterminated.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.minLength    = 6;
    options.maxLength    = 4096;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);

    // The run reaches the section limit with no null, so nothing from it is a candidate.
    for (const auto& candidate : scanner.Candidates())
    {
        CHECK(candidate.section != ".rdata");
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringScanner, ClearResetsState)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "SomethingToFindHere");

    const std::string path = lattic::test::WriteTempFile(image, "test_scan_clear.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;

    lattic::core::ScanOptions options;
    options.includeUtf16 = false;

    CHECK(scanner.Scan(binary, parser, options).success);
    CHECK(!scanner.Candidates().empty());

    scanner.Clear();
    CHECK(scanner.Candidates().empty());

    std::remove(path.c_str());
}
