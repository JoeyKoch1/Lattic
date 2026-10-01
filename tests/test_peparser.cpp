#include "PeFixture.hpp"
#include "TestFramework.hpp"

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"

#include <cstdio>
#include <string>

using lattic::core::Binary;
using lattic::core::PeParser;

namespace
{
std::string Materialize(const lattic::test::PeImage& image, const std::string& name)
{
    const std::string path = lattic::test::WriteTempFile(image, name);
    return path;
}
}

LATTIC_TEST(PeParser, ParseRejectsEmptyBinary)
{
    Binary binary;
    PeParser parser;

    CHECK(!parser.Parse(binary));
    CHECK(!parser.IsParsed());
    CHECK(!parser.LastError().empty());
}

LATTIC_TEST(PeParser, ParseRejectsNonPe)
{
    std::vector<std::uint8_t> junk(512, 0x41);
    std::FILE* file = std::fopen("test_peparser_junk.bin", "wb");
    CHECK(file != nullptr);
    std::fwrite(junk.data(), 1, junk.size(), file);
    std::fclose(file);

    Binary binary;
    CHECK(binary.Load("test_peparser_junk.bin"));

    PeParser parser;
    CHECK(!parser.Parse(binary));
    CHECK(!parser.LastError().empty());

    std::remove("test_peparser_junk.bin");
}

LATTIC_TEST(PeParser, ParseRejectsTruncatedFile)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    image.bytes.resize(32);

    const std::string path = Materialize(image, "test_peparser_truncated.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(!parser.Parse(binary));

    std::remove(path.c_str());
}

LATTIC_TEST(PeParser, ParsesHeadersAndSections)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = Materialize(image, "test_peparser_ok.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));
    CHECK(parser.IsParsed());
    CHECK(parser.LastError().empty());

    CHECK(parser.Is64Bit());
    CHECK(parser.IsExe());
    CHECK(!parser.IsDll());
    CHECK_EQ(parser.ImageBase(), std::uint64_t{ image.imageBase });
    CHECK_EQ(parser.EntryPointRva(), image.entryRva);
    CHECK_EQ(parser.EntryPointVa(), std::uint64_t{ image.imageBase } + image.entryRva);
    CHECK_EQ(parser.NumberOfSections(), std::uint16_t{ 2 });
    CHECK_EQ(parser.SectionAlignment(), std::uint32_t{ 0x1000 });
    CHECK_EQ(parser.FileAlignment(), std::uint32_t{ 0x200 });
    CHECK_EQ(parser.Sections().size(), std::size_t{ 2 });

    const lattic::core::Section* text = parser.SectionByName(".text");
    CHECK(text != nullptr);
    CHECK(text->Executable());
    CHECK(!text->Writable());
    CHECK(text->Readable());
    CHECK(text->Contains(image.textRva));

    const lattic::core::Section* rdata = parser.SectionByName(".rdata");
    CHECK(rdata != nullptr);
    CHECK(rdata->Readable());
    CHECK(!rdata->Executable());

    std::remove(path.c_str());
}

LATTIC_TEST(PeParser, RvaAndVaConversions)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = Materialize(image, "test_peparser_convert.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    std::uint32_t offset = 0;
    CHECK(parser.RvaToOffset(image.textRva, offset));
    CHECK_EQ(offset, image.textRawOff);

    CHECK(parser.VaToOffset(image.TextVa(), offset));
    CHECK_EQ(offset, image.textRawOff);

    std::uint32_t rva = 0;
    CHECK(parser.OffsetToRva(image.textRawOff, rva));
    CHECK_EQ(rva, image.textRva);

    CHECK(parser.VaToOffset(0x10, offset) == false);
    CHECK(parser.RvaToOffset(0x9000, offset) == false);

    std::remove(path.c_str());
}

LATTIC_TEST(PeParser, CountsStringCandidates)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = Materialize(image, "test_peparser_strings.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));
    CHECK(parser.CandidateStringCount() > 0);

    std::remove(path.c_str());
}

LATTIC_TEST(PeParser, ResetClearsParsedState)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = Materialize(image, "test_peparser_reset.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    parser.Reset();
    CHECK(!parser.IsParsed());
    CHECK(parser.Sections().empty());
    CHECK_EQ(parser.CandidateStringCount(), std::size_t{ 0 });

    std::remove(path.c_str());
}

LATTIC_TEST(PeParser, DirectoryLookupIsBoundsChecked)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = Materialize(image, "test_peparser_dir.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    CHECK(parser.Directory(9999) == nullptr);
    CHECK_EQ(parser.Directories().size(), std::size_t{ 16 });

    const lattic::core::DataDirectory* debugDir = parser.Directory(6);
    CHECK(debugDir != nullptr);
    CHECK(debugDir->Present());

    std::remove(path.c_str());
}
