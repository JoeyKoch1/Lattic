#include "PeFixture.hpp"
#include "TestFramework.hpp"

#include "lattic/core/Binary.hpp"
#include "lattic/core/Patcher.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/StringScanner.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using lattic::core::Binary;
using lattic::core::Patcher;
using lattic::core::PeParser;

LATTIC_TEST(Patcher, StageRejectsEmptyPayload)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_empty_payload.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    CHECK(!patcher.Stage(image.TextVa(), {}));
    CHECK(!patcher.LastError().empty());
    CHECK_EQ(patcher.StagedCount(), std::size_t{ 0 });

    std::remove(path.c_str());
}

LATTIC_TEST(Patcher, StageRejectsUnmappedVa)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_unmapped.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    CHECK(!patcher.Stage(0x10, { 0x90 }));
    CHECK(!patcher.LastError().empty());

    std::remove(path.c_str());
}

LATTIC_TEST(Patcher, StageRejectsRunPastEndOfFile)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_overrun.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    // Last mapped byte of .text plus one more than the section holds.
    const std::uint64_t lastByteVa = image.TextVa() + image.textRawSize - 1;
    const std::vector<std::uint8_t> tooLong(8, 0x90);

    Patcher patcher(binary, parser);
    CHECK(!patcher.Stage(lastByteVa, tooLong));

    std::remove(path.c_str());
}

LATTIC_TEST(Patcher, StagedPatchLandsAtExpectedOffset)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_stage.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    CHECK(patcher.Stage(image.TextVa(), { 0xDE, 0xAD, 0xBE, 0xEF }));
    CHECK_EQ(patcher.StagedCount(), std::size_t{ 1 });

    const auto& staged = patcher.Staged();
    CHECK_EQ(staged.size(), std::size_t{ 1 });
    CHECK_EQ(staged[0].offset, image.textRawOff);
    CHECK_EQ(staged[0].va, image.TextVa());

    // Staging the identical payload twice must not double count.
    CHECK(patcher.Stage(image.TextVa(), { 0xDE, 0xAD, 0xBE, 0xEF }));
    CHECK_EQ(patcher.StagedCount(), std::size_t{ 1 });

    patcher.ClearStaged();
    CHECK_EQ(patcher.StagedCount(), std::size_t{ 0 });

    std::remove(path.c_str());
}

LATTIC_TEST(Patcher, ApplyWritesStagedBytesToOutput)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_apply.bin");
    const std::string outPath = "test_patcher_apply_out.bin";

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    CHECK(patcher.Stage(image.TextVa() + 4, { 0x01, 0x02, 0x03, 0x04 }));

    Patcher::Options options;
    Patcher::Report report;

    CHECK(patcher.Apply(outPath, options, report));
    CHECK(report.error.empty());
    CHECK_EQ(report.patchesApplied, std::size_t{ 1 });
    CHECK_EQ(report.bytesWritten, std::size_t{ 4 });

    Binary written;
    CHECK(written.Load(outPath));

    std::vector<std::uint8_t> bytes;
    CHECK(written.Read(image.textRawOff + 4, 4, bytes));
    CHECK_EQ(bytes[0], std::uint8_t{ 0x01 });
    CHECK_EQ(bytes[3], std::uint8_t{ 0x04 });

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(Patcher, ApplyRejectsEmptyOutputPath)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_noout.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    Patcher::Options options;
    Patcher::Report report;

    CHECK(!patcher.Apply("", options, report));
    CHECK(!report.error.empty());

    std::remove(path.c_str());
}

LATTIC_TEST(Patcher, ApplyStripsDebugDirectoryAndSymbolTable)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_strip.bin");
    const std::string outPath = "test_patcher_strip_out.bin";

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);

    Patcher::Options options;
    options.stripDebugInfo = true;

    Patcher::Report report;
    CHECK(patcher.Apply(outPath, options, report));
    CHECK(report.debugInfoStripped);

    Binary written;
    CHECK(written.Load(outPath));

    PeParser verify;
    CHECK(verify.Parse(written));

    const lattic::core::DataDirectory* debugDir = verify.Directory(6);
    CHECK(debugDir != nullptr);
    CHECK(!debugDir->Present());

    // The COFF symbol table pointer and count must both be zeroed.
    const std::size_t lfanew = image.bytes[0x3C] | (image.bytes[0x3D] << 8) |
                               (image.bytes[0x3E] << 16) |
                               (static_cast<std::size_t>(image.bytes[0x3F]) << 24);
    const std::size_t coff = lfanew + 4;

    std::uint32_t symbolPtr = 0;
    std::uint32_t symbolCount = 0;
    std::memcpy(&symbolPtr, written.Data() + coff + 8, 4);
    std::memcpy(&symbolCount, written.Data() + coff + 12, 4);

    CHECK_EQ(symbolPtr, std::uint32_t{ 0 });
    CHECK_EQ(symbolCount, std::uint32_t{ 0 });

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(Patcher, ApplyUpdatesChecksum)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_checksum.bin");
    const std::string outPath = "test_patcher_checksum_out.bin";

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    CHECK(patcher.Stage(image.TextVa(), { 0x90 }));

    Patcher::Options options;
    options.preserveChecksum = true;

    Patcher::Report report;
    CHECK(patcher.Apply(outPath, options, report));
    CHECK(report.checksumUpdated);

    Binary written;
    CHECK(written.Load(outPath));

    PeParser verify;
    CHECK(verify.Parse(written));
    CHECK(verify.Checksum() != 0);

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(Patcher, ApplyLeavesChecksumWhenNotPreserved)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_nochecksum.bin");
    const std::string outPath = "test_patcher_nochecksum_out.bin";

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);
    CHECK(patcher.Stage(image.TextVa(), { 0x90 }));

    Patcher::Options options;
    options.preserveChecksum = false;

    Patcher::Report report;
    CHECK(patcher.Apply(outPath, options, report));
    CHECK(!report.checksumUpdated);

    Binary written;
    CHECK(written.Load(outPath));

    PeParser verify;
    CHECK(verify.Parse(written));
    CHECK_EQ(verify.Checksum(), std::uint32_t{ 0 });

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(Patcher, ApplyEncryptsStringsAndReportsCount)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_encrypt.bin");
    const std::string outPath = "test_patcher_encrypt_out.bin";

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    Patcher patcher(binary, parser);

    Patcher::Options options;
    options.encryptStrings = true;

    Patcher::Report report;
    CHECK(patcher.Apply(outPath, options, report));
    CHECK(report.error.empty());
    CHECK(report.stringsEncryptedApplied);
    CHECK(report.stringsEncrypted > 0);

    // The output must still parse and must now carry the decryptor section.
    Binary written;
    CHECK(written.Load(outPath));

    PeParser verify;
    CHECK(verify.Parse(written));
    CHECK(verify.SectionByName(".lattic") != nullptr);

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(Patcher, ApplyHonoursAnExplicitStringSelection)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    const char* first  = "FirstSelectedValue";
    const char* second = "SecondSelectedValue";
    const std::size_t offsetA = 0x40;
    const std::size_t offsetB = 0x80;

    std::memcpy(image.bytes.data() + image.rdataRawOff + offsetA, first, std::strlen(first) + 1);
    std::memcpy(image.bytes.data() + image.rdataRawOff + offsetB, second, std::strlen(second) + 1);

    const std::string path = lattic::test::WriteTempFile(image, "test_patcher_subset.bin");
    const std::string outPath = "test_patcher_subset_out.bin";

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    lattic::core::StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    const std::uint32_t wantRva = image.rdataRva + static_cast<std::uint32_t>(offsetA);

    std::vector<lattic::core::StringCandidate> only;
    for (const auto& candidate : scanner.Candidates())
    {
        if (candidate.rva == wantRva)
        {
            only.push_back(candidate);
        }
    }

    CHECK_EQ(only.size(), std::size_t{ 1 });

    Patcher patcher(binary, parser);

    Patcher::Options options;
    options.encryptStrings = true;
    options.strings = only;

    Patcher::Report report;
    CHECK(patcher.Apply(outPath, options, report));
    CHECK_EQ(report.stringsEncrypted, std::size_t{ 1 });

    Binary written;
    CHECK(written.Load(outPath));

    std::vector<std::uint8_t> untouched;
    CHECK(written.Read(image.rdataRawOff + offsetB, std::strlen(second), untouched));
    CHECK_EQ(std::string(reinterpret_cast<const char*>(untouched.data()), untouched.size()),
             std::string(second));

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}
