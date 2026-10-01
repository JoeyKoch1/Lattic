#include "PeFixture.hpp"
#include "TestFramework.hpp"

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/StringEncryptor.hpp"
#include "lattic/core/StringScanner.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using lattic::core::Binary;
using lattic::core::EncryptOptions;
using lattic::core::EncryptReport;
using lattic::core::PeParser;
using lattic::core::StringCandidate;
using lattic::core::StringEncryptor;
using lattic::core::StringScanner;

// The fixture plants a 24 byte marker string at .rdata+0, so test strings start past it.
constexpr std::size_t kStr  = 0x40;
constexpr std::size_t kStr2 = 0x80;

namespace
{
void PutAscii(lattic::test::PeImage& image, std::size_t rvaOffset, const char* text)
{
    std::memcpy(image.bytes.data() + image.rdataRawOff + rvaOffset, text, std::strlen(text) + 1);
}

std::string ReadAscii(const lattic::core::Binary& binary, std::size_t offset, std::size_t length)
{
    std::vector<std::uint8_t> bytes;

    if (!binary.Read(offset, length, bytes))
    {
        return "<unreadable>";
    }

    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::size_t LfanewOf(const lattic::test::PeImage& image)
{
    return image.bytes[0x3C] | (image.bytes[0x3D] << 8) | (image.bytes[0x3E] << 16) |
           (static_cast<std::size_t>(image.bytes[0x3F]) << 24);
}

std::uint32_t ReadU32At(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    if (offset + 4 > bytes.size())
    {
        return 0;
    }

    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, 4);
    return value;
}

// Reads a window of the appended section straight out of the loaded image.
std::vector<std::uint8_t> ReadAt(const Binary& binary, std::size_t offset, std::size_t length)
{
    std::vector<std::uint8_t> bytes;
    binary.Read(offset, length, bytes);
    return bytes;
}
}

LATTIC_TEST(StringEncryptor, RejectsOverlongSectionName)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "EncryptableString");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_name.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringEncryptor encryptor;

    EncryptOptions options;
    options.sectionName = "waytoolongsection";

    const EncryptReport report = encryptor.Encrypt(binary, parser, options);

    CHECK(!report.success);
    CHECK(!report.message.empty());
    CHECK(!report.entryPointHooked);

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, ReportsNoWorkWhenNothingMatches)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    // No strings at all in the fixture's readable data.
    const std::string path = lattic::test::WriteTempFile(image, "test_enc_none.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringEncryptor encryptor;

    EncryptOptions options;
    options.minLength = 4000;

    const EncryptReport report = encryptor.Encrypt(binary, parser, options);

    CHECK(report.success);
    CHECK_EQ(report.stringsEncrypted, std::size_t{ 0 });

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, EncryptsSelectedStringsInPlace)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "SecretPassword1");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_select.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    const std::vector<StringCandidate> candidates = scanner.Candidates();
    CHECK(!candidates.empty());

    StringEncryptor encryptor;

    EncryptOptions options;
    const EncryptReport report = encryptor.EncryptSelected(binary, parser, candidates, options);

    CHECK(report.success);
    CHECK(report.entryPointHooked);
    CHECK_EQ(report.stringsEncrypted, candidates.size());
    CHECK(report.bytesEncrypted > 0);

    // The string must no longer be readable as itself.
    const std::string after = ReadAscii(binary, image.rdataRawOff + kStr, 16);
    CHECK(after != "SecretPassword1");

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, XorIsItsOwnInverse)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "RoundTripValue");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_roundtrip.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    const std::vector<StringCandidate> candidates = scanner.Candidates();
    CHECK(!candidates.empty());

    const std::string original = ReadAscii(binary, image.rdataRawOff + kStr, 14);
    CHECK_EQ(original, std::string("RoundTripValue"));

    StringEncryptor encryptor;
    EncryptOptions options;
    CHECK(encryptor.EncryptSelected(binary, parser, candidates, options).success);

    const std::string encrypted = ReadAscii(binary, image.rdataRawOff + kStr, 14);
    CHECK(encrypted != original);

    // Re-parsing the same region and encrypting again restores the plaintext, which is
    // exactly what the injected runtime does at load time.
    PeParser verify;
    CHECK(verify.Parse(binary));

    StringEncryptor second;
    CHECK(second.EncryptSelected(binary, verify, candidates, options).success);

    const std::string restored = ReadAscii(binary, image.rdataRawOff + kStr, 14);
    CHECK_EQ(restored, original);

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, IsDeterministicAcrossRuns)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "DeterministicCheck");

    const std::string pathA = lattic::test::WriteTempFile(image, "test_enc_det_a.bin");
    const std::string pathB = lattic::test::WriteTempFile(image, "test_enc_det_b.bin");

    Binary binaryA;
    Binary binaryB;
    CHECK(binaryA.Load(pathA));
    CHECK(binaryB.Load(pathB));

    PeParser parserA;
    PeParser parserB;
    CHECK(parserA.Parse(binaryA));
    CHECK(parserB.Parse(binaryB));

    StringScanner scannerA;
    StringScanner scannerB;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;

    CHECK(scannerA.Scan(binaryA, parserA, scanOptions).success);
    CHECK(scannerB.Scan(binaryB, parserB, scanOptions).success);

    StringEncryptor encryptorA;
    StringEncryptor encryptorB;

    EncryptOptions options;
    CHECK(encryptorA.EncryptSelected(binaryA, parserA, scannerA.Candidates(), options).success);
    CHECK(encryptorB.EncryptSelected(binaryB, parserB, scannerB.Candidates(), options).success);

    CHECK_EQ(ReadAscii(binaryA, image.rdataRawOff + kStr, 18),
             ReadAscii(binaryB, image.rdataRawOff + kStr, 18));

    std::remove(pathA.c_str());
    std::remove(pathB.c_str());
}

LATTIC_TEST(StringEncryptor, DifferentSeedsProduceDifferentCiphertext)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "SeedVariationCheck");

    const std::string pathA = lattic::test::WriteTempFile(image, "test_enc_seed_a.bin");
    const std::string pathB = lattic::test::WriteTempFile(image, "test_enc_seed_b.bin");

    Binary binaryA;
    Binary binaryB;
    CHECK(binaryA.Load(pathA));
    CHECK(binaryB.Load(pathB));

    PeParser parserA;
    PeParser parserB;
    CHECK(parserA.Parse(binaryA));
    CHECK(parserB.Parse(binaryB));

    StringScanner scannerA;
    StringScanner scannerB;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;

    CHECK(scannerA.Scan(binaryA, parserA, scanOptions).success);
    CHECK(scannerB.Scan(binaryB, parserB, scanOptions).success);

    StringEncryptor encryptorA;
    StringEncryptor encryptorB;

    EncryptOptions optionsA;
    optionsA.seed = 0x11111111;

    EncryptOptions optionsB;
    optionsB.seed = 0x22222222;

    CHECK(encryptorA.EncryptSelected(binaryA, parserA, scannerA.Candidates(), optionsA).success);
    CHECK(encryptorB.EncryptSelected(binaryB, parserB, scannerB.Candidates(), optionsB).success);

    CHECK(ReadAscii(binaryA, image.rdataRawOff + kStr, 19) !=
          ReadAscii(binaryB, image.rdataRawOff + kStr, 19));

    std::remove(pathA.c_str());
    std::remove(pathB.c_str());
}

LATTIC_TEST(StringEncryptor, AppendsMappedExecutableSection)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "SectionAppendCheck");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_section.bin");
    const std::size_t originalSize = image.bytes.size();

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    const std::uint16_t sectionsBefore = parser.NumberOfSections();

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, scanner.Candidates(), EncryptOptions{});

    CHECK(report.success);
    CHECK(binary.Size() > originalSize);

    // The image must still parse cleanly, with one more section.
    PeParser verify;
    CHECK(verify.Parse(binary));
    CHECK_EQ(verify.NumberOfSections(), sectionsBefore + 1);

    const auto* added = verify.SectionByName(".lattic");
    CHECK(added != nullptr);
    CHECK(added->Executable());
    CHECK(added->Readable());
    CHECK(added->Writable());
    CHECK(added->rawOffset == report.sectionRawOffset);

    // Entry point must now point at the new section.
    CHECK_EQ(verify.EntryPointRva(), report.sectionRva);
    CHECK_EQ(report.originalEntryPoint, image.entryRva);

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, NewSectionIsRvaAligned)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "AlignmentCheckHere");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_align.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, scanner.Candidates(), EncryptOptions{});

    CHECK(report.success);
    CHECK_EQ(report.sectionRva % parser.SectionAlignment(), std::uint32_t{ 0 });
    CHECK_EQ(report.sectionRawOffset % parser.FileAlignment(), std::uint32_t{ 0 });

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, EmitsTrampolineThatLoadsOriginalEntryPoint)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "TrampolineShapeCheck");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_tramp.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, scanner.Candidates(), EncryptOptions{});

    CHECK(report.success);

    const std::size_t trampolineSize = StringEncryptor::TrampolineSize();
    CHECK_EQ(report.trampolineSize, trampolineSize);
    CHECK_EQ(trampolineSize, std::size_t{ 12 });

    // The parser predates the appended section, so read the offset straight from the report.
    const std::uint32_t fileOffset = report.sectionRawOffset;

    const auto trampoline = ReadAt(binary, fileOffset, trampolineSize);
    CHECK_EQ(trampoline.size(), trampolineSize);

    // lea rax, [rip + disp32], with rax carrying the original entry point to the stub.
    CHECK_EQ(trampoline[0], std::uint8_t{ 0x48 });
    CHECK_EQ(trampoline[1], std::uint8_t{ 0x8D });
    CHECK_EQ(trampoline[2], std::uint8_t{ 0x05 });

    std::int32_t disp = 0;
    std::memcpy(&disp, trampoline.data() + 3, 4);

    // RIP after the lea is the section RVA plus 7, and it must land on the original
    // entry point.
    const std::int64_t target = static_cast<std::int64_t>(report.sectionRva) + 7 + disp;
    CHECK_EQ(target, static_cast<std::int64_t>(report.originalEntryPoint));

    CHECK_EQ(trampoline[7], std::uint8_t{ 0xE9 });

    std::int32_t jmpDisp = 0;
    std::memcpy(&jmpDisp, trampoline.data() + 8, 4);

    // The jmp is the last instruction in the trampoline, so its RIP is already the stub's
    // first byte and the displacement is zero.
    CHECK_EQ(jmpDisp, 0);
    CHECK_EQ(trampolineSize, std::size_t{ 12 });

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, RuntimeEndsWithJumpToRax)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "StubTailCheckValue");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_tail.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, scanner.Candidates(), EncryptOptions{});

    CHECK(report.success);

    // The parser predates the appended section, so read the offset straight from the report.
    const std::uint32_t fileOffset = report.sectionRawOffset;

    const auto stub = ReadAt(binary, fileOffset + report.trampolineSize,
                             StringEncryptor::StubSize());

    CHECK_EQ(stub.size(), StringEncryptor::StubSize());
    CHECK_EQ(stub[stub.size() - 2], std::uint8_t{ 0xFF });
    CHECK_EQ(stub[stub.size() - 1], std::uint8_t{ 0xE0 });

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, TableRecordsMatchTheSelection)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "TableRecordCheck");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_table.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    const std::vector<StringCandidate> candidates = scanner.Candidates();
    CHECK(!candidates.empty());

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, candidates, EncryptOptions{});

    CHECK(report.success);
    CHECK_EQ(report.tableSize, candidates.size() * StringEncryptor::TableEntrySize());

    // The parser predates the appended section, so read the offset straight from the report.
    const std::uint32_t fileOffset = report.sectionRawOffset;

    const std::size_t tableOffset =
        fileOffset + report.trampolineSize + StringEncryptor::StubSize();

    const auto table = ReadAt(binary, tableOffset, report.tableSize);
    CHECK_EQ(table.size(), report.tableSize);

    for (std::size_t i = 0; i < candidates.size(); ++i)
    {
        const std::uint32_t rva    = ReadU32At(table, i * 16);
        const std::uint32_t length = ReadU32At(table, i * 16 + 4);

        CHECK(rva != 0);
        CHECK_EQ(length, candidates[i].byteLength);

        // A key of zero would leave the string in plaintext.
        CHECK(table[i * 16 + 12] != 0);
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, TableDeltasResolveToTheTargetStrings)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "DeltaResolveCheck");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_delta.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    const std::vector<StringCandidate> candidates = scanner.Candidates();
    CHECK(!candidates.empty());

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, candidates, EncryptOptions{});

    CHECK(report.success);

    const std::uint32_t tableRva =
        report.sectionRva + static_cast<std::uint32_t>(report.trampolineSize) +
        static_cast<std::uint32_t>(StringEncryptor::StubSize());

    const std::uint32_t imageBase = static_cast<std::uint32_t>(parser.ImageBase());

    // The parser predates the appended section, so read the offset straight from the report.
    const std::uint32_t fileOffset = report.sectionRawOffset;

    const auto table = ReadAt(binary, fileOffset + report.trampolineSize +
                                       StringEncryptor::StubSize(),
                              report.tableSize);

    for (std::size_t i = 0; i < candidates.size(); ++i)
    {
        std::int32_t delta = 0;
        std::memcpy(&delta, table.data() + i * 16 + 8, 4);

        const std::uint32_t fieldRva = tableRva + static_cast<std::uint32_t>(i * 16) + 8;
        const std::uint32_t fieldVa  = imageBase + fieldRva;
        const std::uint32_t targetVa = imageBase + candidates[i].rva;

        // The runtime computes lea rcx,[rsi+8] then adds this delta, so the two must agree.
        CHECK_EQ(static_cast<std::int64_t>(fieldVa) + delta,
                 static_cast<std::int64_t>(targetVa));
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, MaxStringsCapsTheSelection)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "FirstCandidate");
    PutAscii(image, kStr, "SecondCandidate");
    PutAscii(image, kStr2, "ThirdCandidate");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_cap.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    const std::vector<StringCandidate> candidates = scanner.Candidates();
    CHECK(candidates.size() >= 3);

    StringEncryptor encryptor;

    EncryptOptions options;
    options.maxStrings = 2;

    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, candidates, options);

    CHECK(report.success);
    CHECK_EQ(report.stringsEncrypted, std::size_t{ 2 });
    CHECK(report.candidatesSkipped > 0);

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, RejectsCandidatesWithBadOffsets)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "ValidStringHere");

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_badoff.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringCandidate bogus;
    bogus.rva        = image.rdataRva;
    bogus.fileOffset = 0xFFFFFF;
    bogus.byteLength = 64;

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, { bogus }, EncryptOptions{});

    CHECK(report.success);
    CHECK_EQ(report.stringsEncrypted, std::size_t{ 0 });
    CHECK_EQ(report.candidatesSkipped, std::size_t{ 1 });
    CHECK(!report.entryPointHooked);

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, PlannedSectionRvaIsAlignedAndPastTheLast)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_planned.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    const std::uint32_t planned = StringEncryptor::PlannedSectionRva(parser);

    CHECK_EQ(planned % parser.SectionAlignment(), std::uint32_t{ 0 });

    for (const auto& section : parser.Sections())
    {
        const std::uint32_t end = section.virtualAddress + section.virtualSize;
        CHECK(planned >= end);
    }

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, FailsWhenNoSectionHeaderSlotIsFree)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "NoRoomForSection");

    const std::size_t lfanew = LfanewOf(image);
    const std::size_t coff  = lfanew + 4;
    const std::size_t opt   = coff + 20;

    // Claim every header slot up to SizeOfHeaders.
    const std::uint32_t headersSize = image.bytes[opt + 60] |
                                      (image.bytes[opt + 61] << 8) |
                                      (image.bytes[opt + 62] << 16) |
                                      (static_cast<std::uint32_t>(image.bytes[opt + 63]) << 24);

    const std::size_t sectionTable = opt + 240;
    const std::size_t maxSections  = (headersSize - sectionTable) / 40;

    // The fixture defines two real section headers. Pad the rest with zeroes so the
    // inflated count still parses, which is what a packed binary looks like.
    for (std::size_t i = 2; i < maxSections; ++i)
    {
        std::memset(image.bytes.data() + sectionTable + i * 40, 0, 40);
    }

    lattic::test::PutU16(image.bytes, coff + 2, static_cast<std::uint16_t>(maxSections));

    // The trailing slots are empty, so nothing they hold can be scanned. Put a string in
    // the last declared slot to prove the scan sees it before the append is refused.
    const std::size_t lastHeader = sectionTable + (maxSections - 1) * 40;
    const std::uint32_t lastRaw = static_cast<std::uint32_t>(image.rdataRawOff + kStr);
    const std::uint32_t lastRva = static_cast<std::uint32_t>(image.rdataRva + kStr);

    std::memcpy(image.bytes.data() + lastHeader, ".lattic", 7);
    lattic::test::PutU32(image.bytes, lastHeader + 8, 64);
    lattic::test::PutU32(image.bytes, lastHeader + 12, lastRva);
    lattic::test::PutU32(image.bytes, lastHeader + 16, 64);
    lattic::test::PutU32(image.bytes, lastHeader + 20, lastRaw);
    lattic::test::PutU32(image.bytes, lastHeader + 36, 0x40000040);

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_noroom.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);
    CHECK(!scanner.Candidates().empty());

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, scanner.Candidates(), EncryptOptions{});

    CHECK(!report.success);
    CHECK(!report.message.empty());
    CHECK(!report.entryPointHooked);

    // The plaintext must survive a failed run.
    CHECK_EQ(ReadAscii(binary, image.rdataRawOff + kStr, 16),
             std::string("NoRoomForSection"));

    std::remove(path.c_str());
}

LATTIC_TEST(StringEncryptor, MarksEncryptedSectionsWritable)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    PutAscii(image, kStr, "WritableSectionCheck");

    // The fixture's .rdata is read only, which is exactly the case that made patched
    // output fault on its first xor.
    const std::size_t lfanew = LfanewOf(image);
    const std::size_t opt    = lfanew + 4 + 20;
    const std::size_t rdataHeader = opt + 240 + 40;

    const std::uint32_t before = ReadU32At(image.bytes, rdataHeader + 36);
    CHECK((before & 0x80000000u) == 0);

    const std::string path = lattic::test::WriteTempFile(image, "test_enc_writable.bin");

    Binary binary;
    CHECK(binary.Load(path));

    PeParser parser;
    CHECK(parser.Parse(binary));

    StringScanner scanner;
    lattic::core::ScanOptions scanOptions;
    scanOptions.includeUtf16 = false;
    CHECK(scanner.Scan(binary, parser, scanOptions).success);

    StringEncryptor encryptor;
    const EncryptReport report =
        encryptor.EncryptSelected(binary, parser, scanner.Candidates(), EncryptOptions{});

    CHECK(report.success);

    // The encryptor mutates the in-memory image, so the patched bytes have to be written
    // out before they can be inspected.
    const std::string outPath = "test_enc_writable_out.bin";
    CHECK(binary.Save(outPath));

    Binary written;
    CHECK(written.Load(outPath));

    PeParser verify;
    CHECK(verify.Parse(written));

    const lattic::core::Section* rdata = verify.SectionByName(".rdata");
    CHECK(rdata != nullptr);
    CHECK(rdata->Writable());

    // The .text section holds no encrypted string and must keep its original flags.
    const lattic::core::Section* text = verify.SectionByName(".text");
    CHECK(text != nullptr);
    CHECK(!text->Writable());

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(StringEncryptor, BuildRuntimeIsDeterministic)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    StringCandidate candidate;
    candidate.rva        = image.rdataRva + 0x10;
    candidate.fileOffset = image.rdataRawOff + kStr;
    candidate.byteLength = 16;

    const std::vector<std::uint8_t> keys = { 0x7B };
    const std::uint32_t imageBase = static_cast<std::uint32_t>(image.imageBase);

    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;

    CHECK(StringEncryptor::BuildRuntime(0x3000, imageBase, image.entryRva, { candidate }, keys,
                                        first));
    CHECK(StringEncryptor::BuildRuntime(0x3000, imageBase, image.entryRva, { candidate }, keys,
                                        second));

    CHECK(!first.empty());
    CHECK(first == second);
}

LATTIC_TEST(StringEncryptor, BuildRuntimeRejectsMismatchedKeyCount)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();

    StringCandidate candidate;
    candidate.rva        = image.rdataRva;
    candidate.byteLength = 8;

    std::vector<std::uint8_t> out;
    const std::uint32_t imageBase = static_cast<std::uint32_t>(image.imageBase);

    CHECK(!StringEncryptor::BuildRuntime(0x3000, imageBase, image.entryRva, { candidate }, {},
                                         out));
    CHECK(!StringEncryptor::BuildRuntime(0x3000, imageBase, image.entryRva, {}, {}, out));
}
