#include "TestFramework.hpp"

#include "PeFixture.hpp"

#include "lattic/core/AntiDebug.hpp"
#include "lattic/core/Binary.hpp"
#include "lattic/core/IntegrityGuard.hpp"
#include "lattic/core/PeParser.hpp"

#include <string>
#include <vector>

using lattic::core::AntiDebug;
using lattic::core::AntiDebugOptions;
using lattic::core::DebugResponse;
using lattic::core::DebuggerCheck;
using lattic::core::IntegrityGuard;
using lattic::core::IntegrityOptions;
using lattic::core::IntegrityReport;
using lattic::core::TamperResponse;

LATTIC_TEST(AntiDebug, IndividualChecksDoNotCrashInAnUndebuggedProcess)
{
    // None of these may throw, hang or fault when nothing is attached, which is the normal
    // case. A check that faults would take the whole target down.
    AntiDebug::IsDebuggerPresent();
    AntiDebug::HasDebugPort();
    AntiDebug::HasDebugObjectHandle();
    AntiDebug::HasDebugFlags();
    AntiDebug::HasHardwareBreakpoints();
    AntiDebug::HasRemoteDebugger();
}

LATTIC_TEST(AntiDebug, CheckIsFalseWhenNothingIsAttached)
{
    AntiDebugOptions options;
    options.checkDebuggerProcesses = false;   // no names configured anyway

    const DebuggerCheck result = AntiDebug::Check(options);

    // The test runner is not debugged, so every enabled check must come back clean. If any
    // of these fire here they are producing false positives.
    CHECK(!result.detected);
    CHECK(result.method.empty());
}

LATTIC_TEST(AntiDebug, DisabledChecksAreNotRun)
{
    AntiDebugOptions options;
    options.checkDebugPort           = false;
    options.checkDebugObjectHandle   = false;
    options.checkDebugFlags          = false;
    options.checkRemoteDebugger      = false;
    options.checkHardwareBreakpoints = false;
    options.checkDebuggerProcesses   = false;

    const DebuggerCheck result = AntiDebug::Check(options);

    CHECK(!result.detected);
}

LATTIC_TEST(AntiDebug, ProcessScanIsCaseInsensitiveAndIgnoresExtension)
{
    const auto found = AntiDebug::FindDebuggerProcesses({ "NoSuchDebuggerAnywhere.exe" });

    CHECK(found.empty());

    // The test runner itself is a running process, so searching for its own base name must
    // find it. This is what proves the enumeration and the case insensitive normalisation
    // both work, without depending on whether a real debugger happens to be open.
    const auto self = AntiDebug::FindDebuggerProcesses({ "lattic_tests" });

    CHECK_EQ(self.size(), std::size_t{ 1 });
    CHECK_EQ(self[0], std::string("lattic_tests"));
}

LATTIC_TEST(AntiDebug, ProcessScanIsCaseInsensitive)
{
    const auto self = AntiDebug::FindDebuggerProcesses({ "LATTIC_TESTS.EXE" });

    CHECK_EQ(self.size(), std::size_t{ 1 });
    CHECK_EQ(self[0], std::string("lattic_tests"));
}

LATTIC_TEST(AntiDebug, ProcessScanReturnsOnlyNamesThatMatched)
{
    const auto found = AntiDebug::FindDebuggerProcesses(
        { "definitely_not_running_aaa.exe", "lattic_tests",
          "definitely_not_running_bbb" });

    CHECK_EQ(found.size(), std::size_t{ 1 });
    CHECK_EQ(found[0], std::string("lattic_tests"));
}

LATTIC_TEST(AntiDebug, EmptyNameListScansNothing)
{
    const auto found = AntiDebug::FindDebuggerProcesses({});

    CHECK(found.empty());
}

LATTIC_TEST(AntiDebug, ResponseNamesAreDefined)
{
    CHECK(std::string(AntiDebug::ResponseName(DebugResponse::Ignore))     == "Ignore");
    CHECK(std::string(AntiDebug::ResponseName(DebugResponse::Dialog)) == "Dialog");
    CHECK(std::string(AntiDebug::ResponseName(DebugResponse::Terminate))  == "Terminate");
}

LATTIC_TEST(AntiDebug, IgnoreResponseDoesNothingOnAFalsePositive)
{
    AntiDebugOptions options;
    options.response = DebugResponse::Ignore;

    DebuggerCheck hit;
    hit.detected = true;
    hit.method   = "Synthetic";

    // Must return rather than exit, otherwise this test would take the runner down with it.
    AntiDebug::Respond(options, hit);
    CHECK(true);
}

LATTIC_TEST(AntiDebug, ResponseOnACleanCheckIsANoOp)
{
    AntiDebugOptions options;
    options.response = DebugResponse::Terminate;

    DebuggerCheck clean;
    clean.detected = false;

    AntiDebug::Respond(options, clean);
    CHECK(true);
}

LATTIC_TEST(Integrity, DigestIsStableAcrossCalls)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "integrity_stable.bin");
    CHECK(!path.empty());

    lattic::core::Binary binary;
    lattic::core::PeParser parser;

    CHECK(binary.Load(path));
    CHECK(parser.Parse(binary));

    const std::uint32_t first  = IntegrityGuard::ComputeDigest(binary, parser, {});
    const std::uint32_t second = IntegrityGuard::ComputeDigest(binary, parser, {});

    CHECK(first == second);
    CHECK(first != 0);
}

LATTIC_TEST(Integrity, FlippedByteChangesTheDigest)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "integrity_flip.bin");
    CHECK(!path.empty());

    lattic::core::Binary binary;
    lattic::core::PeParser parser;

    CHECK(binary.Load(path));
    CHECK(parser.Parse(binary));

    const std::uint32_t before = IntegrityGuard::ComputeDigest(binary, parser, {});

    // Flip one byte inside .rdata, which is covered by the digest.
    std::vector<std::uint8_t> patch = { 0xFF };
    CHECK(binary.Write(image.rdataRawOff + 4, patch));

    lattic::core::PeParser reparsed;
    CHECK(reparsed.Parse(binary));

    const std::uint32_t after = IntegrityGuard::ComputeDigest(binary, reparsed, {});

    CHECK(after != before);
}

LATTIC_TEST(Integrity, IgnoredSectionsAreExcluded)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "integrity_ignore.bin");
    CHECK(!path.empty());

    lattic::core::Binary binary;
    lattic::core::PeParser parser;

    CHECK(binary.Load(path));
    CHECK(parser.Parse(binary));

    const std::uint32_t full = IntegrityGuard::ComputeDigest(binary, parser, {});

    // Excluding .rdata must produce a different digest, proving the exclusion is honoured
    // rather than silently ignored.
    const std::uint32_t partial =
        IntegrityGuard::ComputeDigest(binary, parser, { image.rdataRva });

    CHECK(full != partial);
}

LATTIC_TEST(Integrity, ZeroExpectedDigestIsNotEvidenceOfTampering)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "integrity_zero.bin");
    CHECK(!path.empty());

    lattic::core::Binary binary;
    lattic::core::PeParser parser;

    CHECK(binary.Load(path));
    CHECK(parser.Parse(binary));

    IntegrityOptions options;
    options.response = TamperResponse::Ignore;

    // Zero means packing never recorded one. Reporting that as tampering would fail every
    // image that was packed without the integrity option.
    const IntegrityReport report = IntegrityGuard::Verify(binary, parser, 0, options);

    CHECK(report.intact);
    CHECK(!report.message.empty());
}

LATTIC_TEST(Integrity, MismatchIsReportedAndIgnoreKeepsRunning)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "integrity_mismatch.bin");
    CHECK(!path.empty());

    lattic::core::Binary binary;
    lattic::core::PeParser parser;

    CHECK(binary.Load(path));
    CHECK(parser.Parse(binary));

    IntegrityOptions options;
    options.response = TamperResponse::Ignore;

    const IntegrityReport report =
        IntegrityGuard::Verify(binary, parser, 0xDEADBEEF, options);

    CHECK(!report.intact);
    CHECK_EQ(report.expected, std::uint32_t{ 0xDEADBEEF });
    CHECK(report.message.find("Integrity check failed") != std::string::npos);
}

LATTIC_TEST(Integrity, ResponseNamesAreDefined)
{
    CHECK(std::string(IntegrityGuard::ResponseName(TamperResponse::Ignore))     == "Ignore");
    CHECK(std::string(IntegrityGuard::ResponseName(TamperResponse::Dialog)) == "Dialog");
    CHECK(std::string(IntegrityGuard::ResponseName(TamperResponse::Terminate))  == "Terminate");
}
