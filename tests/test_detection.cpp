#include "TestFramework.hpp"

#include "PeFixture.hpp"

#include "lattic/Lattic.hpp"
#include "lattic/core/PackerDetector.hpp"

#include <cstdio>
#include <string>

using lattic::Lattic;
using lattic::PatchOptions;

namespace
{
std::size_t FileSize(const std::string& path)
{
    std::FILE* file = std::fopen(path.c_str(), "rb");

    if (file == nullptr)
    {
        return 0;
    }

    std::fseek(file, 0, SEEK_END);
    const long size = std::ftell(file);
    std::fclose(file);

    return size > 0 ? static_cast<std::size_t>(size) : 0;
}

void AppendMarker(const std::string& path, const char* marker)
{
    std::FILE* file = std::fopen(path.c_str(), "ab");

    if (file != nullptr)
    {
        std::fwrite(marker, 1, std::strlen(marker), file);
        std::fclose(file);
    }
}
}

LATTIC_TEST(PackerDetector, CleanImageReportsNothingFound)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "detect_clean.bin");
    CHECK(!path.empty());

    Lattic core;
    CHECK(core.LoadBinary(path));

    // An empty reason means nothing blocks, and no signature should have fired.
    CHECK(core.DetectPacking().empty());
    CHECK(!core.AlreadyPacked());
    CHECK(core.PackingSignatures().empty());
}

LATTIC_TEST(PackerDetector, FindsLatticMarkerAndBlocksRepatch)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "detect_lattic.bin");
    CHECK(!path.empty());

    AppendMarker(path, "LATTIC_STUB");

    Lattic core;
    CHECK(core.LoadBinary(path));

    const std::string block = core.DetectPacking();

    CHECK(core.AlreadyPacked());
    CHECK(!block.empty());
    CHECK(core.PackingSignatures().size() == 1);
    CHECK(core.PackingSignatures()[0].find("Lattic") != std::string::npos);
}

LATTIC_TEST(PackerDetector, RepatchIsRefusedBeforeAnythingIsWritten)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "detect_repatch.bin");
    CHECK(!path.empty());

    AppendMarker(path, "LATTIC_STUB");

    Lattic core;
    CHECK(core.LoadBinary(path));

    PatchOptions options;
    options.encryptStrings = true;

    const auto result = core.ApplyAndSave("detect_repatch_out.bin", options);

    // The whole point: the second patch must refuse rather than appending a duplicate
    // section at the same RVA.
    CHECK(!result.success);
    CHECK(!result.message.empty());
    CHECK(result.message.find("already packed") != std::string::npos);
}

LATTIC_TEST(PackerDetector, ForeignPackersWarnButDoNotBlock)
{
    lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "detect_upx.bin");
    CHECK(!path.empty());

    AppendMarker(path, "UPX!");

    Lattic core;
    CHECK(core.LoadBinary(path));

    // Another packer's signature is reported but must not stop the user.
    CHECK(core.DetectPacking().empty());
    CHECK(!core.AlreadyPacked());
    CHECK(!core.PackingSignatures().empty());
}

LATTIC_TEST(PackerDetector, NoBinaryIsReportedNotCrashed)
{
    Lattic core;

    CHECK(!core.DetectPacking().empty());
    CHECK(!core.AlreadyPacked());
    CHECK_EQ(core.CurrentFileSize(), std::size_t{ 0 });
}

LATTIC_TEST(OutputSize, PadReachesTheRequestedSize)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "pad_target.bin");
    CHECK(!path.empty());

    const std::size_t original = FileSize(path);

    Lattic core;
    CHECK(core.LoadBinary(path));

    PatchOptions options;
    options.targetFileSize = original + 4096;

    const auto result = core.ApplyAndSave("pad_target_out.bin", options);

    CHECK(result.success);
    CHECK_EQ(FileSize("pad_target_out.bin"), original + 4096);
    CHECK_EQ(result.bytesPadded, std::size_t{ 4096 });
}

LATTIC_TEST(OutputSize, ZeroTargetLeavesTheFileAlone)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "pad_zero.bin");
    CHECK(!path.empty());

    const std::size_t original = FileSize(path);

    Lattic core;
    CHECK(core.LoadBinary(path));

    const auto result = core.ApplyAndSave("pad_zero_out.bin", PatchOptions{});

    CHECK(result.success);
    CHECK_EQ(FileSize("pad_zero_out.bin"), original);
    CHECK_EQ(result.bytesPadded, std::size_t{ 0 });
}

LATTIC_TEST(OutputSize, TargetBelowCurrentSizeIsIgnoredNotTruncated)
{
    const lattic::test::PeImage image = lattic::test::BuildPeImage();
    const std::string path = lattic::test::WriteTempFile(image, "pad_small.bin");
    CHECK(!path.empty());

    const std::size_t original = FileSize(path);

    Lattic core;
    CHECK(core.LoadBinary(path));

    PatchOptions options;
    options.targetFileSize = original / 2;

    const auto result = core.ApplyAndSave("pad_small_out.bin", options);

    // Shrinking would mean discarding real sections, so the request is a no-op.
    CHECK(result.success);
    CHECK_EQ(FileSize("pad_small_out.bin"), original);
    CHECK_EQ(result.bytesPadded, std::size_t{ 0 });
}
