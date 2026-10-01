#include "TestFramework.hpp"

#include "lattic/core/Binary.hpp"
#include "lattic/util/StringUtil.hpp"

#include <cstdio>
#include <string>
#include <vector>

using lattic::core::Binary;

namespace
{
std::string WriteTemp(const std::string& name, const std::vector<std::uint8_t>& bytes)
{
    std::FILE* file = std::fopen(name.c_str(), "wb");

    if (file == nullptr)
    {
        return {};
    }

    if (!bytes.empty())
    {
        std::fwrite(bytes.data(), 1, bytes.size(), file);
    }

    std::fclose(file);
    return name;
}
}

LATTIC_TEST(Binary, LoadRejectsEmptyPath)
{
    Binary binary;
    CHECK(!binary.Load(""));
    CHECK(!binary.LastError().empty());
    CHECK(!binary.IsLoaded());
}

LATTIC_TEST(Binary, LoadRejectsMissingFile)
{
    Binary binary;
    CHECK(!binary.Load("this-file-does-not-exist-9d3f.bin"));
    CHECK(!binary.IsLoaded());
}

LATTIC_TEST(Binary, LoadAndSaveRoundTrip)
{
    const std::vector<std::uint8_t> payload = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    const std::string path = WriteTemp("test_binary_roundtrip.bin", payload);

    CHECK(!path.empty());

    Binary binary;
    CHECK(binary.Load(path));
    CHECK(binary.IsLoaded());
    CHECK(!binary.IsEmpty());
    CHECK_EQ(binary.Size(), payload.size());
    CHECK_EQ(binary.Path(), path);

    std::vector<std::uint8_t> readBack;
    CHECK(binary.Read(0, payload.size(), readBack));
    CHECK_EQ(readBack.size(), payload.size());
    CHECK(readBack == payload);

    const std::string outPath = "test_binary_roundtrip_out.bin";
    CHECK(binary.Save(outPath));

    Binary reloaded;
    CHECK(reloaded.Load(outPath));
    CHECK_EQ(reloaded.Size(), payload.size());

    std::remove(path.c_str());
    std::remove(outPath.c_str());
}

LATTIC_TEST(Binary, LoadRejectsEmptyFile)
{
    const std::string path = WriteTemp("test_binary_empty.bin", {});

    CHECK(!path.empty());

    Binary binary;
    CHECK(!binary.Load(path));
    CHECK(!binary.IsLoaded());

    std::remove(path.c_str());
}

LATTIC_TEST(Binary, InBoundsRejectsOverflow)
{
    const std::vector<std::uint8_t> payload = { 1, 2, 3, 4 };
    const std::string path = WriteTemp("test_binary_bounds.bin", payload);

    Binary binary;
    CHECK(binary.Load(path));
    CHECK_EQ(binary.Size(), std::size_t{ 4 });

    CHECK(binary.InBounds(0, 4));
    CHECK(binary.InBounds(4, 0));
    CHECK(binary.InBounds(2, 2));
    CHECK(!binary.InBounds(3, 2));
    CHECK(!binary.InBounds(5, 0));
    CHECK(!binary.InBounds(4, 1));
    CHECK(!binary.InBounds(0xFFFFFFFF, 1));

    std::remove(path.c_str());
}

LATTIC_TEST(Binary, WriteRejectsOutOfBounds)
{
    const std::string path = WriteTemp("test_binary_write.bin", { 1, 2, 3, 4 });

    Binary binary;
    CHECK(binary.Load(path));

    CHECK(binary.Write(1, { 0xAA, 0xBB }));
    CHECK(!binary.Write(3, { 1, 2 }));
    CHECK(!binary.Write(10, { 1 }));
    CHECK(!binary.Write(0, nullptr, 4));

    std::vector<std::uint8_t> out;
    CHECK(binary.Read(0, 4, out));
    CHECK_EQ(out[1], std::uint8_t{ 0xAA });
    CHECK_EQ(out[2], std::uint8_t{ 0xBB });

    std::remove(path.c_str());
}

LATTIC_TEST(Binary, AppendAndResize)
{
    const std::string path = WriteTemp("test_binary_append.bin", { 1, 2, 3, 4 });

    Binary binary;
    CHECK(binary.Load(path));

    const std::uint8_t extra[] = { 9, 9 };
    CHECK(binary.Append(extra, 2));
    CHECK_EQ(binary.Size(), std::size_t{ 6 });

    CHECK(binary.Resize(2));
    CHECK_EQ(binary.Size(), std::size_t{ 2 });

    CHECK(binary.Append(nullptr, 0));

    std::remove(path.c_str());
}

LATTIC_TEST(Binary, UnloadClearsState)
{
    const std::string path = WriteTemp("test_binary_unload.bin", { 1, 2, 3 });

    Binary binary;
    CHECK(binary.Load(path));
    binary.Unload();
    CHECK(!binary.IsLoaded());
    CHECK(binary.IsEmpty());
    CHECK(binary.Path().empty());

    std::remove(path.c_str());
}
