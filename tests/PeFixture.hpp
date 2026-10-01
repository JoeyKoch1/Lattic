#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// Builds a small but structurally valid PE32+ image in memory. Enough for the parser,
// the signature scanner and the patcher to work against real headers and section data.
namespace lattic::test
{
struct PeImage
{
    std::vector<std::uint8_t> bytes;

    // PE32+ image base. Held as the low 32 bits because every address in the fixtures
    // stays well below 4 GiB and PeParser reports it as a 64 bit value.
    std::uint32_t imageBase   = 0x400000u;
    std::uint32_t entryRva    = 0x1000;
    std::uint32_t textRva     = 0x1000;
    std::uint32_t textRawSize = 0x200;
    std::uint32_t textRawOff  = 0x400;
    std::uint32_t rdataRva    = 0x2000;
    std::uint32_t rdataRawOff = 0x600;
    std::uint32_t rdataRawSize = 0x200;

    std::uint64_t TextVa() const
    {
        return imageBase + textRva;
    }

    std::uint64_t RdataVa() const
    {
        return imageBase + rdataRva;
    }
};

inline void PutU16(std::vector<std::uint8_t>& out, std::size_t offset, std::uint16_t value)
{
    out[offset]     = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

inline void PutU32(std::vector<std::uint8_t>& out, std::size_t offset, std::uint32_t value)
{
    for (int i = 0; i < 4; ++i)
    {
        out[offset + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

inline void PutU64(std::vector<std::uint8_t>& out, std::size_t offset, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i)
    {
        out[offset + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

inline void PutName(std::vector<std::uint8_t>& out, std::size_t offset, const char* name)
{
    std::memcpy(out.data() + offset, name, 8);
}

inline PeImage BuildPeImage()
{
    constexpr std::size_t kDosSize    = 0x80;
    constexpr std::size_t kHeadersEnd = 0x400;
    constexpr std::size_t kTotal      = 0x800;

    PeImage image;
    image.bytes.assign(kTotal, 0xCC);

    image.bytes[0] = 'M';
    image.bytes[1] = 'Z';
    PutU32(image.bytes, 0x3C, static_cast<std::uint32_t>(kDosSize));

    const std::size_t coff      = kDosSize + 4;
    const std::size_t opt       = coff + 20;
    const std::size_t sectTable = opt + 240;

    PutU32(image.bytes, kDosSize, 0x00004550);

    PutU16(image.bytes, coff + 0, 0x8664);
    PutU16(image.bytes, coff + 2, 2);
    PutU16(image.bytes, coff + 16, 240);
    PutU16(image.bytes, coff + 18, 0x0022);

    PutU16(image.bytes, opt + 0, 0x020B);
    PutU16(image.bytes, opt + 2, 14);
    PutU32(image.bytes, opt + 4, image.textRawSize + image.rdataRawSize);
    PutU32(image.bytes, opt + 16, image.entryRva);
    PutU64(image.bytes, opt + 24, image.imageBase);
    PutU32(image.bytes, opt + 32, 0x1000);
    PutU32(image.bytes, opt + 36, 0x200);
    PutU32(image.bytes, opt + 56, 0x3000);
    PutU32(image.bytes, opt + 60, static_cast<std::uint32_t>(kHeadersEnd));
    PutU32(image.bytes, opt + 64, 0);
    PutU16(image.bytes, opt + 68, 3);
    PutU32(image.bytes, opt + 108, 16);

    // Debug directory points into .rdata so the strip path has something real to clear.
    PutU32(image.bytes, opt + 112 + 6 * 8, image.rdataRva);
    PutU32(image.bytes, opt + 112 + 6 * 8 + 4, 0x40);

    PutName(image.bytes, sectTable, ".text");
    PutU32(image.bytes, sectTable + 8, image.textRawSize);
    PutU32(image.bytes, sectTable + 12, image.textRva);
    PutU32(image.bytes, sectTable + 16, image.textRawSize);
    PutU32(image.bytes, sectTable + 20, image.textRawOff);
    PutU32(image.bytes, sectTable + 36, 0x60000020);

    PutName(image.bytes, sectTable + 40, ".rdata");
    PutU32(image.bytes, sectTable + 40 + 8, image.rdataRawSize);
    PutU32(image.bytes, sectTable + 40 + 12, image.rdataRva);
    PutU32(image.bytes, sectTable + 40 + 16, image.rdataRawSize);
    PutU32(image.bytes, sectTable + 40 + 20, image.rdataRawOff);
    PutU32(image.bytes, sectTable + 40 + 36, 0x40000040);

    const char* marker = "LATTIC_TEST_MARKER_STRING";
    std::memcpy(image.bytes.data() + image.rdataRawOff, marker, std::strlen(marker) + 1);

    // A COFF symbol table pointer so stripDebugInfo has something to zero out.
    PutU32(image.bytes, coff + 8, 0x200);
    PutU32(image.bytes, coff + 12, 3);

    return image;
}

inline std::string WriteTempFile(const PeImage& image, const std::string& name)
{
    const std::string path = name;

    std::FILE* file = std::fopen(path.c_str(), "wb");

    if (file == nullptr)
    {
        return {};
    }

    std::fwrite(image.bytes.data(), 1, image.bytes.size(), file);
    std::fclose(file);
    return path;
}
}
