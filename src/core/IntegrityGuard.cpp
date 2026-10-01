#include "lattic/core/IntegrityGuard.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <sstream>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

namespace lattic::core
{
namespace
{
// FNV-1a. Chosen because it needs no table and no dependency, and because the digest only
// has to detect accidental and casual modification, not withstand an adversary who is
// choosing which bytes to change.
constexpr std::uint32_t kFnvOffset = 0x811C9DC5u;
constexpr std::uint32_t kFnvPrime  = 0x01000193u;

std::uint32_t Fnv1a(std::uint32_t hash, const std::uint8_t* data, std::size_t size)
{
    for (std::size_t i = 0; i < size; ++i)
    {
        hash ^= static_cast<std::uint32_t>(data[i]);
        hash *= kFnvPrime;
    }

    return hash;
}

bool IsIgnored(std::uint32_t rva, const std::vector<std::uint32_t>& ignored)
{
    return std::find(ignored.begin(), ignored.end(), rva) != ignored.end();
}
}

std::uint32_t IntegrityGuard::ComputeDigest(const Binary& binary, const PeParser& parser,
                                            const std::vector<std::uint32_t>& ignoredRvas)
{
    if (!parser.IsParsed() || binary.Size() == 0)
    {
        return 0;
    }

    std::uint32_t hash = kFnvOffset;

    const auto& sections = parser.Sections();

    for (const auto& section : sections)
    {
        // Relocations and exports are legitimately different between builds of the same
        // source, so they are not covered by the digest.
        if (IsIgnored(section.virtualAddress, ignoredRvas))
        {
            continue;
        }

        if (section.rawSize == 0 || section.rawOffset >= binary.Size())
        {
            continue;
        }

        const std::size_t available = binary.Size() - section.rawOffset;
        const std::size_t length    = section.rawSize < available ? section.rawSize : available;

        if (length == 0)
        {
            continue;
        }

        // The section name is folded in too, so renaming a section is caught.
        for (const char c : section.name)
        {
            hash ^= static_cast<std::uint32_t>(static_cast<unsigned char>(c));
            hash *= kFnvPrime;
        }

        hash = Fnv1a(hash, binary.Data() + section.rawOffset, length);
    }

    return hash;
}

IntegrityReport IntegrityGuard::Verify(const Binary& binary, const PeParser& parser,
                                       std::uint32_t expected, const IntegrityOptions& options)
{
    IntegrityReport report;
    report.expected = expected;
    report.actual   = ComputeDigest(binary, parser, options.ignoredRvas);

    // An expected digest of zero means packing never recorded one, which is not evidence of
    // tampering.
    if (expected == 0)
    {
        report.intact  = true;
        report.message = "No integrity digest was recorded";
        return report;
    }

    report.intact = (report.actual == expected);

    if (report.intact)
    {
        report.message = "Image is intact";
        return report;
    }

    std::ostringstream oss;
    oss << "Integrity check failed: expected " << std::hex << expected
        << " but the image digest is " << report.actual;
    report.message = oss.str();

    util::Logger::Error(report.message);

    switch (options.response)
    {
    case TamperResponse::Ignore:
        return report;

    case TamperResponse::Dialog:
        ::MessageBoxA(nullptr, options.dialogMessage.c_str(),
                      options.dialogTitle.c_str(),
                      MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        break;

    case TamperResponse::Terminate:
        break;
    }

    ::ExitProcess(options.exitCode);

    return report;
}

const char* IntegrityGuard::ResponseName(TamperResponse response)
{
    switch (response)
    {
    case TamperResponse::Ignore:     return "Ignore";
    case TamperResponse::Dialog: return "Dialog";
    case TamperResponse::Terminate:  return "Terminate";
    default:                         return "Unknown";
    }
}
}
