#include "lattic/core/StringScanner.hpp"

#include <algorithm>

#include "lattic/util/Logger.hpp"

namespace lattic::core
{
namespace
{
constexpr std::size_t kDirImport = 1;
constexpr std::size_t kDirExport = 0;

// A run longer than this is almost always binary data that happens to be printable,
// not a string. Anything past it is skipped rather than reported.
constexpr std::size_t kHardMaxRun = 8192;
}

bool StringScanner::IsPrintableByte(std::uint8_t c)
{
    return c >= 0x20 && c < 0x7F;
}

void StringScanner::CollectProtectedRanges(const PeParser& parser)
{
    const std::size_t dirs[] = { kDirExport, kDirImport };

    for (std::size_t index : dirs)
    {
        const DataDirectory* dir = parser.Directory(index);

        if (dir == nullptr || !dir->Present())
        {
            continue;
        }

        ProtectedRange range;
        range.rva  = dir->rva;
        range.size = dir->size;
        m_protected.push_back(range);
    }
}

bool StringScanner::IsProtected(std::uint32_t rva, std::uint32_t length) const
{
    const std::uint64_t end = static_cast<std::uint64_t>(rva) + length;

    for (const auto& range : m_protected)
    {
        const std::uint64_t rangeEnd = static_cast<std::uint64_t>(range.rva) + range.size;

        if (rva < rangeEnd && end > range.rva)
        {
            return true;
        }
    }

    return false;
}

void StringScanner::AddCandidate(StringCandidate candidate)
{
    m_candidates.push_back(std::move(candidate));
}

void StringScanner::Deduplicate()
{
    // A UTF-16 run is found by the ASCII pass as a run of interleaved nulls only if those
    // nulls are skipped, which they are not, so the two passes cannot overlap. What they
    // can do is report the same run twice when a section is scanned twice, so collapse on
    // the exact (rva, length) pair and keep the widest run when one contains another.
    std::sort(m_candidates.begin(), m_candidates.end(),
              [](const StringCandidate& a, const StringCandidate& b)
              {
                  if (a.rva != b.rva)
                  {
                      return a.rva < b.rva;
                  }
                  return a.byteLength > b.byteLength;
              });

    std::vector<StringCandidate> unique;
    unique.reserve(m_candidates.size());

    for (const auto& candidate : m_candidates)
    {
        const bool duplicate = !unique.empty() && unique.back().rva == candidate.rva &&
                               unique.back().byteLength == candidate.byteLength;

        if (!duplicate)
        {
            unique.push_back(candidate);
        }
    }

    m_candidates = std::move(unique);
}

void StringScanner::ScanAsciiRun(const std::uint8_t* data, std::size_t start, std::size_t limit,
                                 const Section& section)
{
    std::size_t run = 0;
    std::size_t runStart = start;

    for (std::size_t i = start; i < limit; ++i)
    {
        if (IsPrintableByte(data[i]))
        {
            if (run == 0)
            {
                runStart = i;
            }

            ++run;

            if (run > kHardMaxRun)
            {
                run = 0;
            }

            continue;
        }

        if (data[i] == 0x00 && run >= m_minLength && run <= m_maxLength)
        {
            StringCandidate candidate;
            candidate.rva        = section.virtualAddress +
                          static_cast<std::uint32_t>(runStart - section.rawOffset);
            candidate.fileOffset = static_cast<std::uint32_t>(runStart);
            candidate.byteLength = static_cast<std::uint32_t>(run);
            candidate.charLength = static_cast<std::uint16_t>(run);
            candidate.encoding   = StringEncoding::Ascii;
            candidate.section    = section.name;

            if (!IsProtected(candidate.rva, candidate.byteLength))
            {
                AddCandidate(std::move(candidate));
            }
            else
            {
                ++m_skippedProtected;
            }
        }

        run = 0;
    }
}

void StringScanner::ScanUtf16Run(const std::uint8_t* data, std::size_t start, std::size_t limit,
                                 const Section& section)
{
    // Walk on two-byte boundaries. A run ends at the first unit that is not a printable
    // character followed by a zero high byte, or at the UTF-16 null terminator 00 00.
    std::size_t i = start;

    while (i + 1 < limit)
    {
        const bool printable = IsPrintableByte(data[i]) && data[i + 1] == 0x00;

        if (!printable)
        {
            i += 2;
            continue;
        }

        const std::size_t runStart = i;
        std::size_t       chars    = 0;

        while (i + 1 < limit && IsPrintableByte(data[i]) && data[i + 1] == 0x00)
        {
            ++chars;
            i += 2;

            if (chars >= kHardMaxRun)
            {
                break;
            }
        }

        // The run must be followed by a null unit for it to be a real UTF-16 string.
        const bool terminated = (i + 1 < limit) && data[i] == 0x00 && data[i + 1] == 0x00;

        if (terminated && chars >= m_minLength && chars <= m_maxLength)
        {
            StringCandidate candidate;
            candidate.rva        = section.virtualAddress +
                          static_cast<std::uint32_t>(runStart - section.rawOffset);
            candidate.fileOffset = static_cast<std::uint32_t>(runStart);
            candidate.byteLength = static_cast<std::uint32_t>(chars * 2);
            candidate.charLength = static_cast<std::uint16_t>(chars);
            candidate.encoding   = StringEncoding::Utf16;
            candidate.section    = section.name;

            if (!IsProtected(candidate.rva, candidate.byteLength))
            {
                AddCandidate(std::move(candidate));
            }
            else
            {
                ++m_skippedProtected;
            }
        }

        // Skip the terminator so the next iteration does not re-examine it.
        if (terminated)
        {
            i += 2;
        }
    }
}

ScanReport StringScanner::Scan(const Binary& binary, const PeParser& parser,
                               const ScanOptions& options)
{
    Clear();
    m_lastError.clear();

    ScanReport report;

    if (!binary.IsLoaded() || binary.IsEmpty())
    {
        m_lastError = "StringScanner: binary is empty or not loaded";
        report.message = m_lastError;
        return report;
    }

    if (!parser.IsParsed())
    {
        m_lastError = "StringScanner: parser not initialized";
        report.message = m_lastError;
        return report;
    }

    m_minLength      = options.minLength;
    m_maxLength      = options.maxLength;
    m_skippedProtected = 0;

    CollectProtectedRanges(parser);

    const std::uint8_t* data = binary.Data();
    const std::size_t   size = binary.Size();

    for (const auto& section : parser.Sections())
    {
        if (!section.Readable())
        {
            continue;
        }

        if (!options.includeExecutableSections && section.Executable())
        {
            continue;
        }

        if (section.rawSize == 0)
        {
            continue;
        }

        // Section raw data can point past the end of a truncated or hand-crafted file.
        if (section.rawOffset > size || section.rawSize > size - section.rawOffset)
        {
            continue;
        }

        const std::size_t limit = section.rawSize;
        const std::size_t from  = section.rawOffset;

        ScanAsciiRun(data, from, from + limit, section);

        if (options.includeUtf16)
        {
            ScanUtf16Run(data, from, from + limit, section);
        }

        report.bytesScanned += limit;
    }

    const std::size_t before = m_candidates.size();
    Deduplicate();
    report.skippedDuplicate = before - m_candidates.size();
    report.skippedProtected = m_skippedProtected;

    report.candidates = m_candidates.size();
    report.success     = true;
    report.message     = "Found " + std::to_string(m_candidates.size()) + " string candidates";

    util::Logger::Info("StringScanner: " + report.message);
    return report;
}

const std::vector<StringCandidate>& StringScanner::Candidates() const
{
    return m_candidates;
}

void StringScanner::Clear()
{
    m_candidates.clear();
    m_protected.clear();
}

const std::string& StringScanner::LastError() const
{
    return m_lastError;
}
}
