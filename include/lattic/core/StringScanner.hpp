#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"

namespace lattic::core
{
enum class StringEncoding : std::uint8_t
{
    Ascii,
    Utf16
};

struct StringCandidate
{
    std::uint32_t  rva        = 0;
    std::uint32_t  fileOffset = 0;
    std::uint32_t  byteLength = 0;
    std::uint16_t  charLength = 0;
    StringEncoding encoding   = StringEncoding::Ascii;
    std::string    section;
};

struct ScanOptions
{
    std::size_t minLength = 6;
    std::size_t maxLength = 4096;

    bool includeUtf16                = true;
    bool includeExecutableSections   = false;
};

struct ScanReport
{
    bool        success = false;
    std::string message;

    std::size_t bytesScanned        = 0;
    std::size_t candidates          = 0;
    std::size_t skippedProtected    = 0;
    std::size_t skippedDuplicate    = 0;
};

class StringScanner
{
public:
    StringScanner() = default;
    ~StringScanner() = default;

    StringScanner(const StringScanner&)            = delete;
    StringScanner& operator=(const StringScanner&) = delete;

    // Walks every eligible section and records null-terminated printable runs. Import and
    // export directory data is never reported: the loader reads those before any code runs,
    // so encrypting them turns a loadable image into an unloadable one.
    ScanReport Scan(const Binary& binary, const PeParser& parser, const ScanOptions& options);

    const std::vector<StringCandidate>& Candidates() const;
    void Clear();

    const std::string& LastError() const;

private:
    struct ProtectedRange
    {
        std::uint32_t rva  = 0;
        std::uint32_t size = 0;
    };

    void CollectProtectedRanges(const PeParser& parser);
    bool IsProtected(std::uint32_t rva, std::uint32_t length) const;

    // Both take an explicit limit rather than the image size, so the section walk is
    // bounded by data already validated against the loaded image.
    void ScanAsciiRun(const std::uint8_t* data, std::size_t start, std::size_t limit,
                      const Section& section);
    void ScanUtf16Run(const std::uint8_t* data, std::size_t start, std::size_t limit,
                      const Section& section);

    void AddCandidate(StringCandidate candidate);
    void Deduplicate();

    static bool IsPrintableByte(std::uint8_t c);

    std::size_t m_minLength = 6;
    std::size_t m_maxLength = 4096;
    std::size_t m_skippedProtected = 0;

    std::vector<StringCandidate> m_candidates;
    std::vector<ProtectedRange>  m_protected;
    std::string                  m_lastError;
};
}
