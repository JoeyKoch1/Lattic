#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/StringScanner.hpp"

namespace lattic::core
{
class Patcher
{
public:
    struct Options
    {
        bool stripDebugInfo   = false;
        bool encryptStrings   = false;
        bool preserveChecksum = true;

        // Strings to encrypt. Ignored unless encryptStrings is set. An empty list means
        // every candidate the scanner finds.
        std::vector<StringCandidate> strings;

        // Pads the output out to this many bytes by appending a zero filled section. Zero
        // disables padding. A target smaller than the current size is ignored rather than
        // truncating the file.
        std::size_t targetFileSize = 0;
    };

    struct Report
    {
        std::string error;

        std::size_t bytesWritten       = 0;
        std::size_t patchesApplied     = 0;
        bool        debugInfoStripped  = false;
        bool        checksumUpdated    = false;

        std::size_t stringsEncrypted = 0;
        bool        stringsEncryptedApplied = false;

        std::size_t bytesPadded  = 0;
        bool        paddingApplied = false;
    };

    struct StagedPatch
    {
        std::uint64_t             va     = 0;
        std::uint32_t             offset = 0;
        std::vector<std::uint8_t> bytes;
    };

    Patcher(Binary& binary, const PeParser& parser);
    ~Patcher() = default;

    Patcher(const Patcher&)            = delete;
    Patcher& operator=(const Patcher&) = delete;

    // Resolves the virtual address against the parsed image and records the write.
    bool Stage(std::uint64_t va, const std::vector<std::uint8_t>& bytes);

    void ClearStaged();
    std::size_t StagedCount() const;

    const std::vector<StagedPatch>& Staged() const;

    // Drops the staged write at this virtual address. Returns false when none matches.
    bool Unstage(std::uint64_t va);

    // Writes every staged patch into the in-memory image, applies the requested header
    // transforms, then saves to outputPath.
    bool Apply(const std::string& outputPath, const Options& options, Report& report);

    const std::string& LastError() const;

private:
    struct HeaderOffsets
    {
        std::size_t coff         = 0;
        std::size_t optional     = 0;
        std::size_t directories  = 0;
        std::uint32_t dirCount   = 0;
    };

    bool WriteStaged(Report& report);
    bool EncryptStrings(const std::vector<StringCandidate>& strings, Report& report);
    bool StripDebugInfo();
    bool UpdateChecksum();

    // Appends a zero filled section so the file reaches options.targetFileSize.
    bool PadToSize(std::size_t targetSize, Report& report);

    bool ResolveHeaderOffsets(HeaderOffsets& out) const;
    std::uint32_t ComputeChecksum(std::size_t checksumOffset) const;

    void SetError(std::string message);
    void ClearError();

    Binary&         m_binary;
    const PeParser& m_parser;

    std::vector<StagedPatch> m_staged;
    std::string               m_lastError;
};
}
