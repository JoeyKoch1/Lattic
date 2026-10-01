#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace lattic::core
{
class Binary;
class PeParser;
class Patcher;
}

namespace lattic
{
inline constexpr int         kVersionMajor = 0;
inline constexpr int         kVersionMinor = 1;
inline constexpr int         kVersionPatch = 0;
inline constexpr const char* kVersionString = "0.1.0";

struct PatchOptions
{
    bool stripDebugInfo   = false;
    bool encryptStrings   = false;
    bool preserveChecksum = true;
    bool backupOnSave     = true;

    // Pads the output to exactly this many bytes by appending a zero filled section.
    // Zero disables padding. A value at or below the current size is ignored, because
    // reaching it would mean truncating the file.
    std::size_t targetFileSize = 0;
};

struct StringInfo
{
    std::uint32_t rva        = 0;
    std::uint32_t byteLength = 0;
    std::uint32_t fileOffset = 0;
    bool          utf16      = false;
    std::string   section;
    std::string   preview;
};

struct SectionInfo
{
    std::string   name;
    std::uint32_t rva          = 0;
    std::uint32_t virtualSize  = 0;
    std::uint32_t rawOffset    = 0;
    std::uint32_t rawSize      = 0;
    std::uint32_t characteristics = 0;

    bool Readable() const;
    bool Writable() const;
    bool Executable() const;
};

struct ImportInfo
{
    std::string              dllName;
    std::vector<std::string> functions;
};

struct ExportInfo
{
    std::string   name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva     = 0;
};

struct StagedInfo
{
    std::uint64_t va     = 0;
    std::uint32_t offset = 0;
    std::size_t   length = 0;
    std::string   section;
    std::string   preview;
};

struct PatchResult
{
    bool        success    = false;
    std::string message;
    std::size_t bytesWritten = 0;
    std::size_t patchesApplied = 0;
    std::size_t stringsEncrypted = 0;
    std::size_t bytesPadded    = 0;
};

struct FeatureIntensity
{
    bool enabled = false;

    // Percentage of eligible sites to touch, 0 to 100. Zero with enabled set still does the
    // minimum, which for most passes means nothing at all.
    int  rate = 50;

    // False makes the pass deterministic: same input, same output.
    bool randomize = true;

    std::uint32_t seed = 0;
};

struct NetworkFinding
{
    enum class Kind
    {
        Dll,        // a networking library the binary imports
        Function,   // a networking API the binary imports
        Url,        // a URL literal
        Host,       // a bare hostname
        Path,       // an API path or route literal
        Header,     // an HTTP header name or value
        JsonKey     // a JSON field name
    };

    Kind        kind = Kind::Url;
    std::string value;
    std::string section;
    std::uint32_t rva = 0;
};

class Lattic
{
public:
    Lattic();
    ~Lattic();

    Lattic(const Lattic&)            = delete;
    Lattic& operator=(const Lattic&) = delete;
    bool LoadBinary(const std::string& path);
    void UnloadBinary();

    bool        IsLoaded() const;
    std::string LoadedPath() const;

    std::size_t StringCandidateCount() const;

    const std::vector<StringInfo>& StringCandidates() const;

    // Re-runs the scanner with a different minimum length and returns the new count.
    std::size_t RescanStrings(std::size_t minLength, std::size_t maxLength);

    // Chooses which candidates a later patch encrypts. An empty list means all of them.
    // Records intent only; nothing is written until ApplyAndSave runs.
    bool SelectStrings(const std::vector<std::uint32_t>& rvas);

    const std::vector<std::uint32_t>& SelectedStrings() const;

    std::size_t StagedPatchCount() const;

    const std::vector<StagedInfo>& StagedPatches() const;

    bool UnstagePatch(std::uint64_t va);

    // Rebuilds these on every call, so the reference stays valid only until the next one.
    const std::vector<SectionInfo>& Sections() const;
    const std::vector<ImportInfo>&  Imports() const;
    const std::vector<ExportInfo>&  Exports() const;

    // Empty string means safe to patch, otherwise the reason not to. A binary Lattic has
    // already touched is refused, because a second pass would append a duplicate section
    // at the same RVA.
    std::string DetectPacking();

    // True only after DetectPacking has run on the currently loaded binary.
    bool AlreadyPacked() const;

    std::vector<std::string> PackingSignatures() const;

    std::size_t CurrentFileSize() const;

    // Reads the image only: imported networking libraries and APIs, plus the string literals
    // that look like URLs, hosts, API paths, HTTP headers or JSON keys. Nothing here
    // observes live traffic.
    const std::vector<NetworkFinding>& NetworkSurface();

    // Selects only the URL, host, path, header and JSON findings for string encryption,
    // leaving the import names and everything else alone.
    bool SelectNetworkStrings();

    std::uint64_t ImageBase() const;
    std::uint32_t EntryPointRva() const;

    // Reads length bytes at a virtual address. Returns false when the address is unmapped
    // or the read would run past the end of the image.
    bool ReadAt(std::uint64_t va, std::size_t length, std::vector<std::uint8_t>& out) const;

    bool StagePatch(std::uint64_t va, const std::vector<std::uint8_t>& bytes);

    void ClearStagedPatches();

    PatchResult ApplyAndSave(const std::string& outputPath, const PatchOptions& options);

    const std::string& LastError() const;

    static const char* Version();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
}