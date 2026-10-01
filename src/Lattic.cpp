#include "lattic/Lattic.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string_view>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PackerDetector.hpp"
#include "lattic/core/Patcher.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/StringEncryptor.hpp"
#include "lattic/core/StringScanner.hpp"
#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

namespace lattic
{
struct Lattic::Impl
{
    std::unique_ptr<core::Binary>  binary;
    std::unique_ptr<core::PeParser> parser;
    std::unique_ptr<core::Patcher>  patcher;

    std::string loadedPath;
    std::string lastError;

    bool        loaded = false;
    std::size_t stringCandidates = 0;

    std::vector<StringInfo>    candidates;
    std::vector<StagedInfo>    stagedView;
    std::vector<std::uint32_t> selected;

    std::vector<SectionInfo> sections;
    std::vector<ImportInfo>  imports;
    std::vector<ExportInfo>  exports;

    core::DetectionReport detection;
    bool                  detectionRun = false;

    std::vector<NetworkFinding> network;

    std::size_t minStringLength = 6;
    std::size_t maxStringLength = 4096;

    void SetError(const std::string& msg)
    {
        lastError = msg;
        util::Logger::Error(msg);
    }

    void ClearError()
    {
        lastError.clear();
    }

    // Reads a bounded window of a candidate and renders it for display. The reported length
    // is never trusted, so a corrupt length cannot read past the loaded image.
    static std::string Preview(const core::Binary& binary,
                               const core::StringCandidate& candidate)
    {
        constexpr std::size_t kMaxPreview = 96;

        if (!binary.InBounds(candidate.fileOffset, candidate.byteLength))
        {
            return "<out of bounds>";
        }

        const std::uint8_t* at = binary.Data() + candidate.fileOffset;
        const std::size_t   len = candidate.byteLength;

        if (candidate.encoding == core::StringEncoding::Utf16)
        {
            std::string wide;

            for (std::size_t i = 0; i < len / 2 && wide.size() < kMaxPreview; ++i)
            {
                const std::uint8_t lo = at[i * 2];

                if (lo >= 0x20 && lo < 0x7F)
                {
                    wide.push_back(static_cast<char>(lo));
                }
            }

            return util::str::Ellipsize(wide, kMaxPreview);
        }

        const std::string_view narrow(reinterpret_cast<const char*>(at), len);
        return util::str::Ellipsize(util::str::Printable(narrow), kMaxPreview);
    }

    // Maps the selected RVAs back onto fresh scanner results. An empty selection means
    // every candidate. Re-scanning here rather than caching offsets keeps the file offsets
    // valid even after a patch changed the image.
    std::vector<core::StringCandidate> ResolveSelection(
        const std::vector<std::uint32_t>& rvas) const
    {
        std::vector<core::StringCandidate> resolved;

        if (!loaded || !binary || !parser)
        {
            return resolved;
        }

        core::StringScanner scanner;

        core::ScanOptions options;
        options.minLength    = minStringLength;
        options.maxLength    = maxStringLength;
        options.includeUtf16 = true;

        scanner.Scan(*binary, *parser, options);

        if (rvas.empty())
        {
            return scanner.Candidates();
        }

        for (std::uint32_t rva : rvas)
        {
            const auto it = std::find_if(scanner.Candidates().begin(), scanner.Candidates().end(),
                                         [rva](const core::StringCandidate& c)
                                         { return c.rva == rva; });

            if (it != scanner.Candidates().end())
            {
                resolved.push_back(*it);
            }
        }

        return resolved;
    }

    void Rescan()
    {
        candidates.clear();

        if (!loaded || !parser || !binary)
        {
            stringCandidates = 0;
            return;
        }

        core::StringScanner scanner;

        core::ScanOptions options;
        options.minLength    = minStringLength;
        options.maxLength    = maxStringLength;
        options.includeUtf16 = true;

        scanner.Scan(*binary, *parser, options);

        for (const auto& candidate : scanner.Candidates())
        {
            StringInfo info;
            info.rva        = candidate.rva;
            info.byteLength = candidate.byteLength;
            info.fileOffset = candidate.fileOffset;
            info.utf16      = candidate.encoding == core::StringEncoding::Utf16;
            info.section    = candidate.section;
            info.preview    = Preview(*binary, candidate);
            candidates.push_back(std::move(info));
        }

        stringCandidates = candidates.size();
    }
};

Lattic::Lattic() : m_impl(std::make_unique<Impl>())
{
    util::Logger::Info(std::string("Lattic core ") + Version() + " constructed");
}

Lattic::~Lattic()
{
    UnloadBinary();
}

const char* Lattic::Version()
{
    return kVersionString;
}

bool Lattic::LoadBinary(const std::string& path)
{
    m_impl->ClearError();

    if (path.empty())
    {
        m_impl->SetError("LoadBinary called with an empty path");
        return false;
    }

    UnloadBinary();

    auto binary = std::make_unique<core::Binary>();
    if (!binary->Load(path))
    {
        m_impl->SetError("Failed to load binary: " + path);
        return false;
    }

    auto parser = std::make_unique<core::PeParser>();
    if (!parser->Parse(*binary))
    {
        m_impl->SetError("Failed to parse PE headers: " + path);
        return false;
    }

    auto patcher = std::make_unique<core::Patcher>(*binary, *parser);

    m_impl->detectionRun = false;

    m_impl->binary     = std::move(binary);
    m_impl->parser     = std::move(parser);
    m_impl->patcher    = std::move(patcher);
    m_impl->loadedPath = path;
    m_impl->loaded     = true;

    m_impl->Rescan();

    std::ostringstream oss;
    oss << "Loaded " << path << " (" << m_impl->stringCandidates << " string candidates)";
    util::Logger::Info(oss.str());

    return true;
}

void Lattic::UnloadBinary()
{
    if (m_impl->patcher)
    {
        m_impl->patcher->ClearStaged();
    }

    m_impl->patcher.reset();
    m_impl->parser.reset();
    m_impl->binary.reset();

    m_impl->candidates.clear();
    m_impl->selected.clear();
    m_impl->loadedPath.clear();
    m_impl->loaded           = false;
    m_impl->stringCandidates = 0;

    // The previous file's verdict must not outlive it, or AlreadyPacked would keep reporting
    // the last binary that happened to be open.
    m_impl->detection     = core::DetectionReport{};
    m_impl->detectionRun  = false;
}

bool Lattic::IsLoaded() const
{
    return m_impl->loaded;
}

std::string Lattic::LoadedPath() const
{
    return m_impl->loadedPath;
}

std::size_t Lattic::StringCandidateCount() const
{
    return m_impl->stringCandidates;
}

const std::vector<StringInfo>& Lattic::StringCandidates() const
{
    return m_impl->candidates;
}

std::size_t Lattic::RescanStrings(std::size_t minLength, std::size_t maxLength)
{
    m_impl->ClearError();

    if (!m_impl->loaded)
    {
        m_impl->SetError("RescanStrings called with no binary loaded");
        return 0;
    }

    m_impl->minStringLength = minLength == 0 ? 1 : minLength;
    m_impl->maxStringLength = maxLength == 0 ? 4096 : maxLength;
    m_impl->Rescan();

    return m_impl->stringCandidates;
}

bool Lattic::SelectStrings(const std::vector<std::uint32_t>& rvas)
{
    m_impl->ClearError();

    if (!m_impl->loaded)
    {
        m_impl->SetError("SelectStrings called with no binary loaded");
        return false;
    }

    for (std::uint32_t rva : rvas)
    {
        const bool known = std::any_of(m_impl->candidates.begin(), m_impl->candidates.end(),
                                       [rva](const StringInfo& info) { return info.rva == rva; });

        if (!known)
        {
            std::ostringstream oss;
            oss << "No string candidate at RVA " << util::str::FormatVA(rva);
            m_impl->SetError(oss.str());
            return false;
        }
    }

    m_impl->selected = rvas;
    return true;
}

const std::vector<std::uint32_t>& Lattic::SelectedStrings() const
{
    return m_impl->selected;
}

std::size_t Lattic::StagedPatchCount() const
{
    if (!m_impl->patcher)
    {
        return 0;
    }
    return m_impl->patcher->StagedCount();
}

const std::vector<StagedInfo>& Lattic::StagedPatches() const
{
    m_impl->stagedView.clear();

    if (!m_impl->patcher || !m_impl->parser)
    {
        return m_impl->stagedView;
    }

    for (const auto& patch : m_impl->patcher->Staged())
    {
        StagedInfo info;
        info.va     = patch.va;
        info.offset = patch.offset;
        info.length = patch.bytes.size();

        const std::uint64_t imageBase = m_impl->parser->ImageBase();

        // Subtracting an unsigned va below the image base wraps to near 2^64 and truncates
        // into a nonsense RVA, which then gets looked up in the section table.
        const std::uint32_t patchRva =
            (patch.va >= imageBase && patch.va - imageBase <= 0xFFFFFFFFull)
                ? static_cast<std::uint32_t>(patch.va - imageBase)
                : 0u;

        if (const core::Section* section = m_impl->parser->SectionContainingRva(patchRva))
        {
            info.section = section->name;
        }

        info.preview = util::str::BytesToHexSpaced(patch.bytes);

        m_impl->stagedView.push_back(std::move(info));
    }

    return m_impl->stagedView;
}

bool Lattic::UnstagePatch(std::uint64_t va)
{
    m_impl->ClearError();

    if (!m_impl->patcher)
    {
        m_impl->SetError("UnstagePatch called with no binary loaded");
        return false;
    }

    if (!m_impl->patcher->Unstage(va))
    {
        m_impl->SetError(m_impl->patcher->LastError());
        return false;
    }

    return true;
}

bool SectionInfo::Readable() const
{
    return (characteristics & 0x40000000u) != 0;
}

bool SectionInfo::Writable() const
{
    return (characteristics & 0x80000000u) != 0;
}

bool SectionInfo::Executable() const
{
    return (characteristics & 0x20000000u) != 0;
}

const std::vector<SectionInfo>& Lattic::Sections() const
{
    m_impl->sections.clear();

    if (!m_impl->parser || !m_impl->parser->IsParsed())
    {
        return m_impl->sections;
    }

    for (const auto& section : m_impl->parser->Sections())
    {
        SectionInfo info;
        info.name             = section.name;
        info.rva              = section.virtualAddress;
        info.virtualSize      = section.virtualSize;
        info.rawOffset        = section.rawOffset;
        info.rawSize          = section.rawSize;
        info.characteristics  = section.characteristics;
        m_impl->sections.push_back(std::move(info));
    }

    return m_impl->sections;
}

const std::vector<ImportInfo>& Lattic::Imports() const
{
    m_impl->imports.clear();

    if (!m_impl->parser || !m_impl->parser->IsParsed())
    {
        return m_impl->imports;
    }

    for (const auto& import : m_impl->parser->Imports())
    {
        ImportInfo info;
        info.dllName = import.dllName;
        info.functions = import.functions;
        m_impl->imports.push_back(std::move(info));
    }

    return m_impl->imports;
}

const std::vector<ExportInfo>& Lattic::Exports() const
{
    m_impl->exports.clear();

    if (!m_impl->parser || !m_impl->parser->IsParsed())
    {
        return m_impl->exports;
    }

    for (const auto& entry : m_impl->parser->Exports())
    {
        ExportInfo info;
        info.name    = entry.name;
        info.ordinal = entry.ordinal;
        info.rva     = entry.rva;
        m_impl->exports.push_back(std::move(info));
    }

    return m_impl->exports;
}

std::uint64_t Lattic::ImageBase() const
{
    return m_impl->parser ? m_impl->parser->ImageBase() : 0;
}

std::string Lattic::DetectPacking()
{
    // The UI asks for this every frame, so the analysis is cached until the binary changes.
    // Re-running it per frame produced a log line per frame per signature.
    if (m_impl->detectionRun)
    {
        return core::PackerDetector::BlockRepatch(m_impl->detection);
    }

    if (!m_impl->binary || !m_impl->binary->IsLoaded() ||
        !m_impl->parser   || !m_impl->parser->IsParsed())
    {
        return "No binary loaded";
    }

    m_impl->detection    = core::PackerDetector::Analyze(*m_impl->binary, *m_impl->parser);
    m_impl->detectionRun = true;

    util::Logger::Info("PackerDetector: " + m_impl->detection.summary);

    // A Lattic signature is a hard stop. Other packers are reported so the user can decide,
    // but they do not block, because a file may legitimately carry more than one tool's
    // residue.
    return core::PackerDetector::BlockRepatch(m_impl->detection);
}

bool Lattic::AlreadyPacked() const
{
    return m_impl->detection.alreadyLattic;
}

std::vector<std::string> Lattic::PackingSignatures() const
{
    std::vector<std::string> list;

    for (const auto& signal : m_impl->detection.all)
    {
        list.push_back(std::string(core::PackerDetector::KindName(signal.kind)) +
                       ": " + signal.evidence + " (" + signal.description + ")");
    }

    return list;
}

std::size_t Lattic::CurrentFileSize() const
{
    return (m_impl->binary && m_impl->binary->IsLoaded()) ? m_impl->binary->Size() : 0;
}

namespace
{
bool StartsWith(const std::string& text, const char* prefix)
{
    return text.rfind(prefix, 0) == 0;
}

bool EndsWith(const std::string& text, const char* suffix)
{
    const std::size_t length = std::strlen(suffix);

    return text.size() >= length &&
           text.compare(text.size() - length, length, suffix) == 0;
}

bool LooksLikeUrl(const std::string& text)
{
    return StartsWith(text, "http://") || StartsWith(text, "https://") ||
           StartsWith(text, "ws://")  || StartsWith(text, "wss://") ||
           StartsWith(text, "ftp://");
}

bool LooksLikeHost(const std::string& text)
{
    // Deliberately conservative: a false positive here becomes an encrypted string the
    // user did not expect.
    if (text.size() < 6 || text.find(' ') != std::string::npos || text.find('/') != std::string::npos)
    {
        return false;
    }

    const std::size_t lastDot = text.rfind('.');

    if (lastDot == std::string::npos || lastDot + 2 > text.size())
    {
        return false;
    }

    const std::string tld = text.substr(lastDot + 1);

    for (const char c : tld)
    {
        const bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!alpha)
        {
            return false;
        }
    }

    return tld.size() >= 2 && tld.size() <= 4 && text.find("..") == std::string::npos;
}

bool LooksLikePath(const std::string& text)
{
    return StartsWith(text, "/api/") || StartsWith(text, "/v1/") || StartsWith(text, "/v2/") ||
           StartsWith(text, "/auth") || StartsWith(text, "/login") ||
           EndsWith(text, "/login")   || EndsWith(text, "/token") ||
           StartsWith(text, "/graphql");
}

bool LooksLikeHeader(const std::string& text)
{
    static const char* kHeaders[] =
    {
        "Content-Type", "Authorization", "Bearer", "application/json", "text/plain",
        "User-Agent", "Accept", "X-API", "X-Auth", "Cache-Control"
    };

    for (const char* header : kHeaders)
    {
        if (text.find(header) != std::string::npos)
        {
            return true;
        }
    }

    return false;
}

bool LooksLikeJsonKey(const std::string& text)
{
    if (text.size() < 4 || text.front() != '"' || text.back() != '"')
    {
        return false;
    }

    return text.find("\":") != std::string::npos || text.find("\": ") != std::string::npos;
}

const char* kNetworkDlls[] =
{
    "winhttp.dll", "wininet.dll", "ws2_32.dll", "wsock32.dll", "winsock.dll",
    "mswsock.dll", "iphlpapi.dll", "dnsapi.dll", "netapi32.dll", "secur32.dll",
    "crypt32.dll", "bcrypt.dll"
};
}

const std::vector<NetworkFinding>& Lattic::NetworkSurface()
{
    m_impl->network.clear();

    if (!m_impl->loaded || !m_impl->parser || !m_impl->parser->IsParsed())
    {
        return m_impl->network;
    }

    // Imports first: a networking DLL in the table is the strongest single hint that the
    // binary talks to a server at all.
    for (const auto& import : m_impl->parser->Imports())
    {
        const bool isNetworkDll =
            std::find(std::begin(kNetworkDlls), std::end(kNetworkDlls), import.dllName) !=
            std::end(kNetworkDlls);

        if (!isNetworkDll)
        {
            continue;
        }

        NetworkFinding dll;
        dll.kind  = NetworkFinding::Kind::Dll;
        dll.value = import.dllName;
        m_impl->network.push_back(std::move(dll));

        for (const auto& fn : import.functions)
        {
            NetworkFinding entry;
            entry.kind  = NetworkFinding::Kind::Function;
            entry.value = import.dllName + "!" + fn;
            m_impl->network.push_back(std::move(entry));
        }
    }

    const auto& candidates = StringCandidates();

    for (const auto& info : candidates)
    {
        const std::string& text = info.preview;

        NetworkFinding::Kind kind = NetworkFinding::Kind::Url;
        bool                  matched = false;

        if (LooksLikeUrl(text))         { kind = NetworkFinding::Kind::Url;    matched = true; }
        else if (LooksLikeHost(text))   { kind = NetworkFinding::Kind::Host;   matched = true; }
        else if (LooksLikePath(text))   { kind = NetworkFinding::Kind::Path;   matched = true; }
        else if (LooksLikeHeader(text)) { kind = NetworkFinding::Kind::Header; matched = true; }
        else if (LooksLikeJsonKey(text)){ kind = NetworkFinding::Kind::JsonKey; matched = true; }

        if (!matched)
        {
            continue;
        }

        NetworkFinding finding;
        finding.kind     = kind;
        finding.value    = text;
        finding.section  = info.section;
        finding.rva      = info.rva;
        m_impl->network.push_back(std::move(finding));
    }

    return m_impl->network;
}

bool Lattic::SelectNetworkStrings()
{
    NetworkSurface();

    std::vector<std::uint32_t> rvas;

    for (const auto& finding : m_impl->network)
    {
        if (finding.kind == NetworkFinding::Kind::Url    ||
            finding.kind == NetworkFinding::Kind::Host   ||
            finding.kind == NetworkFinding::Kind::Path   ||
            finding.kind == NetworkFinding::Kind::Header ||
            finding.kind == NetworkFinding::Kind::JsonKey)
        {
            rvas.push_back(finding.rva);
        }
    }

    if (rvas.empty())
    {
        m_impl->SetError("No network related strings were found to select");
        return false;
    }

    return SelectStrings(rvas);
}

std::uint32_t Lattic::EntryPointRva() const
{
    return m_impl->parser ? m_impl->parser->EntryPointRva() : 0;
}

bool Lattic::ReadAt(std::uint64_t va, std::size_t length, std::vector<std::uint8_t>& out) const
{
    out.clear();

    if (!m_impl->binary || !m_impl->parser || !m_impl->parser->IsParsed())
    {
        return false;
    }

    std::uint32_t offset = 0;

    if (!m_impl->parser->VaToOffset(va, offset))
    {
        return false;
    }

    return m_impl->binary->Read(offset, length, out);
}

bool Lattic::StagePatch(std::uint64_t va, const std::vector<std::uint8_t>& bytes)
{
    m_impl->ClearError();

    if (!m_impl->loaded || !m_impl->patcher)
    {
        m_impl->SetError("StagePatch called with no binary loaded");
        return false;
    }

    if (bytes.empty())
    {
        m_impl->SetError("StagePatch called with zero length payload");
        return false;
    }

    if (!m_impl->patcher->Stage(va, bytes))
    {
        std::ostringstream oss;
        oss << "StagePatch failed at VA 0x" << std::hex << va;
        m_impl->SetError(oss.str());
        return false;
    }

    return true;
}

void Lattic::ClearStagedPatches()
{
    if (m_impl->patcher)
    {
        m_impl->patcher->ClearStaged();
    }
}

PatchResult Lattic::ApplyAndSave(const std::string& outputPath, const PatchOptions& options)
{
    m_impl->ClearError();

    PatchResult result;

    if (!m_impl->loaded || !m_impl->patcher)
    {
        result.message = "No binary loaded";
        m_impl->SetError(result.message);
        return result;
    }

    const std::string target = outputPath.empty() ? m_impl->loadedPath : outputPath;

    bool warnedAboutPacker = false;

    // Refuse a file Lattic has already packed. Running the encryptor twice appends a second
    // section at the same RVA, which is what produced "no free section header slot" and a
    // binary that would not launch.
    {
        const std::string block = DetectPacking();

        if (!block.empty())
        {
            result.message = block;
            m_impl->SetError(block);
            return result;
        }

        if (m_impl->detection.isPacked)
        {
            warnedAboutPacker = true;
            util::Logger::Warn(m_impl->detection.summary +
                               ": patching anyway, the result may not be reliable");
        }
    }

    if (options.backupOnSave && target == m_impl->loadedPath)
    {
        const std::string backupPath = m_impl->loadedPath + ".bak";
        std::ifstream src(m_impl->loadedPath, std::ios::binary);
        std::ofstream dst(backupPath, std::ios::binary | std::ios::trunc);

        if (!src || !dst)
        {
            result.message = "Failed to create backup at " + backupPath;
            m_impl->SetError(result.message);
            return result;
        }

        dst << src.rdbuf();
        util::Logger::Info("Backup written to " + backupPath);
    }

    core::Patcher::Options patcherOptions;
    patcherOptions.stripDebugInfo   = options.stripDebugInfo;
    patcherOptions.encryptStrings   = options.encryptStrings;
    patcherOptions.preserveChecksum = options.preserveChecksum;
    patcherOptions.targetFileSize   = options.targetFileSize;
    patcherOptions.strings          = m_impl->ResolveSelection(m_impl->selected);

    core::Patcher::Report report;
    if (!m_impl->patcher->Apply(target, patcherOptions, report))
    {
        result.message = report.error.empty() ? "Patcher failed" : report.error;
        m_impl->SetError(result.message);
        return result;
    }

    result.success        = true;
    result.bytesWritten   = report.bytesWritten;
    result.patchesApplied = report.patchesApplied;
    result.stringsEncrypted = report.stringsEncrypted;
    result.bytesPadded    = report.bytesPadded;

    // Patcher::Apply mutated the in-memory image, appending .lattic and rewriting the entry
    // point. The cached verdict describes the pre-patch bytes, so a second ApplyAndSave on
    // this same instance would sail past the repatch guard it exists to enforce.
    m_impl->detectionRun = false;

    result.message = "Patched " + std::to_string(report.patchesApplied) + " region(s)";

    if (report.stringsEncryptedApplied)
    {
        result.message += ", encrypted " + std::to_string(report.stringsEncrypted) + " string(s)";
    }

    if (report.paddingApplied)
    {
        result.message += ", padded to " + std::to_string(options.targetFileSize) +
                          " bytes";
    }

    // The warning from the detection pass belongs in the summary too, otherwise it is
    // lost the moment the log scrolls away.
    if (warnedAboutPacker)
    {
        result.message = "Patched, but " + m_impl->detection.summary +
                         " was detected first";
    }

    std::ostringstream oss;
    oss << "ApplyAndSave complete: " << result.message << " -> " << target;
    util::Logger::Info(oss.str());

    return result;
}

const std::string& Lattic::LastError() const
{
    return m_impl->lastError;
}
}