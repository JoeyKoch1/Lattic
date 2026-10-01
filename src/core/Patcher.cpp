#include "lattic/core/Patcher.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "lattic/core/StringEncryptor.hpp"
#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

namespace lattic::core
{
namespace
{
constexpr std::size_t kLfanewOffset      = 0x3C;
constexpr std::size_t kCoffHeaderSize    = 20;
constexpr std::size_t kSignatureSize     = 4;
constexpr std::size_t kChecksumOffset    = 64;
constexpr std::size_t kPe32DirOffset     = 96;
constexpr std::size_t kPe32PlusDirOffset = 112;
constexpr std::size_t kPe32DirCount      = 92;
constexpr std::size_t kPe32PlusDirCount  = 108;
constexpr std::size_t kMaxDirectories    = 16;
constexpr std::size_t kDirDebug          = 6;

constexpr std::size_t kSymbolTableOffsetInCoff = 8;
constexpr std::size_t kSymbolCountOffsetInCoff = 12;

std::uint16_t ReadU16(const std::uint8_t* data, std::size_t size, std::size_t offset)
{
    if (data == nullptr || offset + 2 > size)
    {
        return 0;
    }

    return static_cast<std::uint16_t>(data[offset]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[offset + 1]) << 8);
}

std::uint32_t ReadU32(const std::uint8_t* data, std::size_t size, std::size_t offset)
{
    if (data == nullptr || offset + 4 > size)
    {
        return 0;
    }

    std::uint32_t value = 0;
    std::memcpy(&value, data + offset, sizeof(value));
    return value;
}

void WriteU32(std::uint8_t* data, std::size_t size, std::size_t offset, std::uint32_t value)
{
    if (data == nullptr || offset + 4 > size)
    {
        return;
    }

    std::memcpy(data + offset, &value, sizeof(value));
}
}

Patcher::Patcher(Binary& binary, const PeParser& parser)
    : m_binary(binary), m_parser(parser)
{
}

bool Patcher::Stage(std::uint64_t va, const std::vector<std::uint8_t>& bytes)
{
    ClearError();

    if (bytes.empty())
    {
        SetError("Patcher::Stage called with an empty payload");
        return false;
    }

    if (!m_parser.IsParsed())
    {
        SetError("Patcher::Stage called before the PE was parsed");
        return false;
    }

    std::uint32_t offset = 0;

    if (!m_parser.VaToOffset(va, offset))
    {
        std::ostringstream oss;
        oss << "Staged patch VA is not mapped to file data: " << util::str::FormatVA(va);
        SetError(oss.str());
        return false;
    }

    if (!m_binary.InBounds(offset, bytes.size()))
    {
        std::ostringstream oss;
        oss << "Staged patch at offset 0x" << std::hex << offset << " runs past end of file";
        SetError(oss.str());
        return false;
    }

    // Staying inside the file is not enough. A patch that spills into the next section
    // silently corrupts unrelated data, so the section bounds are enforced separately.
    const std::uint64_t rva = va - m_parser.ImageBase();
    const Section*       section = m_parser.SectionContainingRva(static_cast<std::uint32_t>(rva));

    if (section == nullptr)
    {
        std::ostringstream oss;
        oss << "Staged patch VA is not inside any section: " << util::str::FormatVA(va);
        SetError(oss.str());
        return false;
    }

    const std::uint64_t sectionEnd =
        static_cast<std::uint64_t>(section->rawOffset) + section->rawSize;

    if (offset + bytes.size() > sectionEnd)
    {
        std::ostringstream oss;
        oss << "Staged patch at " << util::str::FormatVA(va) << " crosses the end of section "
            << section->name;
        SetError(oss.str());
        return false;
    }

    for (const auto& existing : m_staged)
    {
        if (existing.offset == offset && existing.bytes == bytes)
        {
            return true;
        }
    }

    StagedPatch patch;
    patch.va     = va;
    patch.offset = offset;
    patch.bytes  = bytes;

    m_staged.push_back(std::move(patch));
    return true;
}

void Patcher::ClearStaged()
{
    m_staged.clear();
}

std::size_t Patcher::StagedCount() const
{
    return m_staged.size();
}

bool Patcher::Unstage(std::uint64_t va)
{
    const auto it = std::find_if(m_staged.begin(), m_staged.end(),
                                 [va](const StagedPatch& p) { return p.va == va; });

    if (it == m_staged.end())
    {
        SetError("Patcher::Unstage: no staged patch at that address");
        return false;
    }

    m_staged.erase(it);
    return true;
}

const std::vector<Patcher::StagedPatch>& Patcher::Staged() const
{
    return m_staged;
}

namespace
{
constexpr std::size_t kNumSectionsOffset   = 2;
constexpr std::size_t kOptionalSizeOffset = 16;
constexpr std::size_t kSizeOfHeadersOffset = 60;
constexpr std::size_t kSizeOfImageOffset   = 56;
constexpr std::size_t kSectionHeaderSize   = 40;

std::uint32_t AlignUp(std::uint64_t value, std::uint32_t alignment)
{
    if (alignment == 0)
    {
        return static_cast<std::uint32_t>(value);
    }

    const std::uint64_t remainder = value % alignment;
    return remainder == 0 ? static_cast<std::uint32_t>(value)
                          : static_cast<std::uint32_t>(value + (alignment - remainder));
}
}

bool Patcher::PadToSize(std::size_t targetSize, Report& report)
{
    // A target at or below the current size is not an error, there is nothing to pad.
    if (targetSize == 0 || targetSize <= m_binary.Size())
    {
        return true;
    }

    const std::size_t extra = targetSize - m_binary.Size();

    HeaderOffsets offsets;

    if (!ResolveHeaderOffsets(offsets))
    {
        report.error = "Patcher: could not locate the PE headers for padding";
        SetError(report.error);
        return false;
    }

    const std::uint16_t numberOfSections =
        ReadU16(m_binary.Data(), m_binary.Size(), offsets.coff + kNumSectionsOffset);

    const std::uint16_t optionalSize =
        ReadU16(m_binary.Data(), m_binary.Size(), offsets.coff + kOptionalSizeOffset);

    const std::size_t   sectionTable = offsets.optional + optionalSize;
    const std::uint32_t headersSize =
        ReadU32(m_binary.Data(), m_binary.Size(), offsets.optional + kSizeOfHeadersOffset);

    const std::size_t maxSections =
        headersSize > sectionTable ? (headersSize - sectionTable) / kSectionHeaderSize : 0;

    if (numberOfSections >= maxSections)
    {
        std::ostringstream oss;
        oss << "Patcher: no free section header slot for padding, "
            << static_cast<int>(maxSections) << " available";
        report.error = oss.str();
        SetError(report.error);
        return false;
    }

    const std::uint32_t fileAlignment = m_parser.FileAlignment();
    const std::uint32_t sectionAlignment = m_parser.SectionAlignment();

    if (fileAlignment == 0 || sectionAlignment == 0)
    {
        report.error = "Patcher: file or section alignment is zero, cannot pad";
        SetError(report.error);
        return false;
    }

    // Both PointerToRawData and SizeOfRawData must be multiples of FileAlignment. The end of
    // file only satisfies that when the binary carries no overlay, and a target size is a
    // user supplied number that need not be aligned either. Emitting an unaligned pair
    // produces a section header the loader rejects, so refuse rather than guess.
    const std::size_t currentSize = m_binary.Size();

    if (currentSize % fileAlignment != 0 || extra % fileAlignment != 0)
    {
        std::ostringstream oss;
        oss << "Patcher: cannot pad from " << currentSize << " to " << targetSize
            << " because neither boundary is a multiple of file alignment " << fileAlignment;
        report.error = oss.str();
        SetError(report.error);
        return false;
    }

    // Grow first: the section header is written into the image, so it must already be large
    // enough to hold the directory entry.
    if (!m_binary.Resize(currentSize + extra))
    {
        report.error = "Patcher: could not grow the image to the requested size";
        SetError(report.error);
        return false;
    }

    auto* image = m_binary.Data();

    // The new raw data starts at the old end of file. That offset is not aligned up to
    // FileAlignment the way the encryptor's appended section is.
    const std::uint32_t rawOffset = static_cast<std::uint32_t>(currentSize);
    const std::uint32_t rawSize   = static_cast<std::uint32_t>(extra);

    std::uint32_t newRva = ReadU32(image, m_binary.Size(), offsets.optional + kSizeOfImageOffset);

    for (const auto& section : m_parser.Sections())
    {
        const std::uint32_t end = section.virtualAddress + section.virtualSize;
        newRva = std::max(newRva, AlignUp(end, sectionAlignment));
    }

    const std::uint32_t virtualSize = AlignUp(rawSize, sectionAlignment);

    const std::size_t headerOffset = sectionTable + numberOfSections * kSectionHeaderSize;

    // The section header is a fixed 40 byte write into the image. Resize only guarantees
    // extra bytes past the old end, so a target less than 40 bytes larger than the current
    // size would write past the vector. The bounds checked writers below cannot catch this
    // because they silently skip instead of reporting.
    if (headerOffset + kSectionHeaderSize > m_binary.Size())
    {
        report.error = "Patcher: not enough room for a padding section header";
        SetError(report.error);
        return false;
    }

    const std::size_t total = m_binary.Size();

    auto write32 = [image, total](std::size_t offset, std::uint32_t value)
    {
        WriteU32(image, total, offset, value);
    };

    auto write16 = [image, total](std::size_t offset, std::uint16_t value)
    {
        if (image != nullptr && offset + 2 <= total)
        {
            image[offset]     = static_cast<std::uint8_t>(value & 0xFF);
            image[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        }
    };

    std::memcpy(image + headerOffset, ".pad\0\0\0", 8);
    write32(headerOffset + 8,  virtualSize);
    write32(headerOffset + 12, newRva);
    write32(headerOffset + 16, rawSize);
    write32(headerOffset + 20, rawOffset);
    write32(headerOffset + 24, 0);
    write32(headerOffset + 28, 0);
    write16(headerOffset + 32, 0);
    write16(headerOffset + 34, 0);
    write32(headerOffset + 36, 0x40000000);  // IMAGE_SCN_MEM_READ

    write16(offsets.coff + kNumSectionsOffset,
            static_cast<std::uint16_t>(numberOfSections + 1));

    write32(offsets.optional + kSizeOfImageOffset, newRva + virtualSize);

    report.bytesPadded    = extra;
    report.paddingApplied = true;

    util::Logger::Info("Patcher: padded output by " + std::to_string(extra) +
                       " bytes to reach " + std::to_string(targetSize));
    return true;
}

bool Patcher::Apply(const std::string& outputPath, const Options& options, Report& report)
{
    ClearError();
    report = Report{};

    if (!m_binary.IsLoaded() || m_binary.IsEmpty())
    {
        report.error = "Patcher::Apply called with no binary loaded";
        SetError(report.error);
        return false;
    }

    if (!m_parser.IsParsed())
    {
        report.error = "Patcher::Apply called before the PE was parsed";
        SetError(report.error);
        return false;
    }

    if (outputPath.empty())
    {
        report.error = "Patcher::Apply called with an empty output path";
        SetError(report.error);
        return false;
    }

    // String encryption rewrites the section table and the entry point, so it runs before
    // the staged writes and before the checksum, both of which then see the final image.
    if (options.encryptStrings && !EncryptStrings(options.strings, report))
    {
        report.error = m_lastError;
        return false;
    }

    if (!WriteStaged(report))
    {
        report.error = m_lastError;
        return false;
    }

    if (options.stripDebugInfo && !StripDebugInfo())
    {
        report.error = m_lastError;
        return false;
    }

    report.debugInfoStripped = options.stripDebugInfo;

    // Padding has to happen before the checksum, not after. The checksum covers the file as
    // written, so computing it over the pre-padding image left it stale for every padded
    // output. The comment here previously claimed the opposite order to the one in the code.
    if (options.targetFileSize > 0 && !PadToSize(options.targetFileSize, report))
    {
        report.error = m_lastError;
        return false;
    }

    if (options.preserveChecksum && !UpdateChecksum())
    {
        report.error = m_lastError;
        return false;
    }

    report.checksumUpdated = options.preserveChecksum;

    if (!m_binary.Save(outputPath))
    {
        report.error = "Failed to write output file: " + outputPath;
        SetError(report.error);
        return false;
    }

    util::Logger::Info("Patcher: wrote " + std::to_string(report.patchesApplied) +
                       " patch(es) to " + outputPath);
    return true;
}

bool Patcher::WriteStaged(Report& report)
{
    // Applied in ascending offset order so a later stage deterministically wins an overlap.
    std::vector<const StagedPatch*> ordered;
    ordered.reserve(m_staged.size());

    for (const auto& patch : m_staged)
    {
        ordered.push_back(&patch);
    }

    std::sort(ordered.begin(), ordered.end(),
              [](const StagedPatch* a, const StagedPatch* b) { return a->offset < b->offset; });

    for (const StagedPatch* patch : ordered)
    {
        if (!m_binary.Write(patch->offset, patch->bytes))
        {
            std::ostringstream oss;
            oss << "Failed to write patch at VA " << util::str::FormatVA(patch->va);
            SetError(oss.str());
            return false;
        }

        report.bytesWritten   += patch->bytes.size();
        ++report.patchesApplied;
    }

    return true;
}

bool Patcher::EncryptStrings(const std::vector<StringCandidate>& strings, Report& report)
{
    StringEncryptor encryptor;

    EncryptOptions options;

    const bool haveSelection = !strings.empty();

    // With one, the caller's list is used verbatim.
    const EncryptReport result = haveSelection
        ? encryptor.EncryptSelected(m_binary, m_parser, strings, options)
        : encryptor.Encrypt(m_binary, m_parser, options);

    if (!result.success)
    {
        SetError(result.message.empty() ? "String encryption failed" : result.message);
        return false;
    }

    if (!result.entryPointHooked)
    {
        // The strings are already scrambled in memory, so a caller that saved now would
        // produce an image whose strings never come back. Refuse rather than write that.
        SetError("String encryption did not hook the entry point, image left unencrypted");
        return false;
    }

    report.stringsEncrypted = result.stringsEncrypted;
    report.stringsEncryptedApplied = true;

    util::Logger::Info("Patcher: " + result.message);
    return true;
}

bool Patcher::StripDebugInfo()
{
    HeaderOffsets layout;

    if (!ResolveHeaderOffsets(layout))
    {
        SetError("Patcher: could not locate the data directories");
        return false;
    }

    if (layout.dirCount > kDirDebug)
    {
        WriteU32(m_binary.Data(), m_binary.Size(), layout.directories + kDirDebug * 8, 0);
        WriteU32(m_binary.Data(), m_binary.Size(), layout.directories + kDirDebug * 8 + 4, 0);
    }

    // The COFF symbol table sits outside the debug directory and leaks names on its own.
    WriteU32(m_binary.Data(), m_binary.Size(), layout.coff + kSymbolTableOffsetInCoff, 0);
    WriteU32(m_binary.Data(), m_binary.Size(), layout.coff + kSymbolCountOffsetInCoff, 0);

    util::Logger::Info("Patcher: stripped debug directory and COFF symbol table");
    return true;
}

bool Patcher::UpdateChecksum()
{
    HeaderOffsets layout;

    if (!ResolveHeaderOffsets(layout))
    {
        SetError("Patcher: could not locate the optional header");
        return false;
    }

    const std::size_t   checksumOffset = layout.optional + kChecksumOffset;
    const std::uint32_t checksum      = ComputeChecksum(checksumOffset);

    WriteU32(m_binary.Data(), m_binary.Size(), checksumOffset, checksum);

    util::Logger::Info("Patcher: checksum updated");
    return true;
}

std::uint32_t Patcher::ComputeChecksum(std::size_t checksumOffset) const
{
    const std::uint8_t* data = m_binary.Data();
    const std::size_t   size = m_binary.Size();

    // Matches the CheckSumMappedFile algorithm: fold every 16-bit word into a 32-bit sum,
    // skip the four checksum bytes themselves, then add the file length.
    std::uint32_t sum = 0;

    for (std::size_t i = 0; i < size; i += 2)
    {
        const bool overlaps = (i + 2 > checksumOffset) && (i < checksumOffset + 4);

        if (overlaps)
        {
            continue;
        }

        const std::uint32_t low  = (i < size) ? data[i] : 0u;
        const std::uint32_t high = (i + 1 < size) ? data[i + 1] : 0u;

        sum += low | (high << 8);
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum + static_cast<std::uint32_t>(size);
}

bool Patcher::ResolveHeaderOffsets(HeaderOffsets& out) const
{
    const std::uint8_t* data = m_binary.Data();
    const std::size_t   size = m_binary.Size();

    const std::uint32_t lfanew = ReadU32(data, size, kLfanewOffset);

    if (static_cast<std::size_t>(lfanew) + kSignatureSize + kCoffHeaderSize > size)
    {
        return false;
    }

    const std::size_t coff = static_cast<std::size_t>(lfanew) + kSignatureSize;
    const std::size_t opt  = coff + kCoffHeaderSize;

    if (opt + kChecksumOffset + 4 > size)
    {
        return false;
    }

    const std::uint16_t magic = ReadU16(data, size, opt);

    if (magic == 0x020B)
    {
        out.directories = opt + kPe32PlusDirOffset;
        out.dirCount    = ReadU32(data, size, opt + kPe32PlusDirCount);
    }
    else if (magic == 0x010B)
    {
        out.directories = opt + kPe32DirOffset;
        out.dirCount    = ReadU32(data, size, opt + kPe32DirCount);
    }
    else
    {
        return false;
    }

    if (out.dirCount > kMaxDirectories)
    {
        out.dirCount = kMaxDirectories;
    }

    if (out.directories + out.dirCount * 8 > size)
    {
        return false;
    }

    out.coff     = coff;
    out.optional = opt;
    return true;
}

const std::string& Patcher::LastError() const
{
    return m_lastError;
}

void Patcher::SetError(std::string message)
{
    m_lastError = std::move(message);
    util::Logger::Error(m_lastError);
}

void Patcher::ClearError()
{
    m_lastError.clear();
}
}
