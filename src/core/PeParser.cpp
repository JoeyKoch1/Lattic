#include "lattic/core/PeParser.hpp"

#include <algorithm>
#include <cstring>
#include <set>

#include "lattic/util/Logger.hpp"

namespace lattic::core
{
namespace
{
constexpr std::uint16_t kDosMagic       = 0x5A4D;
constexpr std::uint32_t kPeSignature    = 0x00004550;
constexpr std::uint16_t kPe32Magic      = 0x010B;
constexpr std::uint16_t kPe32PlusMagic  = 0x020B;

constexpr std::size_t kLfanewOffset      = 0x3C;
constexpr std::size_t kCoffHeaderSize    = 20;
constexpr std::size_t kSectionHeaderSize = 40;
constexpr std::size_t kDirectoryCount    = 16;
constexpr std::size_t kDosHeaderSize     = 64;

constexpr std::uint16_t kMachineI386  = 0x014C;
constexpr std::uint16_t kMachineAmd64 = 0x8664;

constexpr std::uint16_t kSubsystemGui = 2;
constexpr std::uint16_t kSubsystemCui = 3;

constexpr std::uint32_t kSectionReadable   = 0x40000000;
constexpr std::uint32_t kSectionWritable   = 0x80000000;
constexpr std::uint32_t kSectionExecutable = 0x20000000;

constexpr std::uint16_t kDllFlag = 0x2000;

constexpr std::size_t kMinStringLength = 6;

constexpr std::size_t kDirExport   = 0;
constexpr std::size_t kDirImport   = 1;
constexpr std::size_t kDirResource = 2;

template <typename T>
T ReadLE(const std::uint8_t* data, std::size_t offset, std::size_t size)
{
    T value{};

    if (data == nullptr || offset + sizeof(T) > size)
    {
        return value;
    }

    std::memcpy(&value, data + offset, sizeof(T));
    return value;
}

std::string ReadFixedName(const std::uint8_t* data, std::size_t offset, std::size_t size)
{
    std::string name;

    if (data == nullptr || offset + 8 > size)
    {
        return name;
    }

    for (std::size_t i = 0; i < 8; ++i)
    {
        const char c = static_cast<char>(data[offset + i]);

        if (c == '\0')
        {
            break;
        }

        name.push_back(c);
    }

    return name;
}
}

bool Section::Readable() const
{
    return (characteristics & kSectionReadable) != 0;
}

bool Section::Writable() const
{
    return (characteristics & kSectionWritable) != 0;
}

bool Section::Executable() const
{
    return (characteristics & kSectionExecutable) != 0;
}

bool Section::Contains(std::uint32_t rva) const
{
    const std::uint32_t span = std::max(virtualSize, rawSize);

    if (span == 0)
    {
        return false;
    }

    return rva >= virtualAddress && rva < virtualAddress + span;
}

bool DataDirectory::Present() const
{
    return rva != 0 && size != 0;
}

bool PeParser::Parse(const Binary& binary)
{
    Reset();
    ClearError();

    if (!binary.IsLoaded() || binary.IsEmpty())
    {
        SetError("PeParser: binary is empty or not loaded");
        return false;
    }

    const std::uint8_t* data = binary.Data();
    const std::size_t   size = binary.Size();

    if (!ParseHeaders(data, size))
    {
        return false;
    }

    if (!ParseSections(data, size))
    {
        return false;
    }

    ParseImports(data, size);
    ParseExports(data, size);
    ScanStrings(data, size);

    m_parsed = true;

    util::Logger::Info("PeParser: " + std::to_string(m_sections.size()) + " sections, " +
                       std::to_string(m_imports.size()) + " imports, " +
                       std::to_string(m_exports.size()) + " exports, " +
                       std::to_string(m_candidateStrings) + " string candidates");

    return true;
}

void PeParser::Reset()
{
    m_sections.clear();
    m_imports.clear();
    m_exports.clear();
    m_directories.clear();

    m_imageBase         = 0;
    m_entryPointRva     = 0;
    m_sectionAlignment  = 0;
    m_fileAlignment     = 0;
    m_sizeOfImage       = 0;
    m_sizeOfHeaders     = 0;
    m_checksum          = 0;
    m_lfanew            = 0;
    m_optionalOffset    = 0;
    m_sectionTableStart = 0;
    m_machine           = 0;
    m_subsystem         = 0;
    m_characteristics   = 0;
    m_numberOfSections  = 0;
    m_candidateStrings  = 0;
    m_parsed            = false;
    m_is64              = false;
}

bool PeParser::IsParsed() const
{
    return m_parsed;
}

bool PeParser::Is64Bit() const
{
    return m_is64;
}

bool PeParser::IsDll() const
{
    return (m_characteristics & kDllFlag) != 0;
}

bool PeParser::IsExe() const
{
    return !IsDll();
}

std::uint64_t PeParser::ImageBase() const
{
    return m_imageBase;
}

std::uint32_t PeParser::EntryPointRva() const
{
    return m_entryPointRva;
}

std::uint64_t PeParser::EntryPointVa() const
{
    return m_imageBase + m_entryPointRva;
}

std::uint16_t PeParser::Machine() const
{
    return m_machine;
}

std::uint16_t PeParser::Subsystem() const
{
    return m_subsystem;
}

std::uint16_t PeParser::Characteristics() const
{
    return m_characteristics;
}

std::uint32_t PeParser::SectionAlignment() const
{
    return m_sectionAlignment;
}

std::uint32_t PeParser::FileAlignment() const
{
    return m_fileAlignment;
}

std::uint32_t PeParser::SizeOfImage() const
{
    return m_sizeOfImage;
}

std::uint32_t PeParser::SizeOfHeaders() const
{
    return m_sizeOfHeaders;
}

std::uint32_t PeParser::Checksum() const
{
    return m_checksum;
}

std::uint16_t PeParser::NumberOfSections() const
{
    return m_numberOfSections;
}

const std::vector<Section>& PeParser::Sections() const
{
    return m_sections;
}

const std::vector<Import>& PeParser::Imports() const
{
    return m_imports;
}

const std::vector<Export>& PeParser::Exports() const
{
    return m_exports;
}

const std::vector<DataDirectory>& PeParser::Directories() const
{
    return m_directories;
}

const DataDirectory* PeParser::Directory(std::size_t index) const
{
    if (index >= m_directories.size())
    {
        return nullptr;
    }

    return &m_directories[index];
}

bool PeParser::RvaToOffset(std::uint32_t rva, std::uint32_t& offset) const
{
    if (rva < m_sizeOfHeaders)
    {
        offset = rva;
        return true;
    }

    for (const auto& section : m_sections)
    {
        if (!section.Contains(rva))
        {
            continue;
        }

        const std::uint32_t delta = rva - section.virtualAddress;

        if (delta >= section.rawSize)
        {
            return false;
        }

        offset = section.rawOffset + delta;
        return true;
    }

    return false;
}

bool PeParser::VaToOffset(std::uint64_t va, std::uint32_t& offset) const
{
    if (va < m_imageBase)
    {
        return false;
    }

    const std::uint64_t rva = va - m_imageBase;

    if (rva > 0xFFFFFFFFull)
    {
        return false;
    }

    return RvaToOffset(static_cast<std::uint32_t>(rva), offset);
}

bool PeParser::OffsetToRva(std::uint32_t offset, std::uint32_t& rva) const
{
    if (offset < m_sizeOfHeaders)
    {
        rva = offset;
        return true;
    }

    for (const auto& section : m_sections)
    {
        if (offset < section.rawOffset || offset >= section.rawOffset + section.rawSize)
        {
            continue;
        }

        rva = section.virtualAddress + (offset - section.rawOffset);
        return true;
    }

    return false;
}

const Section* PeParser::SectionByName(const std::string& name) const
{
    for (const auto& section : m_sections)
    {
        if (section.name == name)
        {
            return &section;
        }
    }

    return nullptr;
}

const Section* PeParser::SectionContainingRva(std::uint32_t rva) const
{
    for (const auto& section : m_sections)
    {
        if (section.Contains(rva))
        {
            return &section;
        }
    }

    return nullptr;
}

std::size_t PeParser::CandidateStringCount() const
{
    return m_candidateStrings;
}

const std::string& PeParser::LastError() const
{
    return m_lastError;
}

bool PeParser::ParseHeaders(const std::uint8_t* data, std::size_t size)
{
    if (size < kDosHeaderSize)
    {
        SetError("PeParser: file smaller than DOS header");
        return false;
    }

    if (ReadLE<std::uint16_t>(data, 0, size) != kDosMagic)
    {
        SetError("PeParser: missing MZ signature");
        return false;
    }

    m_lfanew = ReadLE<std::uint32_t>(data, kLfanewOffset, size);

    if (static_cast<std::size_t>(m_lfanew) + 4 + kCoffHeaderSize > size)
    {
        SetError("PeParser: e_lfanew out of bounds");
        return false;
    }

    if (ReadLE<std::uint32_t>(data, m_lfanew, size) != kPeSignature)
    {
        SetError("PeParser: missing PE signature");
        return false;
    }

    const std::size_t coffOffset = m_lfanew + 4;

    m_machine          = ReadLE<std::uint16_t>(data, coffOffset + 0, size);
    m_numberOfSections = ReadLE<std::uint16_t>(data, coffOffset + 2, size);

    const std::uint16_t optionalSize = ReadLE<std::uint16_t>(data, coffOffset + 16, size);
    m_characteristics = ReadLE<std::uint16_t>(data, coffOffset + 18, size);

    if (m_numberOfSections == 0)
    {
        SetError("PeParser: zero sections");
        return false;
    }

    m_optionalOffset = static_cast<std::uint32_t>(coffOffset + kCoffHeaderSize);

    if (m_optionalOffset + optionalSize > size)
    {
        SetError("PeParser: optional header out of bounds");
        return false;
    }

    const std::uint16_t magic = ReadLE<std::uint16_t>(data, m_optionalOffset, size);

    if (magic == kPe32PlusMagic)
    {
        m_is64 = true;
    }
    else if (magic == kPe32Magic)
    {
        m_is64 = false;
    }
    else
    {
        SetError("PeParser: unknown optional header magic");
        return false;
    }

    const std::size_t opt = m_optionalOffset;

    m_entryPointRva    = ReadLE<std::uint32_t>(data, opt + 16, size);
    m_sectionAlignment = ReadLE<std::uint32_t>(data, opt + 32, size);
    m_fileAlignment    = ReadLE<std::uint32_t>(data, opt + 36, size);
    m_sizeOfImage      = ReadLE<std::uint32_t>(data, opt + 56, size);
    m_sizeOfHeaders    = ReadLE<std::uint32_t>(data, opt + 60, size);
    m_checksum         = ReadLE<std::uint32_t>(data, opt + 64, size);
    m_subsystem        = ReadLE<std::uint16_t>(data, opt + 68, size);

    std::size_t dirOffset = 0;
    std::size_t dirCount  = 0;

    if (m_is64)
    {
        m_imageBase = ReadLE<std::uint64_t>(data, opt + 24, size);
        dirOffset   = opt + 112;
        dirCount    = ReadLE<std::uint32_t>(data, opt + 108, size);
    }
    else
    {
        m_imageBase = ReadLE<std::uint32_t>(data, opt + 28, size);
        dirOffset   = opt + 96;
        dirCount    = ReadLE<std::uint32_t>(data, opt + 92, size);
    }

    if (dirCount > kDirectoryCount)
    {
        dirCount = kDirectoryCount;
    }

    m_directories.resize(kDirectoryCount);

    for (std::size_t i = 0; i < dirCount; ++i)
    {
        const std::size_t entryOffset = dirOffset + i * 8;

        if (entryOffset + 8 > size)
        {
            break;
        }

        m_directories[i].rva  = ReadLE<std::uint32_t>(data, entryOffset, size);
        m_directories[i].size = ReadLE<std::uint32_t>(data, entryOffset + 4, size);
    }

    return true;
}

bool PeParser::ParseSections(const std::uint8_t* data, std::size_t size)
{
    m_sectionTableStart = m_optionalOffset +
                          ReadLE<std::uint16_t>(data, m_lfanew + 4 + 16, size);

    if (m_sectionTableStart >= size)
    {
        SetError("PeParser: section table out of bounds");
        return false;
    }

    m_sections.reserve(m_numberOfSections);

    for (std::uint16_t i = 0; i < m_numberOfSections; ++i)
    {
        const std::size_t base = m_sectionTableStart + i * kSectionHeaderSize;

        if (base + kSectionHeaderSize > size)
        {
            SetError("PeParser: section header truncated");
            return false;
        }

        Section section;
        section.name               = ReadFixedName(data, base, size);
        section.virtualSize        = ReadLE<std::uint32_t>(data, base + 8, size);
        section.virtualAddress     = ReadLE<std::uint32_t>(data, base + 12, size);
        section.rawSize            = ReadLE<std::uint32_t>(data, base + 16, size);
        section.rawOffset          = ReadLE<std::uint32_t>(data, base + 20, size);
        section.pointerRelocations = ReadLE<std::uint32_t>(data, base + 24, size);
        section.pointerLineNumbers = ReadLE<std::uint32_t>(data, base + 28, size);
        section.relocationsCount   = ReadLE<std::uint16_t>(data, base + 32, size);
        section.lineNumbersCount   = ReadLE<std::uint16_t>(data, base + 34, size);
        section.characteristics    = ReadLE<std::uint32_t>(data, base + 36, size);

        // 64 bit compare: two uint32 values sum to a uint32, so an offset and size near the
        // top of the range wrap to something small and pass validation.
        if (static_cast<std::uint64_t>(section.rawOffset) + section.rawSize > size)
        {
            SetError("PeParser: section raw data out of bounds");
            return false;
        }

        m_sections.push_back(std::move(section));
    }

    return true;
}

bool PeParser::ParseImports(const std::uint8_t* data, std::size_t size)
{
    const DataDirectory* dir = Directory(kDirImport);

    if (dir == nullptr || !dir->Present())
    {
        return true;
    }

    std::uint32_t offset = 0;

    if (!RvaToOffset(dir->rva, offset))
    {
        return false;
    }

    const std::size_t maxDescriptors = 4096;

    for (std::size_t i = 0; i < maxDescriptors; ++i)
    {
        const std::size_t base = offset + i * 20;

        if (base + 20 > size)
        {
            break;
        }

        const std::uint32_t originalThunk = ReadLE<std::uint32_t>(data, base + 0, size);
        const std::uint32_t nameRva       = ReadLE<std::uint32_t>(data, base + 12, size);
        const std::uint32_t firstThunk    = ReadLE<std::uint32_t>(data, base + 16, size);

        if (originalThunk == 0 && nameRva == 0 && firstThunk == 0)
        {
            break;
        }

        Import import;

        const char* dllName = ReadStringAtRva(nameRva, data, size);

        if (dllName != nullptr)
        {
            import.dllName = dllName;
        }

        const std::uint32_t thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
        std::uint32_t       thunkOff = 0;

        if (thunkRva != 0 && RvaToOffset(thunkRva, thunkOff))
        {
            const std::size_t thunkStride = m_is64 ? 8 : 4;
            const std::uint64_t ordinalFlag = m_is64 ? 0x8000000000000000ull : 0x80000000ull;
            const std::size_t   maxThunks   = 8192;

            for (std::size_t t = 0; t < maxThunks; ++t)
            {
                const std::size_t entryOffset = thunkOff + t * thunkStride;

                if (entryOffset + thunkStride > size)
                {
                    break;
                }

                const std::uint64_t entry = m_is64
                    ? ReadLE<std::uint64_t>(data, entryOffset, size)
                    : ReadLE<std::uint32_t>(data, entryOffset, size);

                if (entry == 0)
                {
                    break;
                }

                if ((entry & ordinalFlag) != 0)
                {
                    import.functions.push_back("#" + std::to_string(entry & 0xFFFF));
                    continue;
                }

                if (entry > 0xFFFFFFFFull)
                {
                    break;
                }

                const char* fn = ReadStringAtRva(static_cast<std::uint32_t>(entry) + 2, data, size);

                if (fn != nullptr)
                {
                    import.functions.emplace_back(fn);
                }
            }
        }

        m_imports.push_back(std::move(import));
    }

    return true;
}

bool PeParser::ParseExports(const std::uint8_t* data, std::size_t size)
{
    const DataDirectory* dir = Directory(kDirExport);

    if (dir == nullptr || !dir->Present())
    {
        return true;
    }

    std::uint32_t offset = 0;

    if (!RvaToOffset(dir->rva, offset))
    {
        return false;
    }

    if (offset + 40 > size)
    {
        return false;
    }

    const std::uint32_t ordinalBase      = ReadLE<std::uint32_t>(data, offset + 16, size);
    const std::uint32_t numberOfFunctions = ReadLE<std::uint32_t>(data, offset + 20, size);
    const std::uint32_t numberOfNames     = ReadLE<std::uint32_t>(data, offset + 24, size);
    const std::uint32_t addressOfFunctions = ReadLE<std::uint32_t>(data, offset + 28, size);
    const std::uint32_t addressOfNames    = ReadLE<std::uint32_t>(data, offset + 32, size);
    const std::uint32_t addressOfOrdinals = ReadLE<std::uint32_t>(data, offset + 36, size);

    if (numberOfFunctions > 65536 || numberOfNames > 65536)
    {
        return true;
    }

    std::uint32_t functionsOffset = 0;
    std::uint32_t namesOffset     = 0;
    std::uint32_t ordinalsOffset  = 0;

    if (addressOfFunctions != 0 && !RvaToOffset(addressOfFunctions, functionsOffset))
    {
        return true;
    }

    if (addressOfNames != 0 && !RvaToOffset(addressOfNames, namesOffset))
    {
        return true;
    }

    if (addressOfOrdinals != 0 && !RvaToOffset(addressOfOrdinals, ordinalsOffset))
    {
        return true;
    }

    m_exports.reserve(numberOfNames);

    for (std::uint32_t i = 0; i < numberOfNames; ++i)
    {
        const std::size_t nameEntryOffset = namesOffset + i * 4;

        if (nameEntryOffset + 4 > size)
        {
            break;
        }

        const std::uint32_t nameRva = ReadLE<std::uint32_t>(data, nameEntryOffset, size);

        const std::size_t ordinalEntryOffset = ordinalsOffset + i * 2;

        if (ordinalEntryOffset + 2 > size)
        {
            break;
        }

        const std::uint16_t ordinalIndex = ReadLE<std::uint16_t>(data, ordinalEntryOffset, size);

        std::uint32_t functionRva = 0;

        if (ordinalIndex < numberOfFunctions)
        {
            const std::size_t fnEntryOffset = functionsOffset + ordinalIndex * 4;

            if (fnEntryOffset + 4 <= size)
            {
                functionRva = ReadLE<std::uint32_t>(data, fnEntryOffset, size);
            }
        }

        Export exportEntry;
        exportEntry.ordinal = ordinalBase + ordinalIndex;
        exportEntry.rva     = functionRva;

        const char* name = ReadStringAtRva(nameRva, data, size);

        if (name != nullptr)
        {
            exportEntry.name = name;
        }

        m_exports.push_back(std::move(exportEntry));
    }

    return true;
}

void PeParser::ScanStrings(const std::uint8_t* data, std::size_t size)
{
    std::size_t count = 0;

    for (const auto& section : m_sections)
    {
        if (!section.Readable() || section.Executable())
        {
            continue;
        }

        if (section.rawSize == 0 || section.rawOffset + section.rawSize > size)
        {
            continue;
        }

        const std::uint8_t* start = data + section.rawOffset;
        std::size_t         run   = 0;

        for (std::size_t i = 0; i < section.rawSize; ++i)
        {
            const std::uint8_t c = start[i];

            if (c >= 0x20 && c < 0x7F)
            {
                ++run;
                continue;
            }

            if (c == 0x00 && run >= kMinStringLength)
            {
                ++count;
            }

            run = 0;
        }
    }

    m_candidateStrings = count;
}

const char* PeParser::ReadStringAtRva(std::uint32_t rva, const std::uint8_t* data,
                                      std::size_t size) const
{
    std::uint32_t offset = 0;

    if (!RvaToOffset(rva, offset))
    {
        return nullptr;
    }

    if (offset >= size)
    {
        return nullptr;
    }

    // The returned pointer is handed to std::string, which walks it to a NUL. Without a
    // terminator inside the file a hostile import or export name placed at the last byte
    // reads past the end of the buffer. Refuse unless a NUL is actually present.
    if (std::memchr(data + offset, 0, size - offset) == nullptr)
    {
        return nullptr;
    }

    return reinterpret_cast<const char*>(data + offset);
}

void PeParser::SetError(const std::string& message)
{
    m_lastError = message;
    util::Logger::Error(message);
}

void PeParser::ClearError()
{
    m_lastError.clear();
}
}