#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/Binary.hpp"

namespace lattic::core
{
struct Section
{
    std::string   name;
    std::uint32_t virtualSize        = 0;
    std::uint32_t virtualAddress     = 0;
    std::uint32_t rawSize            = 0;
    std::uint32_t rawOffset          = 0;
    std::uint32_t characteristics    = 0;
    std::uint32_t pointerRelocations = 0;
    std::uint32_t pointerLineNumbers = 0;
    std::uint16_t relocationsCount   = 0;
    std::uint16_t lineNumbersCount   = 0;

    bool Readable() const;
    bool Writable() const;
    bool Executable() const;
    bool Contains(std::uint32_t rva) const;
};

struct Import
{
    std::string              dllName;
    std::vector<std::string> functions;
};

struct Export
{
    std::string   name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva     = 0;
};

struct DataDirectory
{
    std::uint32_t rva  = 0;
    std::uint32_t size = 0;

    bool Present() const;
};

class PeParser
{
public:
    PeParser() = default;
    ~PeParser() = default;

    PeParser(const PeParser&)            = delete;
    PeParser& operator=(const PeParser&) = delete;

    bool Parse(const Binary& binary);
    void Reset();

    bool IsParsed() const;
    bool Is64Bit() const;
    bool IsDll() const;
    bool IsExe() const;

    std::uint64_t ImageBase() const;
    std::uint32_t EntryPointRva() const;
    std::uint64_t EntryPointVa() const;

    std::uint16_t Machine() const;
    std::uint16_t Subsystem() const;
    std::uint16_t Characteristics() const;
    std::uint32_t SectionAlignment() const;
    std::uint32_t FileAlignment() const;
    std::uint32_t SizeOfImage() const;
    std::uint32_t SizeOfHeaders() const;
    std::uint32_t Checksum() const;
    std::uint16_t NumberOfSections() const;

    const std::vector<Section>&       Sections() const;
    const std::vector<Import>&        Imports() const;
    const std::vector<Export>&        Exports() const;
    const std::vector<DataDirectory>& Directories() const;

    const DataDirectory* Directory(std::size_t index) const;

    bool RvaToOffset(std::uint32_t rva, std::uint32_t& offset) const;
    bool VaToOffset(std::uint64_t va, std::uint32_t& offset) const;
    bool OffsetToRva(std::uint32_t offset, std::uint32_t& rva) const;

    const Section* SectionByName(const std::string& name) const;
    const Section* SectionContainingRva(std::uint32_t rva) const;

    std::size_t CandidateStringCount() const;

    const std::string& LastError() const;

private:
    bool ParseHeaders(const std::uint8_t* data, std::size_t size);
    bool ParseSections(const std::uint8_t* data, std::size_t size);
    bool ParseImports(const std::uint8_t* data, std::size_t size);
    bool ParseExports(const std::uint8_t* data, std::size_t size);
    void ScanStrings(const std::uint8_t* data, std::size_t size);

    const char* ReadStringAtRva(std::uint32_t rva, const std::uint8_t* data,
                                std::size_t size) const;

    void SetError(const std::string& message);
    void ClearError();

    std::vector<Section>       m_sections;
    std::vector<Import>        m_imports;
    std::vector<Export>        m_exports;
    std::vector<DataDirectory> m_directories;

    std::uint64_t m_imageBase         = 0;
    std::uint32_t m_entryPointRva     = 0;
    std::uint32_t m_sectionAlignment  = 0;
    std::uint32_t m_fileAlignment     = 0;
    std::uint32_t m_sizeOfImage       = 0;
    std::uint32_t m_sizeOfHeaders     = 0;
    std::uint32_t m_checksum          = 0;
    std::uint32_t m_lfanew            = 0;
    std::uint32_t m_optionalOffset    = 0;
    std::uint32_t m_sectionTableStart = 0;
    std::uint16_t m_machine           = 0;
    std::uint16_t m_subsystem         = 0;
    std::uint16_t m_characteristics   = 0;
    std::uint16_t m_numberOfSections  = 0;

    std::size_t m_candidateStrings = 0;

    bool m_parsed = false;
    bool m_is64   = false;

    std::string m_lastError;
};
}