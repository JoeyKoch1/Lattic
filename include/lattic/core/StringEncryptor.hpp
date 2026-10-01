#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/StringScanner.hpp"

namespace lattic::core
{
struct EncryptOptions
{
    std::size_t minLength = 6;
    std::size_t maxLength = 4096;

    // Zero means encrypt every eligible candidate.
    std::size_t maxStrings = 0;

    bool        includeUtf16 = true;
    bool        includeExecutableSections = false;

    // Must be 8 bytes or fewer. Section names are fixed width and not null terminated.
    std::string sectionName = ".lattic";

    std::uint32_t seed = 0x5A17C0DE;
};

struct EncryptReport
{
    bool        success = false;
    std::string message;

    std::size_t stringsEncrypted  = 0;
    std::size_t bytesEncrypted    = 0;
    std::size_t candidatesFound   = 0;
    std::size_t candidatesSkipped = 0;

    std::uint32_t sectionRva       = 0;
    std::uint32_t sectionRawOffset = 0;
    std::size_t   sectionRawSize   = 0;

    std::size_t trampolineSize = 0;
    std::size_t runtimeSize    = 0;
    std::size_t tableSize      = 0;

    std::uint32_t originalEntryPoint = 0;
    std::uint32_t newEntryPoint      = 0;

    // When false the strings stay scrambled in the image but nothing decrypts them at
    // load time, so the output would be broken. Callers must check this before writing.
    bool entryPointHooked = false;
};

class StringEncryptor
{
public:
    StringEncryptor() = default;
    ~StringEncryptor() = default;

    StringEncryptor(const StringEncryptor&)            = delete;
    StringEncryptor& operator=(const StringEncryptor&) = delete;

    // Scans the image, XORs each selected string with a per-string key, appends a
    // position independent decryptor plus its table in a new section, and redirects the
    // entry point so the stub runs before the original code.
    EncryptReport Encrypt(Binary& binary, const PeParser& parser, const EncryptOptions& options);

    // Same as Encrypt but over a caller-chosen set of candidates.
    EncryptReport EncryptSelected(Binary& binary, const PeParser& parser,
                                  const std::vector<StringCandidate>& candidates,
                                  const EncryptOptions& options);

    const std::vector<StringCandidate>& Encrypted() const;

    const std::string& LastError() const;

    // RVA the appended section will occupy, computed without modifying anything.
    static std::uint32_t PlannedSectionRva(const PeParser& parser);

    // Emits the entry trampoline, the decryptor stub and its table exactly as
    // EncryptSelected lays them out, so a test can inspect the result without a loader.
    static bool BuildRuntime(std::uint32_t sectionRva, std::uint64_t imageBase,
                             std::uint32_t originalEntryPoint,
                             const std::vector<StringCandidate>& targets,
                             const std::vector<std::uint8_t>& keys, std::vector<std::uint8_t>& out);

    // Appends the decryptor stub and returns, relative to the start of the stub, the byte
    // offset just past the lea that loads the table pointer. The caller adds the stub's
    // RVA to it to learn where RIP points, then patches the displacement at
    // (offset - 4). Emitting the relocation in one place keeps layout and fixups in step.
    static std::size_t EmitStub(std::vector<std::uint8_t>& out, std::uint32_t tableSize);

    static std::size_t TrampolineSize();
    static std::size_t StubSize();
    static std::size_t TableEntrySize();

private:
    std::vector<StringCandidate> m_encrypted;
    std::string                  m_lastError;
};
}
