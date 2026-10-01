#include "lattic/core/StringEncryptor.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

namespace lattic::core
{
namespace
{
constexpr std::size_t kSectionHeaderSize   = 40;
constexpr std::size_t kCoffHeaderSize      = 20;
constexpr std::size_t kSignatureSize       = 4;
constexpr std::size_t kLfanewOffset        = 0x3C;

constexpr std::size_t kNumSectionsOffset   = 2;
constexpr std::size_t kOptionalSizeOffset  = 16;
constexpr std::size_t kEntryPointOffset    = 16;
constexpr std::size_t kSizeOfImageOffset   = 56;
constexpr std::size_t kSizeOfHeadersOffset = 60;
constexpr std::size_t kCharacteristicsOffset = 36;

constexpr std::uint16_t kPe32Magic     = 0x010B;
constexpr std::uint16_t kPe32PlusMagic = 0x020B;

constexpr std::uint32_t kSectionCntCode    = 0x00000020;
constexpr std::uint32_t kSectionMemExecute = 0x20000000;
constexpr std::uint32_t kSectionMemRead    = 0x40000000;
constexpr std::uint32_t kSectionMemWrite   = 0x80000000;

// Table record layout, 16 bytes.
//   +0  u32  target RVA
//   +4  u32  byte length
//   +8  i32  signed delta from this record's own runtime address to the target
//   +12 u8   XOR key
//
// The delta replaces the image base a naive stub would need, which is what makes the
// stub position independent and therefore safe under ASLR. A signed 32 bit delta spans
// any image the loader accepts, because SizeOfImage cannot exceed 2 GiB.
constexpr std::size_t kTableEntrySize = 16;
constexpr std::size_t kTableFieldRva    = 0;
constexpr std::size_t kTableFieldLength = 4;
constexpr std::size_t kTableFieldDelta  = 8;
constexpr std::size_t kTableFieldKey    = 12;

// The trampoline is lea rax, [rip + disp32] followed by jmp rel32.
constexpr std::size_t kTrampolineSize = 12;

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

void WriteU16(std::uint8_t* data, std::size_t size, std::size_t offset, std::uint16_t value)
{
    if (data == nullptr || offset + 2 > size)
    {
        return;
    }

    data[offset]     = static_cast<std::uint8_t>(value & 0xFF);
    data[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
}

void WriteU32(std::uint8_t* data, std::size_t size, std::size_t offset, std::uint32_t value)
{
    if (data == nullptr || offset + 4 > size)
    {
        return;
    }

    std::memcpy(data + offset, &value, sizeof(value));
}

std::size_t AlignUp(std::size_t value, std::size_t alignment)
{
    if (alignment == 0)
    {
        return value;
    }

    const std::size_t remainder = value % alignment;
    return remainder == 0 ? value : value + (alignment - remainder);
}

// PE section names are exactly eight bytes and are not null terminated when they fill it.
std::string ReadSectionName(const std::uint8_t* data, std::size_t size, std::size_t offset)
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

std::uint8_t NextKey(std::uint32_t& state)
{
    // xorshift32. Seeded per image so the same input always produces the same output,
    // which keeps patching reproducible across runs.
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;

    const auto key = static_cast<std::uint8_t>(state & 0xFF);
    return key == 0 ? 0x5A : key;
}

void EmitU32(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    for (int i = 0; i < 4; ++i)
    {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void EmitI32(std::vector<std::uint8_t>& out, std::int32_t value)
{
    EmitU32(out, static_cast<std::uint32_t>(value));
}

void PatchI32(std::vector<std::uint8_t>& out, std::size_t offset, std::int32_t value)
{
    const auto bits = static_cast<std::uint32_t>(value);

    for (int i = 0; i < 4; ++i)
    {
        out[offset + i] = static_cast<std::uint8_t>((bits >> (i * 8)) & 0xFF);
    }
}
}

std::size_t StringEncryptor::TrampolineSize()
{
    return kTrampolineSize;
}

std::size_t StringEncryptor::TableEntrySize()
{
    return kTableEntrySize;
}

std::size_t StringEncryptor::EmitStub(std::vector<std::uint8_t>& out, std::uint32_t tableSize)
{
    // Everything below is measured from the start of the stub, not from out.size(), so the
    // returned offset stays meaningful whether out is empty or already holds a trampoline.
    const std::size_t base = out.size();

    // x86-64, position independent. Every register it touches is restored, including rax,
    // which the trampoline loaded with the original entry point. The key is read into al
    // so rax has to be saved, otherwise the loop's movzx would destroy the jump target and
    // the final jmp rax would branch to the last key byte.
    //
    //   push rbx, rsi, rdi, r8, rax
    //   lea  rsi, [rip + disp32]        ; record cursor, start of the table
    //   mov  edi, imm32                 ; table byte size
    //   add  rdi, rsi                   ; loop bound
    // loop:
    //   movsxd r8, dword [rsi+8]        ; signed delta to the target
    //   mov   edx, dword [rsi+4]        ; length
    //   movzx eax, byte  [rsi+12]       ; key
    //   lea   rcx, [rsi+8]              ; address of the delta field itself
    //   add   rcx, r8                   ; absolute target address
    // inner:
    //   xor   [rcx], al
    //   inc   rcx
    //   dec   edx
    //   jnz   inner
    //   add   rsi, 16
    //   cmp   rsi, rdi
    //   jne   loop
    //   pop   rax, r8, rdi, rsi, rbx
    //   jmp   rax

    out.push_back(0x53);                                     // push rbx
    out.push_back(0x56);                                     // push rsi
    out.push_back(0x57);                                     // push rdi
    out.push_back(0x41);
    out.push_back(0x50);                                     // push r8
    out.push_back(0x50);                                     // push rax

    const std::size_t leaField = out.size() + 3;

    out.push_back(0x48);                                     // lea rsi, [rip + disp32]
    out.push_back(0x8D);
    out.push_back(0x35);
    EmitI32(out, 0);

    out.push_back(0xBF);                                     // mov edi, imm32
    EmitU32(out, tableSize);

    out.push_back(0x48);                                     // add rdi, rsi
    out.push_back(0x01);
    out.push_back(0xF7);

    const std::size_t loopStart = out.size();

    // REX.W alone leaves the reg field at rax, so an r8 operand needs REX.R (0x4C) as
    // well. Getting this wrong is silent: the instruction still assembles, it just reads
    // and writes rax, which holds the original entry point.
    out.push_back(0x4C);                                     // movsxd r8, dword [rsi+8]
    out.push_back(0x63);
    out.push_back(0x46);
    out.push_back(0x08);

    out.push_back(0x8B);                                     // mov edx, dword [rsi+4]
    out.push_back(0x56);
    out.push_back(0x04);

    out.push_back(0x0F);                                     // movzx eax, byte [rsi+12]
    out.push_back(0xB6);
    out.push_back(0x46);
    out.push_back(0x0C);

    out.push_back(0x48);                                     // lea rcx, [rsi+8]
    out.push_back(0x8D);
    out.push_back(0x4E);
    out.push_back(0x08);

    // add r/m64, r64 puts the source in the reg field and the destination in rm, so this
    // is reg=r8, rm=rcx.
    out.push_back(0x4C);
    out.push_back(0x01);
    out.push_back(0xC1);

    // A record with length zero would make dec edx wrap to 0xFFFFFFFF and spin for about
    // four billion iterations, hanging the target. The encryptor never emits one, but this
    // is injected code running in someone else's process, so it skips instead.
    out.push_back(0x85);                                     // test edx, edx
    out.push_back(0xD2);

    const std::size_t jzZero = out.size();
    out.push_back(0x74);                                     // jz past the inner loop
    out.push_back(0x00);

    const std::size_t innerStart = out.size();

    out.push_back(0x30);                                     // xor [rcx], al
    out.push_back(0x01);
    out.push_back(0x48);                                     // inc rcx
    out.push_back(0xFF);
    out.push_back(0xC1);
    out.push_back(0xFF);                                     // dec edx
    out.push_back(0xCA);

    const std::size_t jnzInner = out.size();
    out.push_back(0x75);
    out.push_back(0x00);
    out[jnzInner + 1] = static_cast<std::uint8_t>(0x100 + innerStart - (jnzInner + 2));

    // The skip target is the instruction after jnz inner.
    out[jzZero + 1] = static_cast<std::uint8_t>(out.size() - (jzZero + 2));

    out.push_back(0x48);                                     // add rsi, 16
    out.push_back(0x83);
    out.push_back(0xC6);
    out.push_back(0x10);

    out.push_back(0x48);                                     // cmp rsi, rdi
    out.push_back(0x39);
    out.push_back(0xF7);

    const std::size_t jneLoop = out.size();
    out.push_back(0x75);
    out.push_back(0x00);
    out[jneLoop + 1] = static_cast<std::uint8_t>(0x100 + loopStart - (jneLoop + 2));

    // pop rax, r8, rdi, rsi, rbx, the exact reverse of the pushes. R8 is pushed with a REX
    // prefix, so 0x41 0x58 is required here; 0x41 0x5F would pop r15 and leave the frame
    // unbalanced.
    out.push_back(0x58);                                     // pop rax
    out.push_back(0x41);
    out.push_back(0x58);                                     // pop r8
    out.push_back(0x5F);                                     // pop rdi
    out.push_back(0x5E);                                     // pop rsi
    out.push_back(0x5B);                                     // pop rbx

    out.push_back(0xFF);                                     // jmp rax
    out.push_back(0xE0);

    // Byte offset, relative to the start of the stub, just past the lea instruction. The
    // caller adds the stub's RVA to it to get where RIP points when the lea executes.
    return (leaField + 4) - base;
}

std::size_t StringEncryptor::StubSize()
{
    // Measured, not counted by hand, so editing the stub cannot silently desync the
    // offsets the table and trampoline are computed from.
    static const std::size_t size = []
    {
        std::vector<std::uint8_t> probe;
        EmitStub(probe, 0);
        return probe.size();
    }();

    return size;
}

std::uint32_t StringEncryptor::PlannedSectionRva(const PeParser& parser)
{
    const std::uint32_t sectionAlignment = parser.SectionAlignment();

    if (sectionAlignment == 0)
    {
        return 0;
    }

    std::uint32_t rva = 0;

    for (const auto& section : parser.Sections())
    {
        const std::uint32_t span = std::max(section.virtualSize, section.rawSize);
        rva = std::max(rva, section.virtualAddress + span);
    }

    return static_cast<std::uint32_t>(AlignUp(rva, sectionAlignment));
}

bool StringEncryptor::BuildRuntime(std::uint32_t sectionRva, std::uint64_t imageBase,
                                   std::uint32_t originalEntryPoint,
                                   const std::vector<StringCandidate>& targets,
                                   const std::vector<std::uint8_t>& keys,
                                   std::vector<std::uint8_t>& out)
{
    if (targets.empty() || targets.size() != keys.size())
    {
        return false;
    }

    const std::size_t   trampolineSize = kTrampolineSize;
    const std::size_t   stubSize       = StubSize();
    const std::uint32_t stubRva        = sectionRva + static_cast<std::uint32_t>(trampolineSize);
    const std::uint32_t tableRva       = stubRva + static_cast<std::uint32_t>(stubSize);
    const std::uint32_t tableSize =
        static_cast<std::uint32_t>(targets.size() * kTableEntrySize);

    out.clear();
    out.reserve(trampolineSize + stubSize + tableSize);

    // lea rax, [rip + disp32] puts the original entry point in rax for the stub's jmp rax.
    out.push_back(0x48);
    out.push_back(0x8D);
    out.push_back(0x05);
    EmitI32(out, static_cast<std::int32_t>(static_cast<std::int64_t>(originalEntryPoint) -
                                           static_cast<std::int64_t>(sectionRva + 7)));

    // jmp rel32 into the stub. The jmp is the last thing in the trampoline, so RIP already
    // points at the stub and the displacement is zero.
    out.push_back(0xE9);
    EmitI32(out, 0);

    // leaEnd is measured from the start of the stub, so the RIP base is stubRva + leaEnd.
    const std::size_t leaEnd = EmitStub(out, tableSize);

    PatchI32(out, trampolineSize + leaEnd - 4,
             static_cast<std::int32_t>(static_cast<std::int64_t>(tableRva) -
                                       static_cast<std::int64_t>(stubRva + leaEnd)));

    for (std::size_t i = 0; i < targets.size(); ++i)
    {
        const std::uint32_t recordRva = tableRva + static_cast<std::uint32_t>(i * kTableEntrySize);
        const std::uint64_t fieldVa =
            imageBase + recordRva + static_cast<std::uint32_t>(kTableFieldDelta);
        const std::uint64_t targetVa = imageBase + targets[i].rva;

        EmitU32(out, targets[i].rva);
        EmitU32(out, targets[i].byteLength);
        EmitI32(out, static_cast<std::int32_t>(static_cast<std::int64_t>(targetVa) -
                                               static_cast<std::int64_t>(fieldVa)));
        out.push_back(keys[i]);
        out.push_back(0);
        out.push_back(0);
        out.push_back(0);
    }

    return true;
}

EncryptReport StringEncryptor::Encrypt(Binary& binary, const PeParser& parser,
                                       const EncryptOptions& options)
{
    m_encrypted.clear();
    m_lastError.clear();

    EncryptReport report;

    StringScanner scanner;

    ScanOptions scanOptions;
    scanOptions.minLength                = options.minLength;
    scanOptions.maxLength                = options.maxLength;
    scanOptions.includeUtf16             = options.includeUtf16;
    scanOptions.includeExecutableSections = options.includeExecutableSections;

    const ScanReport scan = scanner.Scan(binary, parser, scanOptions);

    if (!scan.success)
    {
        report.message = scan.message;
        m_lastError    = scan.message;
        return report;
    }

    report.candidatesFound = scan.candidates;

    return EncryptSelected(binary, parser, scanner.Candidates(), options);
}

EncryptReport StringEncryptor::EncryptSelected(Binary& binary, const PeParser& parser,
                                               const std::vector<StringCandidate>& candidates,
                                               const EncryptOptions& options)
{
    m_encrypted.clear();
    m_lastError.clear();

    EncryptReport report;
    report.candidatesFound    = candidates.size();
    report.originalEntryPoint = parser.EntryPointRva();

    if (options.sectionName.empty() || options.sectionName.size() > 8)
    {
        report.message = "StringEncryptor: section name must be 1 to 8 bytes";
        m_lastError    = report.message;
        return report;
    }

    std::vector<StringCandidate> targets;
    std::vector<std::uint8_t>    keys;

    std::uint32_t state = options.seed != 0 ? options.seed : 1u;

    for (const auto& candidate : candidates)
    {
        if (options.maxStrings != 0 && targets.size() >= options.maxStrings)
        {
            ++report.candidatesSkipped;
            continue;
        }

        if (candidate.byteLength == 0 ||
            !binary.InBounds(candidate.fileOffset, candidate.byteLength))
        {
            ++report.candidatesSkipped;
            continue;
        }

        targets.push_back(candidate);
        keys.push_back(NextKey(state));
    }

    if (targets.empty())
    {
        report.success = true;
        report.message  = "No strings selected for encryption";
        return report;
    }
    const std::uint8_t* header    = binary.Data();
    const std::size_t   headerLen = binary.Size();

    const std::uint32_t lfanew = ReadU32(header, headerLen, kLfanewOffset);
    const std::size_t   coff   = static_cast<std::size_t>(lfanew) + kSignatureSize;
    const std::size_t   opt    = coff + kCoffHeaderSize;

    if (opt + kSizeOfHeadersOffset + 4 > headerLen)
    {
        report.message = "StringEncryptor: optional header out of bounds";
        m_lastError    = report.message;
        return report;
    }

    const std::uint16_t magic = ReadU16(header, headerLen, opt);

    if (magic != kPe32PlusMagic && magic != kPe32Magic)
    {
        report.message = "StringEncryptor: unknown optional header magic";
        m_lastError    = report.message;
        return report;
    }

    const std::uint16_t numberOfSections = ReadU16(header, headerLen, coff + kNumSectionsOffset);
    const std::uint16_t optionalSize    = ReadU16(header, headerLen, coff + kOptionalSizeOffset);

    const std::size_t   sectionTable = opt + optionalSize;
    const std::uint32_t headersSize  = ReadU32(header, headerLen, opt + kSizeOfHeadersOffset);

    // The runtime writes into the sections holding the encrypted strings, so those sections
    // must be mapped writable. A section without IMAGE_SCN_MEM_WRITE is mapped read only by
    // the loader and the decryptor would fault on its first xor. Unlocking them is what
    // every runtime unpacker does, and it is the only way the image can run.
    const auto& sections = parser.Sections();

    std::vector<std::size_t> sectionsToUnlock;

    for (const auto& target : targets)
    {
        for (std::size_t i = 0; i < sections.size() && i < numberOfSections; ++i)
        {
            if (!sections[i].Contains(target.rva))
            {
                continue;
            }

            const std::size_t headerOffset = sectionTable + i * kSectionHeaderSize;

            if (std::find(sectionsToUnlock.begin(), sectionsToUnlock.end(), headerOffset) ==
                sectionsToUnlock.end())
            {
                sectionsToUnlock.push_back(headerOffset);
            }

            break;
        }
    }

    // Appending a section needs a free 40 byte slot inside the existing header block.
    const std::size_t maxSections =
        headersSize > sectionTable ? (headersSize - sectionTable) / kSectionHeaderSize : 0;

    if (numberOfSections >= maxSections)
    {
        std::ostringstream oss;
        oss << "StringEncryptor: no free section header slot, "
            << static_cast<int>(maxSections) << " available";
        report.message = oss.str();
        m_lastError    = report.message;
        return report;
    }

    if (report.originalEntryPoint == 0)
    {
        report.message = "StringEncryptor: image has no entry point to redirect";
        m_lastError    = report.message;
        return report;
    }

    const std::uint32_t sectionRva = PlannedSectionRva(parser);
    const std::uint64_t imageBase  = parser.ImageBase();

    const std::uint32_t sectionAlignment = parser.SectionAlignment();
    const std::uint32_t fileAlignment    = parser.FileAlignment();

    if (sectionAlignment == 0 || fileAlignment == 0)
    {
        report.message = "StringEncryptor: section or file alignment is zero";
        m_lastError    = report.message;
        return report;
    }

    std::vector<std::uint8_t> runtime;

    if (!BuildRuntime(sectionRva, imageBase, report.originalEntryPoint, targets, keys, runtime))
    {
        report.message = "StringEncryptor: failed to build the decryptor runtime";
        m_lastError    = report.message;
        return report;
    }

    const std::size_t payload     = runtime.size();
    const std::size_t virtualSize = AlignUp(payload, sectionAlignment);
    const std::size_t rawSize     = AlignUp(payload, fileAlignment);
    const std::size_t rawOffset   = AlignUp(binary.Size(), fileAlignment);

    if (!binary.Resize(rawOffset + rawSize))
    {
        report.message = "StringEncryptor: failed to grow the file for the new section";
        m_lastError    = report.message;
        return report;
    }

    std::uint8_t* image = binary.Data();

    std::memcpy(image + rawOffset, runtime.data(), runtime.size());
    std::memset(image + rawOffset + payload, 0, rawSize - payload);

    const std::size_t headerOffset = sectionTable + numberOfSections * kSectionHeaderSize;

    std::memset(image + headerOffset, 0, kSectionHeaderSize);
    std::memcpy(image + headerOffset, options.sectionName.data(), options.sectionName.size());

    WriteU32(image, binary.Size(), headerOffset + 8, static_cast<std::uint32_t>(virtualSize));
    WriteU32(image, binary.Size(), headerOffset + 12, sectionRva);
    WriteU32(image, binary.Size(), headerOffset + 16, static_cast<std::uint32_t>(rawSize));
    WriteU32(image, binary.Size(), headerOffset + 20, static_cast<std::uint32_t>(rawOffset));
    WriteU32(image, binary.Size(), headerOffset + 36,
             kSectionCntCode | kSectionMemRead | kSectionMemWrite | kSectionMemExecute);

    WriteU16(image, binary.Size(), coff + kNumSectionsOffset,
             static_cast<std::uint16_t>(numberOfSections + 1));

    const std::uint32_t sizeOfImage = ReadU32(image, binary.Size(), opt + kSizeOfImageOffset);
    const std::uint32_t newSizeOfImage =
        static_cast<std::uint32_t>(AlignUp(sectionRva + virtualSize, sectionAlignment));

    if (newSizeOfImage > sizeOfImage)
    {
        WriteU32(image, binary.Size(), opt + kSizeOfImageOffset, newSizeOfImage);
    }

    // Unlock every section the decryptor will write into. Done after the new section header
    // is in place so the table is consistent, and before the strings are scrambled.
    for (std::size_t unlockOffset : sectionsToUnlock)
    {
        const std::uint32_t characteristics =
            ReadU32(image, binary.Size(), unlockOffset + kCharacteristicsOffset);

        WriteU32(image, binary.Size(), unlockOffset + kCharacteristicsOffset,
                 characteristics | kSectionMemWrite);

        const std::string name = ReadSectionName(image, binary.Size(), unlockOffset);

        util::Logger::Info("StringEncryptor: section " + name +
                           " marked writable so the runtime can decrypt in place");
    }

    // The strings are scrambled only once the runtime is safely written, so a failure
    // above leaves the in-memory image unmodified and the caller can still save it.
    for (std::size_t i = 0; i < targets.size(); ++i)
    {
        std::uint8_t* at = image + targets[i].fileOffset;

        for (std::uint32_t b = 0; b < targets[i].byteLength; ++b)
        {
            at[b] = static_cast<std::uint8_t>(at[b] ^ keys[i]);
        }

        report.bytesEncrypted += targets[i].byteLength;
    }

    WriteU32(image, binary.Size(), opt + kEntryPointOffset, sectionRva);

    m_encrypted = targets;
    report.stringsEncrypted = targets.size();
    report.sectionRva       = sectionRva;
    report.sectionRawOffset = static_cast<std::uint32_t>(rawOffset);
    report.sectionRawSize   = rawSize;
    report.trampolineSize   = kTrampolineSize;
    report.runtimeSize      = StubSize();
    report.tableSize        = payload - kTrampolineSize - StubSize();
    report.newEntryPoint    = sectionRva;
    report.entryPointHooked = true;
    report.success          = true;
    report.message = "Encrypted " + std::to_string(report.stringsEncrypted) + " string(s), " +
                     util::str::FormatBytes(report.bytesEncrypted) + " into section " +
                     options.sectionName + " at RVA " + util::str::FormatVA(sectionRva);

    util::Logger::Info("StringEncryptor: " + report.message);
    return report;
}

const std::vector<StringCandidate>& StringEncryptor::Encrypted() const
{
    return m_encrypted;
}

const std::string& StringEncryptor::LastError() const
{
    return m_lastError;
}
}
