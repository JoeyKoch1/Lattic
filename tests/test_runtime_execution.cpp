#include "TestFramework.hpp"

#include "lattic/core/StringEncryptor.hpp"
#include "lattic/core/StringScanner.hpp"

#include <windows.h>

#include <cstring>
#include <string>
#include <vector>

using lattic::core::StringCandidate;
using lattic::core::StringEncryptor;

namespace
{
// A private, executable page standing in for a mapped image. The runtime is written here
// exactly where the section table says it lives, so the RIP relative references resolve
// the same way they would after the loader maps the real file.
struct FakeImage
{
    void*  base    = nullptr;
    std::size_t size = 0;

    bool Allocate(std::size_t bytes)
    {
        size = bytes;
        base = ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return base != nullptr;
    }

    void Release()
    {
        if (base != nullptr)
        {
            ::VirtualFree(base, 0, MEM_RELEASE);
            base = nullptr;
        }
    }

    ~FakeImage()
    {
        Release();
    }

    std::uint8_t* At(std::uint64_t rva) const
    {
        return static_cast<std::uint8_t*>(base) + rva;
    }
};

std::uint8_t KeyFor(std::uint32_t& state)
{
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;

    const auto key = static_cast<std::uint8_t>(state & 0xFF);
    return key == 0 ? 0x5A : key;
}

struct Plan
{
    std::vector<StringCandidate> targets;
    std::vector<std::uint8_t>    keys;
    std::vector<std::uint8_t>    runtime;
};

// Builds the runtime for two strings parked in the fake image and returns where everything
// landed, so the test can assert on the decrypted bytes afterwards.
Plan PrepareRuntime(FakeImage& image, std::uint32_t sectionRva, std::uint32_t firstRva,
                    std::uint32_t secondRva, const char* first, const char* second,
                    std::uint32_t originalEntryPoint)
{
    Plan plan;

    std::memcpy(image.At(firstRva), first, std::strlen(first) + 1);
    std::memcpy(image.At(secondRva), second, std::strlen(second) + 1);

    StringCandidate a;
    a.rva        = firstRva;
    a.fileOffset = firstRva;
    a.byteLength = static_cast<std::uint32_t>(std::strlen(first));

    StringCandidate b;
    b.rva        = secondRva;
    b.fileOffset = secondRva;
    b.byteLength = static_cast<std::uint32_t>(std::strlen(second));

    plan.targets = { a, b };

    std::uint32_t state = 0x5A17C0DEu;
    plan.keys = { KeyFor(state), KeyFor(state) };

    const auto base = reinterpret_cast<std::uint64_t>(image.base);

    if (!StringEncryptor::BuildRuntime(sectionRva, base, originalEntryPoint, plan.targets,
                                       plan.keys, plan.runtime))
    {
        ::lattic::test::Fail(__FILE__, __LINE__, "BuildRuntime failed");
        return plan;
    }

    std::memcpy(image.At(sectionRva), plan.runtime.data(), plan.runtime.size());

    // Scramble the strings the way EncryptSelected does, so the stub has real work.
    for (std::size_t i = 0; i < plan.targets.size(); ++i)
    {
        std::uint8_t* at = image.At(plan.targets[i].rva);

        for (std::uint32_t index = 0; index < plan.targets[i].byteLength; ++index)
        {
            at[index] = static_cast<std::uint8_t>(at[index] ^ plan.keys[i]);
        }
    }

    return plan;
}

std::string ReadString(const FakeImage& image, std::uint32_t rva, std::size_t length)
{
    return std::string(reinterpret_cast<const char*>(image.At(rva)), length);
}

// A non void return keeps the compiler from turning the call into a tail call, which
// would leave the stub's jmp rax landing on a ret with no return address pushed.
using StubFn = int (*)();

constexpr int kEntryPointMagic = 0x1234;

// mov eax, kEntryPointMagic; ret
void WriteEntryPoint(std::uint8_t* at)
{
    at[0] = 0xB8;
    at[1] = static_cast<std::uint8_t>(kEntryPointMagic & 0xFF);
    at[2] = static_cast<std::uint8_t>((kEntryPointMagic >> 8) & 0xFF);
    at[3] = static_cast<std::uint8_t>((kEntryPointMagic >> 16) & 0xFF);
    at[4] = static_cast<std::uint8_t>((kEntryPointMagic >> 24) & 0xFF);
    at[5] = 0xC3;
}
}

LATTIC_TEST(RuntimeExecution, StubRestoresEncryptedStrings)
{
    FakeImage image;
    CHECK(image.Allocate(0x100000));

    constexpr std::uint32_t kSectionRva = 0x8000;
    constexpr std::uint32_t kFirstRva   = 0x1000;
    constexpr std::uint32_t kSecondRva  = 0x2000;
    constexpr std::uint32_t kOep        = 0x3000;

    // The original entry point is a plain ret, so running the trampoline returns to the
    // test rather than off into unmapped memory.
    WriteEntryPoint(image.At(kOep));

    const char* first  = "RuntimeRestoresThis";
    const char* second = "AndThisOneToo";

    const Plan plan = PrepareRuntime(image, kSectionRva, kFirstRva, kSecondRva, first, second,
                                     kOep);


    // Precondition: both strings really are scrambled.
    CHECK(ReadString(image, kFirstRva, std::strlen(first)) != std::string(first));
    CHECK(ReadString(image, kSecondRva, std::strlen(second)) != std::string(second));

    const auto stub = reinterpret_cast<StubFn>(image.At(kSectionRva));

    CHECK_EQ(stub(), kEntryPointMagic);

    CHECK_EQ(ReadString(image, kFirstRva, std::strlen(first)), std::string(first));
    CHECK_EQ(ReadString(image, kSecondRva, std::strlen(second)), std::string(second));

    CHECK_EQ(plan.targets.size(), std::size_t{ 2 });

    // Running the stub a second time proves the loop bound is honoured rather than
    // walking past the table. The strings come back garbled, which is the point.
    CHECK_EQ(stub(), kEntryPointMagic);
    CHECK(ReadString(image, kFirstRva, std::strlen(first)) != std::string(first));
}

LATTIC_TEST(RuntimeExecution, PreservesTheStackAndRegisters)
{
    FakeImage image;
    CHECK(image.Allocate(0x100000));

    constexpr std::uint32_t kSectionRva = 0x8000;
    constexpr std::uint32_t kFirstRva   = 0x1000;
    constexpr std::uint32_t kOep        = 0x3000;

    WriteEntryPoint(image.At(kOep));

    PrepareRuntime(image, kSectionRva, kFirstRva, 0x2000, "StackBalanceCheck", "Second",
                   kOep);

    // A local whose address the stub must not disturb, plus a canary the callee saved
    // register cannot be pointing at.
    volatile std::uint64_t canary = 0x0123456789ABCDEFull;

    const auto stub = reinterpret_cast<StubFn>(image.At(kSectionRva));

    // Returning proves the frame was balanced: a stub that pushed four registers and
    // popped a different four would return to the wrong place.
    CHECK_EQ(stub(), kEntryPointMagic);
    CHECK_EQ(canary, 0x0123456789ABCDEFull);
}

LATTIC_TEST(RuntimeExecution, HandlesManyRecords)
{
    FakeImage image;
    CHECK(image.Allocate(0x400000));

    constexpr std::uint32_t kSectionRva = 0x20000;
    constexpr std::uint32_t kOep        = 0x30000;

    WriteEntryPoint(image.At(kOep));

    std::vector<StringCandidate> targets;
    std::vector<std::uint8_t>    keys;

    std::uint32_t state = 0x5A17C0DEu;

    std::vector<std::string> originals;

    for (int i = 0; i < 64; ++i)
    {
        const std::string text = "Record" + std::to_string(i) + "StringValue";
        const std::uint32_t rva = 0x1000 + static_cast<std::uint32_t>(i) * 0x100;

        std::memcpy(image.At(rva), text.c_str(), text.size() + 1);
        originals.push_back(text);

        StringCandidate candidate;
        candidate.rva        = rva;
        candidate.fileOffset = rva;
        candidate.byteLength = static_cast<std::uint32_t>(text.size());

        targets.push_back(candidate);
        keys.push_back(KeyFor(state));
    }

    std::vector<std::uint8_t> runtime;
    CHECK(StringEncryptor::BuildRuntime(kSectionRva, reinterpret_cast<std::uint64_t>(image.base),
                                        kOep, targets, keys, runtime));
    CHECK_EQ(runtime.size(), StringEncryptor::TrampolineSize() + StringEncryptor::StubSize() +
                                64 * StringEncryptor::TableEntrySize());

    std::memcpy(image.At(kSectionRva), runtime.data(), runtime.size());

    for (std::size_t i = 0; i < targets.size(); ++i)
    {
        std::uint8_t* at = image.At(targets[i].rva);

        for (std::uint32_t b = 0; b < targets[i].byteLength; ++b)
        {
            at[b] = static_cast<std::uint8_t>(at[b] ^ keys[i]);
        }
    }

    const auto stub = reinterpret_cast<StubFn>(image.At(kSectionRva));
    CHECK_EQ(stub(), kEntryPointMagic);

    for (std::size_t i = 0; i < targets.size(); ++i)
    {
        CHECK_EQ(ReadString(image, targets[i].rva, originals[i].size()), originals[i]);
    }
}

LATTIC_TEST(RuntimeExecution, ZeroLengthRecordDoesNotHang)
{
    FakeImage image;
    CHECK(image.Allocate(0x100000));

    constexpr std::uint32_t kSectionRva = 0x8000;
    constexpr std::uint32_t kOep        = 0x3000;

    WriteEntryPoint(image.At(kOep));

    std::memcpy(image.At(0x1000), "ZeroLengthEdge", 15);

    StringCandidate candidate;
    candidate.rva        = 0x1000;
    candidate.fileOffset = 0x1000;
    candidate.byteLength = 0;

    const std::vector<std::uint8_t> keys = { 0x11 };

    std::vector<std::uint8_t> runtime;
    CHECK(StringEncryptor::BuildRuntime(kSectionRva, reinterpret_cast<std::uint64_t>(image.base),
                                        kOep, { candidate }, keys, runtime));
    std::memcpy(image.At(kSectionRva), runtime.data(), runtime.size());

    // A zero length record must not spin on the inner loop.
    const auto stub = reinterpret_cast<StubFn>(image.At(kSectionRva));
    CHECK_EQ(stub(), kEntryPointMagic);

    CHECK_EQ(ReadString(image, 0x1000, 14), std::string("ZeroLengthEdge"));
}
