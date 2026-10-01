#include "TestFramework.hpp"

#include "lattic/core/Signature.hpp"

#include <string>
#include <vector>

using lattic::core::Match;
using lattic::core::Signature;
using lattic::core::SignatureSet;

LATTIC_TEST(Signature, ParseRejectsEmptyPattern)
{
    Signature sig;

    CHECK(!sig.Parse(""));
    CHECK(!sig.Valid());
    CHECK(!sig.LastError().empty());
}

LATTIC_TEST(Signature, ParseRejectsInvalidByte)
{
    Signature sig;

    CHECK(!sig.Parse("48 8B ZZ"));
    CHECK(!sig.Valid());

    Signature half;
    CHECK(!half.Parse("4"));
}

LATTIC_TEST(Signature, ParseExactPattern)
{
    Signature sig("prologue", "48 8B C1 90");

    CHECK(sig.Valid());
    CHECK(!sig.Empty());
    CHECK_EQ(sig.Name(), std::string("prologue"));
    CHECK_EQ(sig.Length(), std::size_t{ 4 });
    CHECK(sig.Bytes() != nullptr);
    CHECK(sig.Mask() != nullptr);
    CHECK(sig.LastError().empty());
}

LATTIC_TEST(Signature, WildcardsProduceZeroMask)
{
    Signature sig("wild", "48 ?? ?? 90");

    CHECK(sig.Valid());
    CHECK_EQ(sig.Length(), std::size_t{ 4 });
    CHECK_EQ(sig.Mask()[0], std::uint8_t{ 0xFF });
    CHECK_EQ(sig.Mask()[1], std::uint8_t{ 0x00 });
    CHECK_EQ(sig.Mask()[3], std::uint8_t{ 0xFF });
}

LATTIC_TEST(Signature, MatchAtIsBoundsChecked)
{
    Signature sig("prologue", "48 8B C1");
    const std::uint8_t data[] = { 0x48, 0x8B, 0xC1, 0x90 };

    CHECK(sig.MatchAt(data, 4, 0));

    // Not enough bytes left for the pattern.
    CHECK(!sig.MatchAt(data, 4, 2));
    CHECK(!sig.MatchAt(data, 4, 4));
    CHECK(!sig.MatchAt(data, 4, 100));
    CHECK(!sig.MatchAt(nullptr, 4, 0));
}

LATTIC_TEST(Signature, FindFirstReturnsFirstOccurrence)
{
    Signature sig("prologue", "48 8B C1");

    const std::vector<std::uint8_t> data = { 0x90, 0x48, 0x8B, 0xC1, 0x48, 0x8B, 0xC1 };

    Match match;
    CHECK(sig.FindFirst(data.data(), data.size(), 0, match));
    CHECK_EQ(match.offset, std::size_t{ 1 });
    CHECK_EQ(match.length, std::size_t{ 3 });
}

LATTIC_TEST(Signature, FindFirstRespectsStartOffset)
{
    Signature sig("prologue", "48 8B C1");

    const std::vector<std::uint8_t> data = { 0x48, 0x8B, 0xC1, 0x90, 0x48, 0x8B, 0xC1 };

    Match match;
    CHECK(sig.FindFirst(data.data(), data.size(), 4, match));
    CHECK_EQ(match.offset, std::size_t{ 4 });
}

LATTIC_TEST(Signature, FindAllRespectsMaxMatches)
{
    Signature sig("prologue", "90");

    const std::vector<std::uint8_t> data = { 0x90, 0x90, 0x90, 0x90 };

    const auto all = sig.FindAll(data.data(), data.size(), 0, 0);
    CHECK_EQ(all.size(), std::size_t{ 4 });

    const auto limited = sig.FindAll(data.data(), data.size(), 0, 2);
    CHECK_EQ(limited.size(), std::size_t{ 2 });
}

LATTIC_TEST(Signature, FindAllOnPatternLongerThanData)
{
    Signature sig("prologue", "48 8B C1 90 90 90");

    const std::vector<std::uint8_t> data = { 0x48, 0x8B, 0xC1 };

    CHECK(sig.FindAll(data.data(), data.size(), 0, 0).empty());

    Match match;
    CHECK(!sig.FindFirst(data.data(), data.size(), 0, match));
}

LATTIC_TEST(Signature, AddressBaseOffsetsMatchAddress)
{
    Signature sig("prologue", "90 90");
    sig.SetAddressBase(0x140000000);

    const std::vector<std::uint8_t> data = { 0x00, 0x90, 0x90 };

    Match match;
    CHECK(sig.FindFirst(data.data(), data.size(), 0, match));
    CHECK_EQ(match.address, std::uint64_t{ 0x140000001 });
}

LATTIC_TEST(SignatureSet, AddAndFind)
{
    SignatureSet set;

    CHECK(set.Empty());
    CHECK_EQ(set.Size(), std::size_t{ 0 });

    Signature first("a", "DE AD");
    Signature second("b", "BE EF");

    set.Add(first);
    set.Add(second);

    CHECK(!set.Empty());
    CHECK_EQ(set.Size(), std::size_t{ 2 });
    CHECK_EQ(set.At(0).Name(), std::string("a"));

    const std::vector<std::uint8_t> data = { 0x00, 0xDE, 0xAD, 0x00, 0xBE, 0xEF };

    const auto found = set.FindAll(data.data(), data.size(), 0);
    CHECK_EQ(found.size(), std::size_t{ 2 });

    set.Clear();
    CHECK(set.Empty());
}
