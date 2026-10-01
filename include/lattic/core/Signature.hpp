#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lattic::core
{
struct Match
{
    std::uint64_t address = 0;
    std::size_t   offset  = 0;
    std::size_t   length  = 0;
};

class Signature
{
public:
    Signature() = default;
    Signature(std::string name, std::string pattern);

    bool Parse(std::string_view pattern);

    bool Valid() const;
    bool Empty() const;

    const std::string& Name() const;
    const std::string& Pattern() const;
    const std::string& LastError() const;

    void SetName(std::string name);
    void SetAddressBase(std::uint64_t base);

    std::size_t         Length() const;
    const std::uint8_t* Bytes() const;
    const std::uint8_t* Mask() const;

    bool MatchAt(const std::uint8_t* data, std::size_t size, std::size_t offset) const;

    bool FindFirst(const std::uint8_t* data, std::size_t size, std::size_t startOffset,
                   Match& out) const;

    std::vector<Match> FindAll(const std::uint8_t* data, std::size_t size,
                               std::size_t startOffset, std::size_t maxMatches) const;

private:
    void SetError(std::string message);
    void ClearError();

    static int ParseNibble(char c);
    static int ParseByte(std::string_view token);

    std::string               m_name;
    std::string               m_pattern;
    std::string               m_lastError;
    std::vector<std::uint8_t> m_bytes;
    std::vector<std::uint8_t> m_mask;
    std::uint64_t             m_addressBase = 0;
    bool                      m_valid       = false;
};

class SignatureSet
{
public:
    SignatureSet() = default;

    void Add(Signature sig);
    void Clear();

    std::size_t Size() const;
    bool        Empty() const;

    Signature&       At(std::size_t index);
    const Signature& At(std::size_t index) const;

    std::vector<Signature>&       All();
    const std::vector<Signature>& All() const;

    std::vector<Match> FindFirst(const std::uint8_t* data, std::size_t size,
                                 std::size_t startOffset) const;

    std::vector<Match> FindAll(const std::uint8_t* data, std::size_t size,
                               std::size_t startOffset) const;

private:
    std::vector<Signature> m_signatures;
};
}