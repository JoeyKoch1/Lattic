#include "lattic/core/Signature.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "lattic/util/StringUtil.hpp"

namespace lattic::core
{
Signature::Signature(std::string name, std::string pattern)
    : m_name(std::move(name)), m_pattern(std::move(pattern))
{
    Parse(m_pattern);
}

bool Signature::Parse(std::string_view pattern)
{
    ClearError();

    m_bytes.clear();
    m_mask.clear();
    m_valid = false;
    m_pattern.assign(pattern);

    if (pattern.empty())
    {
        SetError("Signature pattern is empty");
        return false;
    }

    std::string cleaned;
    cleaned.reserve(pattern.size());

    for (char c : pattern)
    {
        if (std::isspace(static_cast<unsigned char>(c)))
        {
            cleaned.push_back(' ');
            continue;
        }

        cleaned.push_back(c);
    }

    auto tokens = util::str::Split(cleaned, ' ');

    for (const auto& raw : tokens)
    {
        if (raw.empty())
        {
            continue;
        }

        if (raw == "?" || raw == "??" || raw == "*")
        {
            m_bytes.push_back(0x00);
            m_mask.push_back(0x00);
            continue;
        }

        if (raw.size() == 2 && (raw[0] == '?' || raw[1] == '?'))
        {
            const char known = raw[0] == '?' ? raw[1] : raw[0];

            if (ParseNibble(known) < 0)
            {
                SetError("Invalid nibble in pattern token: " + raw);
                return false;
            }

            m_bytes.push_back(static_cast<std::uint8_t>(ParseNibble(known) << 4));
            m_mask.push_back(0xF0);

            m_bytes.back() = 0x00;
            continue;
        }

        const int value = ParseByte(raw);

        if (value < 0)
        {
            SetError("Invalid byte in pattern: " + raw);
            return false;
        }

        m_bytes.push_back(static_cast<std::uint8_t>(value));
        m_mask.push_back(0xFF);
    }

    if (m_bytes.empty())
    {
        SetError("Signature contained no bytes");
        return false;
    }

    m_valid = true;
    return true;
}

bool Signature::Valid() const
{
    return m_valid;
}

bool Signature::Empty() const
{
    return m_bytes.empty();
}

const std::string& Signature::Name() const
{
    return m_name;
}

const std::string& Signature::Pattern() const
{
    return m_pattern;
}

const std::string& Signature::LastError() const
{
    return m_lastError;
}

void Signature::SetName(std::string name)
{
    m_name = std::move(name);
}

void Signature::SetAddressBase(std::uint64_t base)
{
    m_addressBase = base;
}

std::size_t Signature::Length() const
{
    return m_bytes.size();
}

const std::uint8_t* Signature::Bytes() const
{
    return m_bytes.data();
}

const std::uint8_t* Signature::Mask() const
{
    return m_mask.data();
}

bool Signature::MatchAt(const std::uint8_t* data, std::size_t size, std::size_t offset) const
{
    if (!m_valid || data == nullptr)
    {
        return false;
    }

    if (offset > size)
    {
        return false;
    }

    if (m_bytes.size() > (size - offset))
    {
        return false;
    }

    for (std::size_t i = 0; i < m_bytes.size(); ++i)
    {
        const std::uint8_t mask = m_mask[i];

        if (mask == 0x00)
        {
            continue;
        }

        const std::uint8_t actual = data[offset + i];

        if ((actual & mask) != (m_bytes[i] & mask))
        {
            return false;
        }
    }

    return true;
}

bool Signature::FindFirst(const std::uint8_t* data, std::size_t size, std::size_t startOffset,
                          Match& out) const
{
    out = {};

    if (!m_valid || data == nullptr || m_bytes.empty())
    {
        return false;
    }

    if (m_bytes.size() > size)
    {
        return false;
    }

    const std::size_t last = size - m_bytes.size();

    for (std::size_t offset = startOffset; offset <= last; ++offset)
    {
        if (MatchAt(data, size, offset))
        {
            out.address = m_addressBase + offset;
            out.offset  = offset;
            out.length  = m_bytes.size();
            return true;
        }
    }

    return false;
}

std::vector<Match> Signature::FindAll(const std::uint8_t* data, std::size_t size,
                                      std::size_t startOffset, std::size_t maxMatches) const
{
    std::vector<Match> results;

    if (!m_valid || data == nullptr || m_bytes.empty())
    {
        return results;
    }

    if (m_bytes.size() > size)
    {
        return results;
    }

    const std::size_t last = size - m_bytes.size();

    for (std::size_t offset = startOffset; offset <= last; ++offset)
    {
        if (!MatchAt(data, size, offset))
        {
            continue;
        }

        Match match;
        match.address = m_addressBase + offset;
        match.offset  = offset;
        match.length  = m_bytes.size();

        results.push_back(match);

        if (maxMatches > 0 && results.size() >= maxMatches)
        {
            break;
        }
    }

    return results;
}

void Signature::SetError(std::string message)
{
    m_lastError = std::move(message);
}

void Signature::ClearError()
{
    m_lastError.clear();
}

int Signature::ParseNibble(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }

    return -1;
}

int Signature::ParseByte(std::string_view token)
{
    if (token.size() != 2)
    {
        return -1;
    }

    const int hi = ParseNibble(token[0]);
    const int lo = ParseNibble(token[1]);

    if (hi < 0 || lo < 0)
    {
        return -1;
    }

    return (hi << 4) | lo;
}

void SignatureSet::Add(Signature sig)
{
    m_signatures.push_back(std::move(sig));
}

void SignatureSet::Clear()
{
    m_signatures.clear();
}

std::size_t SignatureSet::Size() const
{
    return m_signatures.size();
}

bool SignatureSet::Empty() const
{
    return m_signatures.empty();
}

Signature& SignatureSet::At(std::size_t index)
{
    return m_signatures.at(index);
}

const Signature& SignatureSet::At(std::size_t index) const
{
    return m_signatures.at(index);
}

std::vector<Signature>& SignatureSet::All()
{
    return m_signatures;
}

const std::vector<Signature>& SignatureSet::All() const
{
    return m_signatures;
}

std::vector<Match> SignatureSet::FindFirst(const std::uint8_t* data, std::size_t size,
                                           std::size_t startOffset) const
{
    std::vector<Match> results;

    for (const auto& sig : m_signatures)
    {
        Match match;

        if (sig.FindFirst(data, size, startOffset, match))
        {
            results.push_back(match);
        }
    }

    return results;
}

std::vector<Match> SignatureSet::FindAll(const std::uint8_t* data, std::size_t size,
                                         std::size_t startOffset) const
{
    std::vector<Match> results;

    for (const auto& sig : m_signatures)
    {
        auto hits = sig.FindAll(data, size, startOffset, 0);
        results.insert(results.end(), hits.begin(), hits.end());
    }

    return results;
}
}