#include "lattic/util/StringUtil.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace lattic::util::str
{

std::string ToLower(std::string_view input)
{
    std::string out;
    out.reserve(input.size());

    for (char c : input)
    {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    return out;
}

std::string ToUpper(std::string_view input)
{
    std::string out;
    out.reserve(input.size());

    for (char c : input)
    {
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    return out;
}

std::string TrimLeft(std::string_view input)
{
    std::size_t start = 0;

    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])))
    {
        ++start;
    }

    return std::string(input.substr(start));
}

std::string TrimRight(std::string_view input)
{
    std::size_t end = input.size();

    while (end > 0 && std::isspace(static_cast<unsigned char>(input[end - 1])))
    {
        --end;
    }

    return std::string(input.substr(0, end));
}

std::string Trim(std::string_view input)
{
    return TrimRight(TrimLeft(input));
}

bool StartsWith(std::string_view input, std::string_view prefix)
{
    if (prefix.size() > input.size())
    {
        return false;
    }

    return input.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWith(std::string_view input, std::string_view suffix)
{
    if (suffix.size() > input.size())
    {
        return false;
    }

    return input.compare(input.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> Split(std::string_view input, char delimiter)
{
    std::vector<std::string> parts;
    std::size_t              start = 0;

    while (start <= input.size())
    {
        std::size_t end = input.find(delimiter, start);

        if (end == std::string_view::npos)
        {
            parts.emplace_back(input.substr(start));
            break;
        }

        parts.emplace_back(input.substr(start, end - start));
        start = end + 1;
    }

    return parts;
}

std::string Join(const std::vector<std::string>& parts, std::string_view delimiter)
{
    std::string out;

    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        if (i > 0)
        {
            out.append(delimiter);
        }
        out.append(parts[i]);
    }

    return out;
}

std::string BytesToHex(const std::uint8_t* data, std::size_t length)
{
    static constexpr char kHexChars[] = "0123456789ABCDEF";

    std::string out;
    out.resize(length * 2);

    for (std::size_t i = 0; i < length; ++i)
    {
        out[i * 2]     = kHexChars[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHexChars[data[i] & 0x0F];
    }

    return out;
}

std::string BytesToHex(const std::vector<std::uint8_t>& bytes)
{
    return BytesToHex(bytes.data(), bytes.size());
}

std::string BytesToHexSpaced(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char kHexChars[] = "0123456789ABCDEF";

    if (bytes.empty())
    {
        return {};
    }

    std::string out;
    out.reserve(bytes.size() * 3 - 1);

    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        if (i > 0)
        {
            out.push_back(' ');
        }

        out.push_back(kHexChars[(bytes[i] >> 4) & 0x0F]);
        out.push_back(kHexChars[bytes[i] & 0x0F]);
    }

    return out;
}

bool HexToBytes(std::string_view hex, std::vector<std::uint8_t>& out)
{
    out.clear();

    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    {
        hex.remove_prefix(2);
    }

    std::string clean;
    clean.reserve(hex.size());

    for (char c : hex)
    {
        if (!std::isspace(static_cast<unsigned char>(c)))
        {
            clean.push_back(c);
        }
    }

    if (clean.empty() || (clean.size() % 2) != 0)
    {
        return false;
    }

    out.reserve(clean.size() / 2);

    for (std::size_t i = 0; i < clean.size(); i += 2)
    {
        auto nibble = [](char c) -> int
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
        };

        const int hi = nibble(clean[i]);
        const int lo = nibble(clean[i + 1]);

        if (hi < 0 || lo < 0)
        {
            out.clear();
            return false;
        }

        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }

    return true;
}

std::string FormatVA(std::uint64_t va)
{
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << va;
    return oss.str();
}

std::string FormatBytes(std::uint64_t byteCount)
{
    static constexpr const char* kUnits[] = { "B", "KB", "MB", "GB", "TB" };

    double value      = static_cast<double>(byteCount);
    int    unitIndex  = 0;

    while (value >= 1024.0 && unitIndex < 4)
    {
        value /= 1024.0;
        ++unitIndex;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(unitIndex == 0 ? 0 : 2) << value << ' '
        << kUnits[unitIndex];

    return oss.str();
}

std::string FileName(std::string_view path)
{
    const std::size_t pos = path.find_last_of("\\/");

    if (pos == std::string_view::npos)
    {
        return std::string(path);
    }

    return std::string(path.substr(pos + 1));
}

std::string FileExtension(std::string_view path)
{
    const std::size_t slash = path.find_last_of("\\/");
    const std::size_t dot   = path.find_last_of('.');

    if (dot == std::string_view::npos)
    {
        return {};
    }

    if (slash != std::string_view::npos && dot < slash)
    {
        return {};
    }

    return std::string(path.substr(dot));
}

std::string DirectoryOf(std::string_view path)
{
    const std::size_t pos = path.find_last_of("\\/");

    if (pos == std::string_view::npos)
    {
        return {};
    }

    return std::string(path.substr(0, pos));
}

std::string Printable(std::string_view input)
{
    std::string out;
    out.reserve(input.size());

    for (char c : input)
    {
        const unsigned char uc = static_cast<unsigned char>(c);

        if (uc >= 0x20 && uc < 0x7F)
        {
            out.push_back(c);
        }
        else
        {
            out.push_back('.');
        }
    }

    return out;
}

std::string Ellipsize(std::string_view input, std::size_t maxLen)
{
    if (input.size() <= maxLen)
    {
        return std::string(input);
    }

    if (maxLen <= 3)
    {
        return std::string(input.substr(0, maxLen));
    }

    std::string out(input.substr(0, maxLen - 3));
    out.append("...");
    return out;
}

#ifdef _WIN32

std::string Narrow(const std::wstring& wide)
{
    if (wide.empty())
    {
        return {};
    }

    const int size = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                           nullptr, 0, nullptr, nullptr);

    if (size <= 0)
    {
        return {};
    }

    std::string out;
    out.resize(static_cast<std::size_t>(size));

    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), out.data(), size,
                          nullptr, nullptr);

    return out;
}

std::wstring Widen(const std::string& narrow)
{
    if (narrow.empty())
    {
        return {};
    }

    const int size = ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                                           static_cast<int>(narrow.size()), nullptr, 0);

    if (size <= 0)
    {
        return {};
    }

    std::wstring out;
    out.resize(static_cast<std::size_t>(size));

    ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(), static_cast<int>(narrow.size()), out.data(),
                          size);

    return out;
}

#else

std::string Narrow(const std::wstring& wide)
{
    return std::string(wide.begin(), wide.end());
}

std::wstring Widen(const std::string& narrow)
{
    return std::wstring(narrow.begin(), narrow.end());
}

#endif
}