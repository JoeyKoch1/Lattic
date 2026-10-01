#include "lattic/util/Json.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace lattic::util
{
namespace
{
constexpr int kMaxDepth = 64;

struct Parser
{
    const std::string& text;
    std::size_t        pos = 0;
    std::string        error;

    explicit Parser(const std::string& t) : text(t)
    {
    }

    void SkipSpace()
    {
        while (pos < text.size())
        {
            const char c = text[pos];

            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            {
                ++pos;
                continue;
            }

            break;
        }
    }

    bool AtEnd() const
    {
        return pos >= text.size();
    }

    bool Fail(const std::string& message)
    {
        if (error.empty())
        {
            error = message + " at offset " + std::to_string(pos);
        }
        return false;
    }

    bool ParseValue(Json& out, int depth)
    {
        if (depth > kMaxDepth)
        {
            return Fail("nesting too deep");
        }

        SkipSpace();

        if (AtEnd())
        {
            return Fail("unexpected end of input");
        }

        switch (text[pos])
        {
        case '{': return ParseObject(out, depth);
        case '[': return ParseArray(out, depth);
        case '"':
        {
            std::string value;
            if (!ParseString(value))
            {
                return false;
            }
            out = Json::From(value);
            return true;
        }
        case 't': return ParseLiteral("true", Json::From(true), out);
        case 'f': return ParseLiteral("false", Json::From(false), out);
        case 'n': return ParseLiteral("null", Json::Null(), out);
        default:  return ParseNumber(out);
        }
    }

    bool ParseLiteral(const char* literal, Json value, Json& out)
    {
        const std::size_t length = std::char_traits<char>::length(literal);

        if (text.compare(pos, length, literal) != 0)
        {
            return Fail("bad literal");
        }

        pos += length;
        out = std::move(value);
        return true;
    }

    bool ParseNumber(Json& out)
    {
        const std::size_t start = pos;

        if (pos < text.size() && (text[pos] == '-' || text[pos] == '+'))
        {
            ++pos;
        }

        while (pos < text.size())
        {
            const char c = text[pos];

            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '-' ||
                c == '+')
            {
                ++pos;
                continue;
            }

            break;
        }

        if (pos == start)
        {
            return Fail("expected a value");
        }

        const std::string token = text.substr(start, pos - start);
        char*             end   = nullptr;

        const double value = std::strtod(token.c_str(), &end);

        if (end == nullptr || *end != '\0')
        {
            pos = start;
            return Fail("malformed number");
        }

        out = Json::From(value);
        return true;
    }

    void AppendUtf8(std::string& out, std::uint32_t code)
    {
        if (code < 0x80)
        {
            out.push_back(static_cast<char>(code));
        }
        else if (code < 0x800)
        {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
        else if (code < 0x10000)
        {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
        else
        {
            out.push_back(static_cast<char>(0xF0 | (code >> 18)));
            out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }

    bool ParseHex4(std::uint32_t& out)
    {
        if (pos + 4 > text.size())
        {
            return Fail("truncated escape");
        }

        out = 0;

        for (int i = 0; i < 4; ++i)
        {
            const char c = text[pos++];

            out <<= 4;

            if (c >= '0' && c <= '9')
            {
                out |= static_cast<std::uint32_t>(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                out |= static_cast<std::uint32_t>(c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F')
            {
                out |= static_cast<std::uint32_t>(c - 'A' + 10);
            }
            else
            {
                return Fail("bad hex escape");
            }
        }

        return true;
    }

    bool ParseString(std::string& out)
    {
        if (AtEnd() || text[pos] != '"')
        {
            return Fail("expected a string");
        }

        ++pos;
        out.clear();

        while (pos < text.size())
        {
            const char c = text[pos++];

            if (c == '"')
            {
                return true;
            }

            if (c != '\\')
            {
                out.push_back(c);
                continue;
            }

            if (AtEnd())
            {
                return Fail("truncated escape");
            }

            const char esc = text[pos++];

            switch (esc)
            {
            case '"':  out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case 'n':  out.push_back('\n'); break;
            case 'r':  out.push_back('\r'); break;
            case 't':  out.push_back('\t'); break;
            case 'u':
            {
                std::uint32_t code = 0;
                if (!ParseHex4(code))
                {
                    return false;
                }

                // Combine a surrogate pair when one follows, otherwise emit the code point
                // as it stands. A lone surrogate becomes U+FFFD rather than invalid UTF-8.
                if (code >= 0xD800 && code <= 0xDBFF && pos + 1 < text.size() &&
                    text[pos] == '\\' && text[pos + 1] == 'u')
                {
                    pos += 2;

                    std::uint32_t low = 0;
                    if (!ParseHex4(low))
                    {
                        return false;
                    }

                    if (low >= 0xDC00 && low <= 0xDFFF)
                    {
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                    }
                    else
                    {
                        AppendUtf8(out, code);
                        code = low;
                    }
                }

                if (code >= 0xD800 && code <= 0xDFFF)
                {
                    code = 0xFFFD;
                }

                AppendUtf8(out, code);
                break;
            }
            default:
                return Fail("unknown escape");
            }
        }

        return Fail("unterminated string");
    }

    bool ParseArray(Json& out, int depth)
    {
        ++pos;
        out = Json::Array();

        SkipSpace();

        if (!AtEnd() && text[pos] == ']')
        {
            ++pos;
            return true;
        }

        while (true)
        {
            Json item;

            if (!ParseValue(item, depth + 1))
            {
                return false;
            }

            out.Push(std::move(item));
            SkipSpace();

            if (AtEnd())
            {
                return Fail("unterminated array");
            }

            if (text[pos] == ',')
            {
                ++pos;
                continue;
            }

            if (text[pos] == ']')
            {
                ++pos;
                return true;
            }

            return Fail("expected , or ]");
        }
    }

    bool ParseObject(Json& out, int depth)
    {
        ++pos;
        out = Json::Object();

        SkipSpace();

        if (!AtEnd() && text[pos] == '}')
        {
            ++pos;
            return true;
        }

        while (true)
        {
            SkipSpace();

            std::string key;

            if (!ParseString(key))
            {
                return false;
            }

            SkipSpace();

            if (AtEnd() || text[pos] != ':')
            {
                return Fail("expected :");
            }

            ++pos;

            Json value;

            if (!ParseValue(value, depth + 1))
            {
                return false;
            }

            out.Set(key, std::move(value));
            SkipSpace();

            if (AtEnd())
            {
                return Fail("unterminated object");
            }

            if (text[pos] == ',')
            {
                ++pos;
                continue;
            }

            if (text[pos] == '}')
            {
                ++pos;
                return true;
            }

            return Fail("expected , or }");
        }
    }
};
}

Json Json::Null()
{
    return Json();
}

Json Json::From(bool value)
{
    Json json;
    json.m_type = Type::Bool;
    json.m_bool = value;
    return json;
}

Json Json::From(std::int64_t value)
{
    return From(static_cast<double>(value));
}

Json Json::From(int value)
{
    return From(static_cast<std::int64_t>(value));
}

Json Json::From(std::uint64_t value)
{
    return From(static_cast<double>(value));
}

Json Json::From(double value)
{
    Json json;
    json.m_type = Type::Number;
    json.m_number = value;
    return json;
}

Json Json::From(const std::string& value)
{
    Json json;
    json.m_type = Type::String;
    json.m_string = value;
    return json;
}

Json Json::From(const char* value)
{
    return From(std::string(value != nullptr ? value : ""));
}

Json Json::Array()
{
    Json json;
    json.m_type = Type::Array;
    return json;
}

Json Json::Object()
{
    Json json;
    json.m_type = Type::Object;
    return json;
}

Json::Type Json::GetType() const
{
    return m_type;
}

bool Json::IsNull() const
{
    return m_type == Type::Null;
}

bool Json::AsBool() const
{
    if (m_type == Type::Bool)
    {
        return m_bool;
    }

    if (m_type == Type::Number)
    {
        return m_number != 0.0;
    }

    return false;
}

double Json::AsNumber() const
{
    if (m_type == Type::Number)
    {
        return m_number;
    }

    if (m_type == Type::Bool)
    {
        return m_bool ? 1.0 : 0.0;
    }

    return 0.0;
}

std::int64_t Json::AsInt() const
{
    const double value = AsNumber();

    if (!(value > static_cast<double>(std::numeric_limits<std::int64_t>::min())) ||
        !(value < static_cast<double>(std::numeric_limits<std::int64_t>::max())))
    {
        return 0;
    }

    return static_cast<std::int64_t>(value);
}

std::string Json::AsString() const
{
    if (m_type == Type::String)
    {
        return m_string;
    }

    if (m_type == Type::Number)
    {
        char buffer[40] = {};
        std::snprintf(buffer, sizeof(buffer), "%.17g", m_number);
        return std::string(buffer);
    }

    if (m_type == Type::Bool)
    {
        return m_bool ? "true" : "false";
    }

    return {};
}

const std::vector<Json>& Json::Items() const
{
    return m_items;
}

const std::vector<std::pair<std::string, Json>>& Json::Members() const
{
    return m_members;
}

const Json* Json::Find(const std::string& key) const
{
    for (const auto& member : m_members)
    {
        if (member.first == key)
        {
            return &member.second;
        }
    }

    return nullptr;
}

bool Json::Has(const std::string& key) const
{
    return Find(key) != nullptr;
}

void Json::Push(Json value)
{
    if (m_type != Type::Array)
    {
        m_type = Type::Array;
    }

    m_items.push_back(std::move(value));
}

void Json::Set(const std::string& key, Json value)
{
    if (m_type != Type::Object)
    {
        m_type = Type::Object;
    }

    for (auto& member : m_members)
    {
        if (member.first == key)
        {
            member.second = std::move(value);
            return;
        }
    }

    m_members.emplace_back(key, std::move(value));
}

std::string Json::EscapeString(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 2);

    out.push_back('"');

    for (const char c : value)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
            {
                char buffer[8] = {};
                std::snprintf(buffer, sizeof(buffer), "\\u%04x",
                              static_cast<unsigned int>(static_cast<unsigned char>(c)));
                out += buffer;
            }
            else
            {
                out.push_back(c);
            }
            break;
        }
    }

    out.push_back('"');
    return out;
}

void Json::DumpInto(std::string& out, bool pretty, int depth) const
{
    const std::string pad  = pretty ? std::string(static_cast<std::size_t>(depth + 1) * 2, ' ') : "";
    const std::string padEnd = pretty ? std::string(static_cast<std::size_t>(depth) * 2, ' ') : "";
    const char*        sep = pretty ? ",\n" : ",";
    const char*        open = pretty ? "\n" : "";

    switch (m_type)
    {
    case Type::Null:
        out += "null";
        break;

    case Type::Bool:
        out += m_bool ? "true" : "false";
        break;

    case Type::Number:
    {
        char buffer[40] = {};
        std::snprintf(buffer, sizeof(buffer), "%.17g", m_number);
        out += buffer;
        break;
    }

    case Type::String:
        out += EscapeString(m_string);
        break;

    case Type::Array:
    {
        if (m_items.empty())
        {
            out += "[]";
            break;
        }

        out += "[";
        out += open;

        for (std::size_t i = 0; i < m_items.size(); ++i)
        {
            if (i > 0)
            {
                out += sep;
            }

            out += pad;
            m_items[i].DumpInto(out, pretty, depth + 1);
        }

        // The closing newline belongs to pretty output only. Emitting it unconditionally
        // left a stray newline inside every compact array.
        out += open;
        out += padEnd;
        out += "]";
        break;
    }

    case Type::Object:
    {
        if (m_members.empty())
        {
            out += "{}";
            break;
        }

        out += "{";
        out += open;

        for (std::size_t i = 0; i < m_members.size(); ++i)
        {
            if (i > 0)
            {
                out += sep;
            }

            out += pad;
            out += EscapeString(m_members[i].first);
            out += pretty ? ": " : ":";
            m_members[i].second.DumpInto(out, pretty, depth + 1);
        }

        out += open;
        out += padEnd;
        out += "}";
        break;
    }
    }
}

std::string Json::Dump(bool pretty) const
{
    std::string out;
    DumpInto(out, pretty, 0);
    return out;
}

bool Json::Parse(const std::string& text, Json& out, std::string& error)
{
    error.clear();

    Parser parser(text);

    if (!parser.ParseValue(out, 0))
    {
        error = parser.error;
        out = Json();
        return false;
    }

    parser.SkipSpace();

    if (!parser.AtEnd())
    {
        error = "trailing content at offset " + std::to_string(parser.pos);
        out = Json();
        return false;
    }

    return true;
}
}
