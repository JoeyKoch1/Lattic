#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace lattic::util
{
// A deliberately small JSON value. It exists so the MCP endpoint can speak the protocol
// without pulling in a dependency, and it is bounded on every path that walks input.
class Json
{
public:
    enum class Type
    {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object
    };

    Json() = default;

    static Json Null();
    static Json From(bool value);
    static Json From(std::int64_t value);
    static Json From(int value);
    static Json From(std::uint64_t value);
    static Json From(double value);
    static Json From(const std::string& value);
    static Json From(const char* value);

    static Json Array();
    static Json Object();

    Type GetType() const;
    bool IsNull() const;

    // Accessors return a default when the type does not match, so callers never crash on a
    // malformed payload.
    bool        AsBool() const;
    double      AsNumber() const;
    std::int64_t AsInt() const;
    std::string AsString() const;

    const std::vector<Json>& Items() const;

    // Objects keep insertion order, which keeps the tool listing stable between calls.
    const std::vector<std::pair<std::string, Json>>& Members() const;

    const Json* Find(const std::string& key) const;
    bool Has(const std::string& key) const;

    void Push(Json value);
    void Set(const std::string& key, Json value);

    std::string Dump(bool pretty = false) const;

    // Returns false and fills error when the text is not valid JSON. Nesting is capped so a
    // hostile payload cannot exhaust the stack.
    static bool Parse(const std::string& text, Json& out, std::string& error);

    static std::string EscapeString(const std::string& value);

private:
    void DumpInto(std::string& out, bool pretty, int depth) const;

    Type m_type = Type::Null;

    bool        m_bool = false;
    double      m_number = 0.0;
    std::string m_string;

    std::vector<Json>                          m_items;
    std::vector<std::pair<std::string, Json>>  m_members;
};
}
