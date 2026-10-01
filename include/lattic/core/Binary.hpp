#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lattic::core
{
class Binary
{
public:
    Binary() = default;
    ~Binary() = default;

    Binary(const Binary&)            = delete;
    Binary& operator=(const Binary&) = delete;

    Binary(Binary&&) noexcept            = default;
    Binary& operator=(Binary&&) noexcept = default;

    bool Load(const std::string& path);
    bool Save(const std::string& path) const;
    bool SaveInPlace() const;

    void Unload();

    bool IsLoaded() const;
    bool IsEmpty() const;

    const std::string& Path() const;

    std::uint8_t*       Data();
    const std::uint8_t* Data() const;

    std::size_t Size() const;

    bool InBounds(std::size_t offset, std::size_t length) const;

    bool Read(std::size_t offset, std::size_t length, std::vector<std::uint8_t>& out) const;
    bool Write(std::size_t offset, const std::vector<std::uint8_t>& bytes);
    bool Write(std::size_t offset, const std::uint8_t* data, std::size_t length);

    bool Resize(std::size_t newSize);
    bool Append(const std::uint8_t* data, std::size_t length);

    const std::string& LastError() const;

private:
    void SetError(const std::string& message);
    void ClearError();

    std::vector<std::uint8_t> m_data;
    std::string               m_path;
    std::string               m_lastError;
    bool                      m_loaded = false;
};
}