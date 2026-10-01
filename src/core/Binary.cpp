#include "lattic/core/Binary.hpp"

#include <cstring>
#include <fstream>

#include "lattic/util/Logger.hpp"

namespace lattic::core
{
bool Binary::Load(const std::string& path)
{
    ClearError();
    Unload();

    if (path.empty())
    {
        SetError("Binary::Load received an empty path");
        return false;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file.is_open())
    {
        SetError("Failed to open file: " + path);
        return false;
    }

    const std::streampos end = file.tellg();

    if (end <= 0)
    {
        SetError("File is empty or unreadable: " + path);
        return false;
    }

    const std::size_t size = static_cast<std::size_t>(end);

    m_data.resize(size);
    file.seekg(0, std::ios::beg);

    if (!file.read(reinterpret_cast<char*>(m_data.data()), static_cast<std::streamsize>(size)))
    {
        m_data.clear();
        SetError("Failed to read file contents: " + path);
        return false;
    }

    file.close();

    m_path   = path;
    m_loaded = true;

    util::Logger::Info("Binary loaded: " + path + " (" + std::to_string(size) + " bytes)");
    return true;
}

bool Binary::Save(const std::string& path) const
{
    if (!m_loaded || m_data.empty())
    {
        return false;
    }

    if (path.empty())
    {
        return false;
    }

    std::ofstream file(path, std::ios::binary | std::ios::trunc);

    if (!file.is_open())
    {
        return false;
    }

    file.write(reinterpret_cast<const char*>(m_data.data()),
               static_cast<std::streamsize>(m_data.size()));

    if (!file.good())
    {
        return false;
    }

    file.close();
    return true;
}

bool Binary::SaveInPlace() const
{
    if (m_path.empty())
    {
        return false;
    }

    return Save(m_path);
}

void Binary::Unload()
{
    m_data.clear();
    m_data.shrink_to_fit();
    m_path.clear();
    m_loaded = false;
}

bool Binary::IsLoaded() const
{
    return m_loaded;
}

bool Binary::IsEmpty() const
{
    return m_data.empty();
}

const std::string& Binary::Path() const
{
    return m_path;
}

std::uint8_t* Binary::Data()
{
    return m_data.data();
}

const std::uint8_t* Binary::Data() const
{
    return m_data.data();
}

std::size_t Binary::Size() const
{
    return m_data.size();
}

bool Binary::InBounds(std::size_t offset, std::size_t length) const
{
    if (length == 0)
    {
        return offset <= m_data.size();
    }

    if (offset > m_data.size())
    {
        return false;
    }

    return length <= (m_data.size() - offset);
}

bool Binary::Read(std::size_t offset, std::size_t length, std::vector<std::uint8_t>& out) const
{
    out.clear();

    if (!InBounds(offset, length))
    {
        return false;
    }

    out.resize(length);

    if (length > 0)
    {
        std::memcpy(out.data(), m_data.data() + offset, length);
    }

    return true;
}

bool Binary::Write(std::size_t offset, const std::uint8_t* data, std::size_t length)
{
    if (data == nullptr && length > 0)
    {
        return false;
    }

    if (!InBounds(offset, length))
    {
        return false;
    }

    if (length > 0)
    {
        std::memcpy(m_data.data() + offset, data, length);
    }

    return true;
}

bool Binary::Write(std::size_t offset, const std::vector<std::uint8_t>& bytes)
{
    return Write(offset, bytes.data(), bytes.size());
}

bool Binary::Resize(std::size_t newSize)
{
    try
    {
        m_data.resize(newSize);
    }
    catch (...)
    {
        return false;
    }

    return true;
}

bool Binary::Append(const std::uint8_t* data, std::size_t length)
{
    if (data == nullptr && length > 0)
    {
        return false;
    }

    if (length == 0)
    {
        return true;
    }

    try
    {
        m_data.insert(m_data.end(), data, data + length);
    }
    catch (...)
    {
        return false;
    }

    return true;
}

const std::string& Binary::LastError() const
{
    return m_lastError;
}

void Binary::SetError(const std::string& message)
{
    m_lastError = message;
    util::Logger::Error(message);
}

void Binary::ClearError()
{
    m_lastError.clear();
}
}