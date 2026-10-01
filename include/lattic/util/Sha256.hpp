#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lattic::util
{
class Sha256
{
public:
    static constexpr std::size_t kDigestSize = 32;

    using Digest = std::array<std::uint8_t, kDigestSize>;

    Sha256();

    void Update(const std::uint8_t* data, std::size_t length);
    void Update(const std::vector<std::uint8_t>& data);
    void Final(Digest& out);
    void Reset();

    static Digest Hash(const std::uint8_t* data, std::size_t length);
    static Digest Hash(const std::vector<std::uint8_t>& data);
    static std::string ToHex(const Digest& digest);
    static std::string ToHexShort(const Digest& digest, std::size_t chars);

private:
    void Transform(const std::uint8_t* block);

    std::array<std::uint32_t, 8> m_state;
    std::array<std::uint8_t, 64> m_buffer;
    std::uint64_t                m_bitLength;
    std::size_t                  m_bufferLength;
};
}