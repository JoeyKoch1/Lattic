#include "lattic/util/Sha256.hpp"

#include <cstring>

namespace lattic::util
{
namespace
{
constexpr std::uint32_t kK[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

inline std::uint32_t Rotr(std::uint32_t x, std::uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}
}

Sha256::Sha256()
{
    Reset();
}

void Sha256::Reset()
{
    m_state = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    m_buffer.fill(0);
    m_bitLength    = 0;
    m_bufferLength = 0;
}

void Sha256::Transform(const std::uint8_t* block)
{
    std::uint32_t w[64];

    for (int i = 0; i < 16; ++i)
    {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]));
    }

    for (int i = 16; i < 64; ++i)
    {
        const std::uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = m_state[0];
    std::uint32_t b = m_state[1];
    std::uint32_t c = m_state[2];
    std::uint32_t d = m_state[3];
    std::uint32_t e = m_state[4];
    std::uint32_t f = m_state[5];
    std::uint32_t g = m_state[6];
    std::uint32_t h = m_state[7];

    for (int i = 0; i < 64; ++i)
    {
        const std::uint32_t s1    = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
        const std::uint32_t ch    = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + s1 + ch + kK[i] + w[i];
        const std::uint32_t s0    = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
        const std::uint32_t maj   = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
}

void Sha256::Update(const std::uint8_t* data, std::size_t length)
{
    if (data == nullptr || length == 0)
    {
        return;
    }

    m_bitLength += static_cast<std::uint64_t>(length) * 8;

    std::size_t offset = 0;

    while (offset < length)
    {
        const std::size_t space = 64 - m_bufferLength;
        const std::size_t copy  = (length - offset < space) ? (length - offset) : space;

        std::memcpy(m_buffer.data() + m_bufferLength, data + offset, copy);

        m_bufferLength += copy;
        offset         += copy;

        if (m_bufferLength == 64)
        {
            Transform(m_buffer.data());
            m_bufferLength = 0;
        }
    }
}

void Sha256::Update(const std::vector<std::uint8_t>& data)
{
    Update(data.data(), data.size());
}

void Sha256::Final(Digest& out)
{
    const std::uint64_t bitLength = m_bitLength;

    const std::uint8_t padByte = 0x80;
    Update(&padByte, 1);

    const std::uint8_t zeroByte = 0x00;

    while (m_bufferLength != 56)
    {
        Update(&zeroByte, 1);
    }

    std::uint8_t lengthBytes[8];

    for (int i = 0; i < 8; ++i)
    {
        lengthBytes[i] = static_cast<std::uint8_t>((bitLength >> (56 - i * 8)) & 0xFF);
    }

    Update(lengthBytes, 8);

    for (int i = 0; i < 8; ++i)
    {
        out[i * 4]     = static_cast<std::uint8_t>((m_state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<std::uint8_t>((m_state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<std::uint8_t>((m_state[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<std::uint8_t>(m_state[i] & 0xFF);
    }
}

Sha256::Digest Sha256::Hash(const std::uint8_t* data, std::size_t length)
{
    Sha256 h;
    h.Update(data, length);
    Digest out;
    h.Final(out);
    return out;
}

Sha256::Digest Sha256::Hash(const std::vector<std::uint8_t>& data)
{
    return Hash(data.data(), data.size());
}

std::string Sha256::ToHex(const Digest& digest)
{
    static constexpr char kHex[] = "0123456789abcdef";

    std::string out;
    out.resize(kDigestSize * 2);

    for (std::size_t i = 0; i < kDigestSize; ++i)
    {
        out[i * 2]     = kHex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[digest[i] & 0x0F];
    }

    return out;
}

std::string Sha256::ToHexShort(const Digest& digest, std::size_t chars)
{
    const std::string full = ToHex(digest);

    if (chars >= full.size())
    {
        return full;
    }

    return full.substr(0, chars);
}
}