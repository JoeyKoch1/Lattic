#include "lattic/core/watermark/Watermark.hpp"

#include <chrono>
#include <cstring>
#include <sstream>

#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

namespace lattic::core::watermark
{
namespace
{
template <typename T>
void AppendLE(std::vector<std::uint8_t>& out, T value)
{
    for (std::size_t i = 0; i < sizeof(T); ++i)
    {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

template <typename T>
bool ReadLE(const std::vector<std::uint8_t>& data, std::size_t& cursor, T& out)
{
    if (cursor + sizeof(T) > data.size())
    {
        return false;
    }

    out = 0;

    for (std::size_t i = 0; i < sizeof(T); ++i)
    {
        out |= static_cast<T>(data[cursor++]) << (i * 8);
    }

    return true;
}

void AppendString(std::vector<std::uint8_t>& out, const std::string& s)
{
    AppendLE<std::uint16_t>(out, static_cast<std::uint16_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

bool ReadString(const std::vector<std::uint8_t>& data, std::size_t& cursor, std::string& out)
{
    std::uint16_t length = 0;

    if (!ReadLE(data, cursor, length))
    {
        return false;
    }

    if (cursor + length > data.size())
    {
        return false;
    }

    out.assign(reinterpret_cast<const char*>(data.data() + cursor), length);
    cursor += length;
    return true;
}
}

std::uint64_t CurrentUnixTime()
{
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

std::string DefaultOwnerId()
{
#ifdef _WIN32
    char  username[256] = {};
    DWORD size = sizeof(username);

    if (::GetUserNameA(username, &size))
    {
        return std::string(username);
    }
#endif

    return "unknown";
}

std::string DefaultMachineId()
{
    std::ostringstream oss;

#ifdef _WIN32
    char  computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (::GetComputerNameA(computerName, &size))
    {
        oss << computerName;
    }

    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 0);
    oss << '-' << std::hex << cpuInfo[1] << cpuInfo[3] << cpuInfo[2];
#else
    oss << "unknown";
#endif

    const std::string seed = oss.str();
    const auto digest = util::Sha256::Hash(
        reinterpret_cast<const std::uint8_t*>(seed.data()), seed.size());

    return util::Sha256::ToHex(digest);
}

std::vector<std::uint8_t> WatermarkBlock::Serialize() const
{
    std::vector<std::uint8_t> out;
    out.reserve(kBlockHeaderSize + toolName.size() + toolVersion.size() +
                owner.size() + product.size() + custom.size());

    out.insert(out.end(), kBlockMagic.begin(), kBlockMagic.end());

    AppendLE<std::uint32_t>(out, kBlockVersion);
    AppendLE<std::uint32_t>(out, static_cast<std::uint32_t>(flags));
    AppendLE<std::uint64_t>(out, timestamp);

    out.insert(out.end(), buildId.begin(), buildId.end());
    out.insert(out.end(), machineId.begin(), machineId.end());
    out.insert(out.end(), contentHash.begin(), contentHash.end());
    out.insert(out.end(), signature.begin(), signature.end());

    AppendString(out, toolName);
    AppendString(out, toolVersion);
    AppendString(out, owner);
    AppendString(out, product);
    AppendString(out, custom);

    return out;
}

bool WatermarkBlock::Deserialize(const std::vector<std::uint8_t>& data)
{
    if (data.size() < kBlockHeaderSize)
    {
        return false;
    }

    if (std::memcmp(data.data(), kBlockMagic.data(), kBlockMagic.size()) != 0)
    {
        return false;
    }

    std::size_t cursor = kBlockMagic.size();

    std::uint32_t versionValue = 0;
    std::uint32_t flagsValue   = 0;

    if (!ReadLE(data, cursor, versionValue)) return false;
    if (!ReadLE(data, cursor, flagsValue))   return false;
    if (!ReadLE(data, cursor, timestamp))    return false;

    version = static_cast<std::uint16_t>(versionValue);
    flags   = static_cast<WatermarkFlags>(flagsValue);

    if (cursor + kHashSize > data.size()) return false;
    std::memcpy(buildId.data(), data.data() + cursor, kHashSize);
    cursor += kHashSize;

    if (cursor + kHashSize > data.size()) return false;
    std::memcpy(machineId.data(), data.data() + cursor, kHashSize);
    cursor += kHashSize;

    if (cursor + kHashSize > data.size()) return false;
    std::memcpy(contentHash.data(), data.data() + cursor, kHashSize);
    cursor += kHashSize;

    if (cursor + kSignatureSize > data.size()) return false;
    std::memcpy(signature.data(), data.data() + cursor, kSignatureSize);
    cursor += kSignatureSize;

    if (!ReadString(data, cursor, toolName))    return false;
    if (!ReadString(data, cursor, toolVersion)) return false;
    if (!ReadString(data, cursor, owner))       return false;
    if (!ReadString(data, cursor, product))     return false;
    if (!ReadString(data, cursor, custom))      return false;

    return true;
}

std::string WatermarkBlock::BuildIdHex() const
{
    return util::Sha256::ToHex(buildId);
}

std::string WatermarkBlock::Summary() const
{
    std::ostringstream oss;

    oss << "Lattic watermark";
    oss << " v" << version;
    oss << " | " << toolName << ' ' << toolVersion;

    if (!owner.empty())
    {
        oss << " | owner=" << owner;
    }

    if (!product.empty())
    {
        oss << " | product=" << product;
    }

    if (!custom.empty())
    {
        oss << " | custom=" << custom;
    }

    if (HasFlag(flags, WatermarkFlags::HasBuildId))
    {
        oss << " | build=" << util::Sha256::ToHexShort(buildId, 16);
    }

    if (HasFlag(flags, WatermarkFlags::Trial))
    {
        oss << " | TRIAL";
    }

    if (HasFlag(flags, WatermarkFlags::Signed))
    {
        oss << " | signed";
    }

    return oss.str();
}

void Watermarker::SetError(std::string message)
{
    m_lastError = std::move(message);
    util::Logger::Error(m_lastError);
}

const std::string& Watermarker::LastError() const
{
    return m_lastError;
}

bool Watermarker::HasWatermark(const Binary& binary) const
{
    WatermarkBlock block;
    return Read(binary, block);
}

WatermarkResult Watermarker::Apply(Binary& binary, const WatermarkConfig& config)
{
    WatermarkResult result;
    m_lastError.clear();

    if (!binary.IsLoaded() || binary.IsEmpty())
    {
        result.message = "Watermarker: binary is empty";
        SetError(result.message);
        return result;
    }

    WatermarkBlock existing;

    if (Read(binary, existing))
    {
        result.message = "Watermarker: binary already watermarked";
        SetError(result.message);
        return result;
    }

    WatermarkBlock block;

    block.toolName    = config.toolName;
    block.toolVersion = config.toolVersion;
    block.owner       = config.owner;
    block.product     = config.product;
    block.custom      = config.custom;
    block.timestamp   = config.includeTimestamp ? CurrentUnixTime() : 0;

    WatermarkFlags flags = WatermarkFlags::None;

    if (config.includeBuildId)
    {
        block.buildId = util::Sha256::Hash(binary.Data(), binary.Size());
        flags = flags | WatermarkFlags::HasBuildId;
    }

    if (config.includeMachineId)
    {
        const std::string machine = DefaultMachineId();
        block.machineId = util::Sha256::Hash(
            reinterpret_cast<const std::uint8_t*>(machine.data()), machine.size());
        flags = flags | WatermarkFlags::HasMachine;
    }

    if (config.includeTimestamp)
    {
        flags = flags | WatermarkFlags::HasTime;
    }

    if (!config.owner.empty())
    {
        flags = flags | WatermarkFlags::HasOwner;
    }

    if (!config.product.empty())
    {
        flags = flags | WatermarkFlags::HasProduct;
    }

    if (!config.custom.empty())
    {
        flags = flags | WatermarkFlags::HasCustom;
    }

    if (config.trial)
    {
        flags = flags | WatermarkFlags::Trial;
    }

    if (config.oem)
    {
        flags = flags | WatermarkFlags::Oem;
    }

    const bool hasSignature = config.signature != std::array<std::uint8_t, kSignatureSize>{};

    if (hasSignature)
    {
        block.signature = config.signature;
        flags = flags | WatermarkFlags::Signed;
    }

    block.flags = flags;

    {
        WatermarkBlock temp = block;
        temp.contentHash = {};

        const auto body = temp.Serialize();
        block.contentHash = util::Sha256::Hash(body);
    }

    const auto body = block.Serialize();

    const std::size_t blockOffset = binary.Size();

    if (!binary.Append(body.data(), body.size()))
    {
        result.message = "Watermarker: failed to append block";
        SetError(result.message);
        return result;
    }

    std::vector<std::uint8_t> trailer;
    trailer.reserve(kTrailerSize);

    trailer.insert(trailer.end(), kTrailerMagic.begin(), kTrailerMagic.end());
    trailer.push_back(0);

    AppendLE<std::uint32_t>(trailer, static_cast<std::uint32_t>(blockOffset));
    AppendLE<std::uint32_t>(trailer, static_cast<std::uint32_t>(body.size()));
    AppendLE<std::uint32_t>(trailer, kBlockVersion);
    AppendLE<std::uint32_t>(trailer, static_cast<std::uint32_t>(block.flags));
    AppendLE<std::uint32_t>(trailer, 0);

    if (!binary.Append(trailer.data(), trailer.size()))
    {
        result.message = "Watermarker: failed to append trailer";
        SetError(result.message);
        return result;
    }

    result.success        = true;
    result.blockOffset    = blockOffset;
    result.blockSize      = body.size();
    result.totalAppended  = body.size() + trailer.size();
    result.contentHashHex = util::Sha256::ToHex(block.contentHash);
    result.message = "watermark applied at offset " + std::to_string(blockOffset) +
                     " (" + std::to_string(result.totalAppended) + " bytes)";

    util::Logger::Info("Watermarker: " + result.message);
    return result;
}

bool Watermarker::Read(const Binary& binary, WatermarkBlock& out) const
{
    m_lastError.clear();

    if (!binary.IsLoaded() || binary.Size() < kTrailerSize)
    {
        return false;
    }

    const std::uint8_t* tail = binary.Data() + binary.Size() - kTrailerSize;

    if (std::memcmp(tail, kTrailerMagic.data(), kTrailerMagic.size()) != 0)
    {
        return false;
    }

    std::uint32_t blockOffset = 0;
    std::uint32_t blockSize   = 0;

    std::memcpy(&blockOffset, tail + 12, 4);
    std::memcpy(&blockSize,   tail + 16, 4);

    if (blockSize < kBlockHeaderSize)
    {
        return false;
    }

    if (blockOffset > binary.Size())
    {
        return false;
    }

    if (static_cast<std::size_t>(blockOffset) + blockSize + kTrailerSize != binary.Size())
    {
        return false;
    }

    std::vector<std::uint8_t> body(
        binary.Data() + blockOffset,
        binary.Data() + blockOffset + blockSize);

    return out.Deserialize(body);
}

bool Watermarker::Verify(const Binary& binary) const
{
    WatermarkBlock block;

    if (!Read(binary, block))
    {
        return false;
    }

    WatermarkBlock temp = block;
    temp.contentHash = {};

    const auto body   = temp.Serialize();
    const auto digest = util::Sha256::Hash(body);

    return digest == block.contentHash;
}

bool Watermarker::Strip(Binary& binary) const
{
    WatermarkBlock block;

    if (!Read(binary, block))
    {
        return false;
    }

    const std::size_t bodySize = block.Serialize().size();
    const std::size_t newSize  = binary.Size() - bodySize - kTrailerSize;

    if (newSize == 0)
    {
        return false;
    }

    return binary.Resize(newSize);
}
}