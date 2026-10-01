#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/Binary.hpp"
#include "lattic/util/Sha256.hpp"

namespace lattic::core::watermark
{
constexpr std::array<std::uint8_t, 8> kBlockMagic = {
    'L', 'A', 'T', 'T', 'I', 'C', 'W', 'M'
};

constexpr std::array<std::uint8_t, 11> kTrailerMagic = {
    'L', 'A', 'T', 'T', 'I', 'C', 'W', 'M', 'E', 'N', 'D'
};

constexpr std::uint32_t kBlockVersion   = 1;
constexpr std::size_t   kBlockHeaderSize = 0x48;
constexpr std::size_t   kTrailerSize     = 32;
constexpr std::size_t   kSignatureSize   = 64;
constexpr std::size_t   kHashSize        = 32;

enum class WatermarkFlags : std::uint32_t
{
    None       = 0,
    Signed     = 1u << 0,
    HasOwner   = 1u << 1,
    HasProduct = 1u << 2,
    HasCustom  = 1u << 3,
    HasBuildId = 1u << 4,
    HasMachine = 1u << 5,
    HasTime    = 1u << 6,
    Trial      = 1u << 7,
    Oem        = 1u << 8
};

inline WatermarkFlags operator|(WatermarkFlags a, WatermarkFlags b)
{
    return static_cast<WatermarkFlags>(static_cast<std::uint32_t>(a) |
                                       static_cast<std::uint32_t>(b));
}

inline bool HasFlag(WatermarkFlags value, WatermarkFlags bit)
{
    return (static_cast<std::uint32_t>(value) & static_cast<std::uint32_t>(bit)) != 0;
}

struct WatermarkConfig
{
    std::string owner;
    std::string product;
    std::string custom;

    std::string toolName    = "Lattic";
    std::string toolVersion = "0.1.0";

    bool includeBuildId   = true;
    bool includeTimestamp = true;
    bool includeMachineId = false;

    bool trial = false;
    bool oem   = false;

    std::array<std::uint8_t, kSignatureSize> signature = {};
};

struct WatermarkBlock
{
    std::uint16_t  version = static_cast<std::uint16_t>(kBlockVersion);
    WatermarkFlags flags   = WatermarkFlags::None;

    std::uint64_t timestamp = 0;

    std::array<std::uint8_t, kHashSize> buildId     = {};
    std::array<std::uint8_t, kHashSize> machineId   = {};
    std::array<std::uint8_t, kHashSize> contentHash = {};

    std::string toolName;
    std::string toolVersion;
    std::string owner;
    std::string product;
    std::string custom;

    std::array<std::uint8_t, kSignatureSize> signature = {};

    std::vector<std::uint8_t> Serialize() const;
    bool Deserialize(const std::vector<std::uint8_t>& data);

    std::string Summary() const;
    std::string BuildIdHex() const;
};

struct WatermarkResult
{
    bool        success = false;
    std::string message;

    std::size_t blockOffset   = 0;
    std::size_t blockSize     = 0;
    std::size_t totalAppended = 0;

    std::string contentHashHex;
};

class Watermarker
{
public:
    Watermarker() = default;

    WatermarkResult Apply(Binary& binary, const WatermarkConfig& config);

    bool Read(const Binary& binary, WatermarkBlock& out) const;
    bool Verify(const Binary& binary) const;
    bool Strip(Binary& binary) const;

    bool HasWatermark(const Binary& binary) const;

    const std::string& LastError() const;

private:
    void SetError(std::string message);

    mutable std::string m_lastError;
};

std::string    DefaultOwnerId();
std::string    DefaultMachineId();
std::uint64_t  CurrentUnixTime();
}