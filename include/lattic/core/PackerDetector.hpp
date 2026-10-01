#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lattic::core
{
class PeParser;
class Binary;

enum class PackerKind
{
    None,
    Lattic,
    UPX,
    Themida,
    VMProtect,
    ASPack,
    MPRESS,
    Enigma,
    PECompact,
    Petite,
    Obsidium,
    Unknown
};

struct PackerSignal
{
    PackerKind kind = PackerKind::None;

    // What gave it away, for the UI: a section name, a marker string, or a suspicious import.
    std::string evidence;
    std::string description;
};

struct DetectionReport
{
    bool isPacked = false;

    // Highest confidence signal found, if any.
    PackerSignal primary;

    std::vector<PackerSignal> all;

    // True when this binary already carries a Lattic section or marker, which means
    // repatching it would append a second section at the same RVA.
    bool alreadyLattic = false;

    std::string summary;
};

// Inspects a parsed image for signs that it has already been protected. This runs before
// patching so a second pass over an already packed file is refused rather than producing a
// corrupt image.
class PackerDetector
{
public:
    PackerDetector() = default;
    ~PackerDetector() = default;

    PackerDetector(const PackerDetector&)            = delete;
    PackerDetector& operator=(const PackerDetector&) = delete;

    static DetectionReport Analyze(const Binary& binary, const PeParser& parser);

    // Refuses a binary Lattic has already touched. Returns an empty string when the file is
    // safe to patch, otherwise the reason.
    static std::string BlockRepatch(const DetectionReport& report);

    static const char* KindName(PackerKind kind);

private:
    static void AddSignal(DetectionReport& report, PackerKind kind,
                          std::string evidence, std::string description);
};
}
