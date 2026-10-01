#include "lattic/core/PackerDetector.hpp"

#include <algorithm>
#include <cstring>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/util/Logger.hpp"

namespace lattic::core
{
namespace
{
bool ContainsIgnoreCase(const std::string& haystack, const char* needle)
{
    const std::size_t length = std::strlen(needle);
    const std::size_t total  = haystack.size();

    if (length == 0 || total < length)
    {
        return false;
    }

    for (std::size_t i = 0; i + length <= total; ++i)
    {
        std::size_t k = 0;

        while (k < length)
        {
            char a = haystack[i + k];
            char b = needle[k];

            if (a >= 'A' && a <= 'Z')
            {
                a = static_cast<char>(a - 'A' + 'a');
            }

            if (b >= 'A' && b <= 'Z')
            {
                b = static_cast<char>(b - 'A' + 'a');
            }

            if (a != b)
            {
                break;
            }

            ++k;
        }

        if (k == length)
        {
            return true;
        }
    }

    return false;
}

struct Signature
{
    PackerKind   kind;
    const char*  sectionName;
    const char*  marker;
    const char*  description;
};

// Section name plus marker pairs. The marker is searched across the whole file because
// packers routinely keep their identity string outside the section they named.
const Signature kSignatures[] =
{
    { PackerKind::UPX,        "UPX0",       "UPX!",            "UPX" },
    { PackerKind::UPX,        "UPX1",       "UPX!",            "UPX" },
    { PackerKind::UPX,        ".UPX0",      "UPX!",            "UPX" },
    { PackerKind::Themida,    ".themida",   "Themida",         "Themida or WinLicense" },
    { PackerKind::Themida,    ".winlice",   "WinLicense",      "Themida or WinLicense" },
    { PackerKind::VMProtect,  ".vmp0",      "VMProtect",       "VMProtect" },
    { PackerKind::VMProtect,  ".vmp1",      "VMProtect",       "VMProtect" },
    { PackerKind::ASPack,     ".aspack",    "ASPack",          "ASPack" },
    { PackerKind::ASPack,     ".adata",     "ASPack",          "ASPack" },
    { PackerKind::MPRESS,     ".MPRESS1",   "MPRESS",          "MPRESS" },
    { PackerKind::MPRESS,     ".MPRESS2",   "MPRESS",          "MPRESS" },
    { PackerKind::Enigma,     ".enigma1",   "Enigma Protector", "Enigma Protector" },
    { PackerKind::Enigma,     ".enigma2",   "Enigma Protector", "Enigma Protector" },
    { PackerKind::PECompact,  "PEC2",       "PECompact2",      "PECompact" },
    { PackerKind::Petite,     ".petite",    "petite",          "Petite" },
    { PackerKind::Obsidium,   ".obsidium",  "Obsidium",        "Obsidium" },
    { PackerKind::Unknown,    ".enigma",    nullptr,            "Enigma Protector" },
};

// Lattic's own footprint: the section the encryptor appends, and the marker the decryptor
// stub is supposed to carry. Neither marker string is written by StringEncryptor, so in
// practice only the section name matches.
const char* kLatticSectionNames[] = { ".lattic", ".lattic2" };
const char* kLatticMarkers[]      = { "LATTIC_STUB", "LatticProtect" };
}

void PackerDetector::AddSignal(DetectionReport& report, PackerKind kind,
                               std::string evidence, std::string description)
{
    PackerSignal signal;
    signal.kind        = kind;
    signal.evidence    = std::move(evidence);
    signal.description = std::move(description);

    report.all.push_back(signal);
}

DetectionReport PackerDetector::Analyze(const Binary& binary, const PeParser& parser)
{
    DetectionReport report;

    const std::size_t size   = binary.Size();
    const auto*       data   = binary.Data();

    if (data == nullptr || size == 0)
    {
        report.summary = "Nothing to analyse";
        return report;
    }

    const std::string image(reinterpret_cast<const char*>(data), size);

    // Checked before the generic signatures because this is the one case that must block
    // rather than warn.
    for (const char* name : kLatticSectionNames)
    {
        for (const auto& section : parser.Sections())
        {
            if (ContainsIgnoreCase(section.name, name))
            {
                report.alreadyLattic = true;
                AddSignal(report, PackerKind::Lattic,
                          "section " + section.name, "Packed by Lattic");
                break;
            }
        }
    }

    if (!report.alreadyLattic)
    {
        for (const char* marker : kLatticMarkers)
        {
            if (image.find(marker) != std::string::npos)
            {
                report.alreadyLattic = true;
                AddSignal(report, PackerKind::Lattic,
                          std::string("marker ") + marker, "Packed by Lattic");
                break;
            }
        }
    }

    for (const auto& signature : kSignatures)
    {
        bool matched = false;

        for (const auto& section : parser.Sections())
        {
            if (ContainsIgnoreCase(section.name, signature.sectionName))
            {
                AddSignal(report, signature.kind,
                          "section " + section.name, signature.description);
                matched = true;
                break;
            }
        }

        if (!matched && signature.marker != nullptr &&
            image.find(signature.marker) != std::string::npos)
        {
            AddSignal(report, signature.kind,
                      std::string("marker ") + signature.marker, signature.description);
        }
    }

    report.isPacked = !report.all.empty();

    if (report.isPacked)
    {
        // Lattic wins the primary slot because it is the only one that hard blocks.
        for (const auto& signal : report.all)
        {
            if (signal.kind == PackerKind::Lattic)
            {
                report.primary = signal;
                break;
            }
        }

        if (report.primary.kind == PackerKind::None)
        {
            report.primary = report.all.front();
        }

        report.summary = report.all.size() == 1
            ? "Detected " + report.primary.description
            : "Detected " + std::to_string(report.all.size()) + " packing signatures";
    }
    else
    {
        report.summary = "No packing signatures found";
    }

    // Deliberately not logged here. The facade caches the result and logs once, because the
    // UI calls Analyze through DetectPacking on every rendered frame.
    return report;
}

std::string PackerDetector::BlockRepatch(const DetectionReport& report)
{
    if (report.alreadyLattic)
    {
        return "This binary is already packed by Lattic. Patching it again would append a "
               "second .lattic section at the same RVA and corrupt the image. Load the "
               "original, unpacked binary instead.";
    }

    return {};
}

const char* PackerDetector::KindName(PackerKind kind)
{
    switch (kind)
    {
    case PackerKind::None:       return "None";
    case PackerKind::Lattic:     return "Lattic";
    case PackerKind::UPX:        return "UPX";
    case PackerKind::Themida:    return "Themida";
    case PackerKind::VMProtect:  return "VMProtect";
    case PackerKind::ASPack:     return "ASPack";
    case PackerKind::MPRESS:     return "MPRESS";
    case PackerKind::Enigma:     return "Enigma";
    case PackerKind::PECompact:  return "PECompact";
    case PackerKind::Petite:     return "Petite";
    case PackerKind::Obsidium:   return "Obsidium";
    default:                     return "Unknown";
    }
}
}
