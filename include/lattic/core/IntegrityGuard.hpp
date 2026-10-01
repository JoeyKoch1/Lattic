#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lattic::core
{
class Binary;
class PeParser;

enum class TamperResponse
{
    Ignore,
    Dialog,
    Terminate
};

struct IntegrityOptions
{
    TamperResponse response = TamperResponse::Dialog;

    std::string dialogTitle   = "LatticProtect";
    std::string dialogMessage =
        "This executable has been modified and can no longer run.";

    std::uint32_t exitCode = 0xC0000005u;

    // Regions excluded from the digest. The entry trampoline and the .lattic section are
    // written after the digest is taken, so including them would make every image look
    // tampered with.
    std::vector<std::uint32_t> ignoredRvas;
};

struct IntegrityReport
{
    bool          intact      = true;
    std::uint32_t expected    = 0;
    std::uint32_t actual      = 0;
    std::string   section;    // the first section that no longer matches
    std::string   message;
};

// Detects post packing modification. The digest is a checksum over the mapped sections, so
// a byte flipped in the text or rdata section is caught, while relocation and import fixups
// that legitimately differ between builds are excluded.
class IntegrityGuard
{
public:
    IntegrityGuard() = default;
    ~IntegrityGuard() = default;

    IntegrityGuard(const IntegrityGuard&)            = delete;
    IntegrityGuard& operator=(const IntegrityGuard&) = delete;

    // Digest of the image, skipping any section whose RVA appears in options.ignoredRvas.
    static std::uint32_t ComputeDigest(const Binary& binary, const PeParser& parser,
                                       const std::vector<std::uint32_t>& ignoredRvas);

    // Recomputes and compares against a digest recorded at pack time.
    static IntegrityReport Verify(const Binary& binary, const PeParser& parser,
                                  std::uint32_t expected, const IntegrityOptions& options);

    static const char* ResponseName(TamperResponse response);
};
}
