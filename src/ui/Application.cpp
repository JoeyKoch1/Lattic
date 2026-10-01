#include "lattic/ui/Application.hpp"

#include <commdlg.h>

#include <imgui.h>
#include <imgui_internal.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>

#include "lattic/core/Binary.hpp"
#include "lattic/core/PeParser.hpp"
#include "lattic/core/Signature.hpp"
#include "lattic/core/mutate/JunkCodeEngine.hpp"
#include "lattic/util/Logger.hpp"
#include "lattic/util/StringUtil.hpp"

namespace lattic::ui
{
namespace
{
constexpr ImVec4 kAccent     = ImVec4(0.36f, 0.61f, 0.94f, 1.00f);
constexpr ImVec4 kAccentHover = ImVec4(0.44f, 0.69f, 1.00f, 1.00f);
constexpr ImVec4 kAccentActive = ImVec4(0.28f, 0.53f, 0.86f, 1.00f);
constexpr ImVec4 kDanger     = ImVec4(0.90f, 0.36f, 0.36f, 1.00f);
constexpr ImVec4 kSuccess    = ImVec4(0.42f, 0.78f, 0.44f, 1.00f);
constexpr ImVec4 kWarning    = ImVec4(0.94f, 0.72f, 0.32f, 1.00f);

constexpr float kSidePanelWidth = 320.0f;
constexpr float kNavWidth       = 168.0f;
constexpr float kStatusHeight   = 28.0f;

std::string TrimBuffer(const std::array<char, 512>& buf)
{
    return util::str::Trim(std::string(buf.data()));
}

std::string TrimBufferLarge(const std::array<char, 4096>& buf)
{
    return util::str::Trim(std::string(buf.data()));
}

// "0x" followed by sixteen uppercase hex digits, the same shape util::str::FormatVA
// produces, without the ostringstream it builds.
void FormatVaHex(char (&out)[20], std::uint64_t va)
{
    std::snprintf(out, sizeof(out), "0x%016llX", static_cast<unsigned long long>(va));
}

char FoldAscii(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

// Case insensitive substring search with no allocation on either side. needle must already
// be folded to lower case.
bool ContainsFold(const std::string& haystack, const std::string& needle)
{
    if (needle.empty())
    {
        return true;
    }

    if (needle.size() > haystack.size())
    {
        return false;
    }

    const std::size_t last = haystack.size() - needle.size();

    for (std::size_t i = 0; i <= last; ++i)
    {
        std::size_t j = 0;

        while (j < needle.size() && FoldAscii(haystack[i + j]) == needle[j])
        {
            ++j;
        }

        if (j == needle.size())
        {
            return true;
        }
    }

    return false;
}

void DrawSectionHeader(const char* label)
{
    ImGui::PushStyleColor(ImGuiCol_Text, kAccent);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
}

const char* NetworkTag(NetworkFinding::Kind kind)
{
    switch (kind)
    {
    case NetworkFinding::Kind::Dll:     return "dll";
    case NetworkFinding::Kind::Function:return "api";
    case NetworkFinding::Kind::Url:     return "url";
    case NetworkFinding::Kind::Host:    return "host";
    case NetworkFinding::Kind::Path:    return "path";
    case NetworkFinding::Kind::Header:  return "header";
    case NetworkFinding::Kind::JsonKey: return "json";
    }

    return "?";
}
}

// Keeps the one namespace block that the paging helpers share open across the file.
namespace
{
struct Pager
{
    int         page     = 0;
    int         pageSize = 100;
    std::size_t total    = 0;

    int PageCount() const
    {
        if (pageSize <= 0)
        {
            return 1;
        }
        return static_cast<int>((total + static_cast<std::size_t>(pageSize) - 1) /
                                static_cast<std::size_t>(pageSize));
    }

    void Clamp()
    {
        if (page >= PageCount())
        {
            page = PageCount() - 1;
        }
        if (page < 0)
        {
            page = 0;
        }
    }

    std::size_t First() const
    {
        return static_cast<std::size_t>(page) * static_cast<std::size_t>(pageSize);
    }

    std::size_t Last() const
    {
        const std::size_t end = First() + static_cast<std::size_t>(pageSize);
        return end < total ? end : total;
    }
};

const char* kPageSizes[] = { "50", "100", "250", "500" };
const int   kPageValues[] = { 50, 100, 250, 500 };

// Everything that lines up in a column of controls hangs off these, so labels, enable
// boxes and sliders all start at the same x on every panel.
constexpr float kLabelColumn = 196.0f;
constexpr float kCheckColumn = 196.0f;
constexpr float kSliderColumn = 230.0f;

// The percentage readout the slider formats for itself needs a fixed slice on the right,
// otherwise a wide slider pushes the value off the edge of the panel.
constexpr float kValueColumn = 66.0f;

// One row of an intensity control: a label, an enable box and a percentage slider. The
// slider is what dims when the pass is off, so the label and the box stay readable.
void DrawIntensityRow(const char* id, const char* label, bool& enabled, int& rate)
{
    ImGui::PushID(id);

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(label);

    ImGui::SameLine(kCheckColumn);
    ImGui::Checkbox("##enabled", &enabled);

    ImGui::SameLine(kSliderColumn);

    if (!enabled)
    {
        ImGui::BeginDisabled();
    }

    ImGui::SetNextItemWidth(-kValueColumn);
    ImGui::SliderInt("##rate", &rate, 0, 100, "%d%%");

    if (!enabled)
    {
        ImGui::EndDisabled();
    }

    ImGui::PopID();
}

// A label and a slider with no enable box, for the settings that are always live. The
// slider still starts at the slider column so it lines up with the intensity rows above.
void DrawLabeledSlider(const char* id, const char* label, int& value, int min, int max,
                       const char* format)
{
    ImGui::PushID(id);

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(label);

    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(-kValueColumn);
    ImGui::SliderInt("##value", &value, min, max, format);

    ImGui::PopID();
}

void FormatBytes(std::size_t bytes, char (&out)[64])
{
    static const char* kUnits[] = { "B", "KB", "MB", "GB" };

    double value  = static_cast<double>(bytes);
    std::size_t unit = 0;

    while (value >= 1024.0 && unit + 1 < 4)
    {
        value /= 1024.0;
        ++unit;
    }

    std::snprintf(out, 64, "%.2f %s", value, kUnits[unit]);
}

void DrawPager(Pager& pager, const char* unit)
{
    if (pager.pageSize <= 0)
    {
        pager.pageSize = 100;
    }

    ImGui::TextDisabled("%zu %s", pager.total, unit);

    ImGui::SameLine();

    if (ImGui::Button("<", ImVec2(28.0f, 0.0f)))
    {
        --pager.page;
    }

    ImGui::SameLine();
    ImGui::Text("Page %d / %d", pager.page + 1, pager.PageCount());
    ImGui::SameLine();

    if (ImGui::Button(">", ImVec2(28.0f, 0.0f)))
    {
        ++pager.page;
    }

    ImGui::SameLine();
    ImGui::TextUnformatted("Per page");

    ImGui::SameLine();
    ImGui::SetNextItemWidth(90.0f);

    int selected = 1;
    for (int i = 0; i < IM_ARRAYSIZE(kPageValues); ++i)
    {
        if (kPageValues[i] == pager.pageSize)
        {
            selected = i;
        }
    }

    if (ImGui::Combo("##pagesize", &selected, kPageSizes, IM_ARRAYSIZE(kPageSizes)))
    {
        pager.pageSize = kPageValues[selected];
        pager.Clamp();
    }

    pager.Clamp();
}
}

Application::Application() = default;

Application::~Application()
{
    Shutdown();
}

bool Application::Init(HWND hwnd)
{
    m_hwnd      = hwnd;
    m_hInstance = ::GetModuleHandleW(nullptr);

    ApplyTheme();
    LoadFonts();

    // The server borrows the core, so it is attached here and stopped before the facade is
    // torn down in Shutdown.
    m_mcp.Attach(&m_core);

    m_statusMessage = "Ready. Load an EXE or DLL to begin.";
    m_initialized   = true;

    util::Logger::Info("Application initialized");
    return true;
}

void Application::Shutdown()
{
    if (!m_initialized)
    {
        return;
    }

    // The server holds a pointer to m_core, so it has to go down first.
    m_mcp.Stop();

    m_core.UnloadBinary();
    m_initialized = false;

    util::Logger::Info("Application shutdown");
}

const std::uint8_t* Application::EmbeddedFont(std::size_t& byteCount) const
{
    byteCount = 0;

    const HRSRC resource = ::FindResourceA(m_hInstance, MAKEINTRESOURCEA(IDR_LATTIC_FONT),
                                           RT_RCDATA);

    if (resource == nullptr)
    {
        return nullptr;
    }

    const HGLOBAL handle = ::LoadResource(m_hInstance, resource);

    if (handle == nullptr)
    {
        return nullptr;
    }

    byteCount = ::SizeofResource(m_hInstance, resource);

    if (byteCount == 0)
    {
        return nullptr;
    }

    return static_cast<const std::uint8_t*>(::LockResource(handle));
}

void Application::ApplyTheme()
{
    ImGuiStyle& style = ImGui::GetStyle();
    ImGui::StyleColorsDark();

    // Metrics are tuned for a 16px monospace face. Everything is a little roomier than
    // the ImGui defaults, which are sized for a 13px proportional font.
    style.WindowPadding     = ImVec2(12.0f, 10.0f);
    style.FramePadding      = ImVec2(10.0f, 6.0f);
    style.CellPadding       = ImVec2(6.0f, 4.0f);
    style.ItemSpacing       = ImVec2(10.0f, 7.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 5.0f);
    style.IndentSpacing     = 20.0f;
    style.ScrollbarSize     = 14.0f;
    style.GrabMinSize       = 12.0f;

    // Rounded corners read better against a flat dark background than the square defaults,
    // and the rounding doubles as a disabled-state cue on framed widgets.
    style.WindowRounding    = 0.0f;
    style.ChildRounding     = 4.0f;
    style.FrameRounding     = 4.0f;
    style.PopupRounding     = 6.0f;
    style.GrabRounding      = 4.0f;
    style.ScrollbarRounding = 8.0f;
    style.TabRounding       = 4.0f;
    style.WindowBorderSize  = 0.0f;
    style.ChildBorderSize   = 1.0f;
    style.FrameBorderSize   = 0.0f;
    style.PopupBorderSize   = 1.0f;
    style.DisabledAlpha     = 0.45f;

    ImVec4* colors = style.Colors;

    colors[ImGuiCol_WindowBg]            = ImVec4(0.086f, 0.090f, 0.110f, 1.00f);
    colors[ImGuiCol_ChildBg]             = ImVec4(0.067f, 0.071f, 0.086f, 1.00f);
    colors[ImGuiCol_PopupBg]             = ImVec4(0.098f, 0.102f, 0.125f, 1.00f);
    colors[ImGuiCol_Border]              = ImVec4(0.180f, 0.192f, 0.230f, 1.00f);
    colors[ImGuiCol_FrameBg]             = ImVec4(0.118f, 0.129f, 0.161f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]      = ImVec4(0.161f, 0.180f, 0.227f, 1.00f);
    colors[ImGuiCol_FrameBgActive]       = ImVec4(0.204f, 0.235f, 0.302f, 1.00f);
    colors[ImGuiCol_TitleBg]             = ImVec4(0.086f, 0.090f, 0.110f, 1.00f);
    colors[ImGuiCol_TitleBgActive]       = ImVec4(0.118f, 0.129f, 0.161f, 1.00f);
    colors[ImGuiCol_MenuBarBg]           = ImVec4(0.075f, 0.079f, 0.098f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]         = ImVec4(0.067f, 0.071f, 0.086f, 1.00f);
    colors[ImGuiCol_ScrollbarGrab]       = ImVec4(0.220f, 0.239f, 0.290f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.300f, 0.325f, 0.390f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.360f, 0.610f, 0.940f, 1.00f);
    colors[ImGuiCol_CheckMark]           = kAccent;
    colors[ImGuiCol_SliderGrab]          = kAccent;
    colors[ImGuiCol_SliderGrabActive]    = kAccentHover;
    colors[ImGuiCol_Button]              = ImVec4(0.145f, 0.161f, 0.204f, 1.00f);
    colors[ImGuiCol_ButtonHovered]       = ImVec4(0.204f, 0.235f, 0.302f, 1.00f);
    colors[ImGuiCol_ButtonActive]        = kAccentActive;
    colors[ImGuiCol_Header]              = ImVec4(0.145f, 0.161f, 0.204f, 1.00f);
    colors[ImGuiCol_HeaderHovered]       = ImVec4(0.204f, 0.235f, 0.302f, 1.00f);
    colors[ImGuiCol_HeaderActive]        = kAccentActive;
    colors[ImGuiCol_Separator]           = ImVec4(0.180f, 0.192f, 0.230f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]    = kAccent;
    colors[ImGuiCol_SeparatorActive]     = kAccentHover;
    colors[ImGuiCol_TableHeaderBg]       = ImVec4(0.125f, 0.137f, 0.172f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]   = ImVec4(0.180f, 0.192f, 0.230f, 1.00f);
    colors[ImGuiCol_TableBorderLight]    = ImVec4(0.145f, 0.157f, 0.192f, 1.00f);
    colors[ImGuiCol_TableRowBg]          = ImVec4(0.000f, 0.000f, 0.000f, 0.000f);
    colors[ImGuiCol_TableRowBgAlt]       = ImVec4(1.000f, 1.000f, 1.000f, 0.020f);
    colors[ImGuiCol_Text]                = ImVec4(0.878f, 0.890f, 0.918f, 1.00f);
    colors[ImGuiCol_TextDisabled]        = ImVec4(0.478f, 0.502f, 0.557f, 1.00f);
    colors[ImGuiCol_NavCursor]           = ImVec4(0.360f, 0.610f, 0.940f, 0.40f);
    colors[ImGuiCol_NavWindowingHighlight] = ImVec4(0.360f, 0.610f, 0.940f, 0.20f);
}

void Application::LoadFonts()
{
    ImGuiIO& io = ImGui::GetIO();

    std::size_t fontBytes = 0;
    const auto*  fontData  = EmbeddedFont(fontBytes);
    io.Fonts->Clear();

    if (fontData == nullptr || fontBytes == 0)
    {
        // No embedded font, fall back to the built in one so the tool still starts.
        util::Logger::Warn("Application: embedded font missing, using the built in font");
        m_fontRegular = io.Fonts->AddFontDefault();
        m_fontSmall  = m_fontRegular;
        io.FontDefault = m_fontRegular;
        return;
    }

    // Basic Latin plus the punctuation, arrows, box drawing and block glyphs the panels
    // draw, so nothing renders as a fallback box.
    static const ImWchar kRanges[] =
    {
        0x0020, 0x00FF,   // Basic Latin, Latin-1 Supplement
        0x2010, 0x2027,   // Dashes and quotes
        0x20AC, 0x20AC,   // Euro
        0x2190, 0x21FF,   // Arrows
        0x2500, 0x257F,   // Box Drawing
        0x2580, 0x259F,   // Block Elements
        0x25A0, 0x25FF,   // Geometric Shapes
        0x0000
    };

    // A monospace face at one to one oversampling with horizontal pixel snapping stays
    // crisp; oversampling only blurs the glyph edges of a fixed pitch font.
    //
    // FontDataOwnedByAtlas must stay false. The bytes live in the executable's resource
    // section, so the atlas freeing them would be a crash on a pointer it never owned.
    ImFontConfig config;
    config.OversampleH        = 1;
    config.OversampleV        = 1;
    config.PixelSnapH         = true;
    config.FontDataOwnedByAtlas = false;
    auto* mutableData = const_cast<unsigned char*>(fontData);
    const auto dataSize = static_cast<int>(fontBytes);

    m_fontRegular = io.Fonts->AddFontFromMemoryTTF(mutableData, dataSize, m_fontSize,
                                                  &config, kRanges);

    if (m_fontRegular == nullptr)
    {
        m_fontRegular = io.Fonts->AddFontDefault();
        m_fontSmall  = m_fontRegular;
        io.FontDefault = m_fontRegular;
        return;
    }

    // A second, smaller cut from the same data for tables and the log, so the atlas holds
    // one face at two sizes instead of loading the file twice.
    const float smallSize = m_fontSize - 3.0f;

    m_fontSmall = io.Fonts->AddFontFromMemoryTTF(mutableData, dataSize, smallSize,
                                                &config, kRanges);

    if (m_fontSmall == nullptr)
    {
        m_fontSmall = m_fontRegular;
    }

    io.FontDefault = m_fontRegular;

    util::Logger::Info("Application: loaded JetBrains Mono at " +
                       std::to_string(static_cast<int>(m_fontSize)) + "px and " +
                       std::to_string(static_cast<int>(smallSize)) + "px");
}

void Application::Animate(float& value, float target, float rate)
{
    // Exponential decay toward the target, using the frame time so the motion looks the
    // same at 30 and 240 frames per second. Capped so a stalled frame cannot overshoot.
    const float dt = m_animDelta;
    value += (target - value) * (1.0f - std::exp(-rate * dt));
}

void Application::Update()
{
    // The panel fade is a one shot on switch, so it is reset here rather than inside the
    // nav handler, which does not run on the frame the selection changes.
    static Panel s_previousPanel = Panel::Count;

    if (s_previousPanel != m_panel)
    {
        s_previousPanel = m_panel;
        m_panelFade     = 0.0f;
    }

    m_animDelta = std::min(ImGui::GetIO().DeltaTime, 0.1f);
    Animate(m_panelFade, 1.0f, 14.0f);

    HandleShortcuts();
    DrawMenuBar();
    DrawSidePanel();
    DrawMainPanel();
    DrawStatusBar();
    DrawAboutModal();
    DrawFileDialog();
}

void Application::HandleShortcuts()
{
    ImGuiIO& io = ImGui::GetIO();

    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false))
    {
        m_pendingPath = "OPEN";
    }

    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S, false))
    {
        SavePatched();
    }

    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Q, false))
    {
        ::PostQuitMessage(0);
    }
}

void Application::DrawMenuBar()
{
    if (!ImGui::BeginMainMenuBar())
    {
        return;
    }

    if (ImGui::BeginMenu("File"))
    {
        if (ImGui::MenuItem("Open...", "Ctrl+O"))
        {
            m_pendingPath = "OPEN";
        }

        if (ImGui::MenuItem("Save", "Ctrl+S", false, m_core.IsLoaded()))
        {
            SavePatched();
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Unload", nullptr, false, m_core.IsLoaded()))
        {
            m_core.UnloadBinary();
            m_selectedStrings.clear();
            m_visibleStrings.clear();
            m_statusMessage = "Binary unloaded.";
            m_dirty         = false;
            InvalidateCaches();
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Exit", "Ctrl+Q"))
        {
            ::PostQuitMessage(0);
        }

        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View"))
    {
        static const char* kNames[] =
        {
            "Strings", "Patches", "Mutation", "Junk", "VM",
            "Network", "MCP", "Debugger", "Log", "Info"
        };

        for (int i = 0; i < IM_ARRAYSIZE(kNames); ++i)
        {
            const Panel target = static_cast<Panel>(i);

            if (ImGui::MenuItem(kNames[i], nullptr, m_panel == target))
            {
                m_panel = target;
            }
        }
    }

    if (ImGui::BeginMenu("Help"))
    {
        if (ImGui::MenuItem("About"))
        {
            m_showAbout = true;
        }
        ImGui::EndMenu();
    }

    ImGui::EndMainMenuBar();
}

void Application::DrawSidePanel()
{
    const float top = ImGui::GetFrameHeight();
    const float displayWidth = ImGui::GetIO().DisplaySize.x;
    const float displayHeight = ImGui::GetIO().DisplaySize.y;

    // Below roughly 1000px the two fixed columns leave nothing for the content, so the
    // side panel narrows first and then drops off the bottom at very small heights.
    const float panelWidth = std::clamp(displayWidth * 0.25f, 240.0f, kSidePanelWidth);

    ImGui::SetNextWindowPos(ImVec2(0.0f, top));
    ImGui::SetNextWindowSize(ImVec2(panelWidth, displayHeight - top - kStatusHeight));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar |
                             ImGuiWindowFlags_NoSavedSettings;

    ImGui::Begin("##side", nullptr, flags);

    ImGui::TextColored(kAccent, "Lattic");
    ImGui::SameLine();
    ImGui::TextDisabled("%s", Lattic::Version());

    ImGui::Separator();

    if (m_core.IsLoaded())
    {
        // The path is clipped to the panel and the full string goes in a tooltip, so a
        // deep path cannot push the counters below it out of view.
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(m_loadedPathCache.c_str());
        ImGui::PopTextWrapPos();

        if (ImGui::IsItemHovered())
        {
            ImGui::SetTooltip("%s", m_loadedPathCache.c_str());
        }

        ImGui::TextDisabled("Candidates: %zu", m_core.StringCandidateCount());
        ImGui::TextDisabled("Selected:   %zu", m_selectedStrings.size());
        ImGui::TextDisabled("Staged:     %zu", m_core.StagedPatchCount());
    }
    else
    {
        ImGui::TextDisabled("No binary loaded");
    }

    ImGui::Separator();

    DrawSectionHeader("Options");

    ImGui::Checkbox("Encrypt strings", &m_encryptStrings);
    ImGui::Checkbox("Strip debug info", &m_stripDebugInfo);
    ImGui::Checkbox("Backup on save", &m_backupOnSave);
    ImGui::Checkbox("Preserve checksum", &m_preserveChecksum);

    // The side panel is a third of the window wide, so it uses its own much narrower
    // column rather than the main panel's, or the slider has no track left.
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Min length");
    ImGui::SameLine(96.0f);
    ImGui::SetNextItemWidth(-46.0f);
    if (ImGui::SliderInt("##minlen", &m_minStringLength, 4, 32, "%d",
                         ImGuiSliderFlags_AlwaysClamp))
    {
        RescanStrings();
    }

    ImGui::Separator();

    DrawSectionHeader("Stage a patch");

    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##va", "VA (0x...)", m_patchVaBuffer.data(),
                             m_patchVaBuffer.size(), ImGuiInputTextFlags_CharsHexadecimal);

    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextMultiline("##bytes", m_patchBytesBuffer.data(), m_patchBytesBuffer.size(),
                              ImVec2(-1.0f, 60.0f));

    if (ImGui::Button("Stage", ImVec2(-1.0f, 0.0f)))
    {
        std::string vaText    = TrimBuffer(m_patchVaBuffer);
        std::string bytesText = TrimBufferLarge(m_patchBytesBuffer);

        std::vector<std::uint8_t> bytes;

        if (vaText.empty() || !util::str::HexToBytes(bytesText, bytes))
        {
            m_statusMessage = "Invalid bytes. Use hex like DE AD BE EF.";
        }
        else
        {
            const std::uint64_t va = std::strtoull(vaText.c_str(), nullptr, 16);

            if (va == 0)
            {
                m_statusMessage = "Invalid virtual address.";
            }
            else if (m_core.StagePatch(va, bytes))
            {
                m_statusMessage = "Patch staged.";
                m_dirty         = true;
                m_patchVaBuffer.fill(0);
                m_patchBytesBuffer.fill(0);
            }
            else
            {
                m_statusMessage = m_core.LastError();
            }
        }
    }

    ImGui::Spacing();

    if (ImGui::Button("Clear staged", ImVec2(-1.0f, 0.0f)))
    {
        m_core.ClearStagedPatches();
        m_statusMessage = "Staged patches cleared.";
        m_dirty         = false;
    }

    ImGui::BeginDisabled(!m_core.IsLoaded());

    if (ImGui::Button("Patch and save", ImVec2(-1.0f, 32.0f)))
    {
        SavePatched();
    }

    ImGui::EndDisabled();

    ImGui::End();
}

void Application::DrawNavRail()
{
    static const char* kLabels[] =
    {
        "Strings", "Patches", "Mutation", "Junk", "VM",
        "Network", "MCP", "Debugger", "Log", "Info"
    };

    static const char* kHints[] =
    {
        "String candidates", "Staged regions", "IR rewrite passes", "Junk insertion",
        "Virtualization", "Network surface", "MCP server", "Anti-debug", "Log", "Binary info"
    };

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6.0f, 8.0f));
    const bool visible = ImGui::BeginChild("##nav", ImVec2(kNavWidth, 0.0f),
                                           ImGuiChildFlags_Borders,
                                           ImGuiWindowFlags_NoScrollbar |
                                           ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();

    if (!visible)
    {
        ImGui::EndChild();
        return;
    }

    const float   rowHeight = ImGui::GetFrameHeight();
    ImDrawList*   draw      = ImGui::GetWindowDrawList();

    for (int i = 0; i < IM_ARRAYSIZE(kLabels); ++i)
    {
        const Panel target = static_cast<Panel>(i);
        const bool  active = (m_panel == target);

        float& anim = m_navAnim[static_cast<std::size_t>(i)];
        Animate(anim, active ? 1.0f : 0.0f, 16.0f);

        const ImVec2 rowMin = ImGui::GetCursorScreenPos();
        const ImVec2 rowMax = ImVec2(rowMin.x + ImGui::GetContentRegionAvail().x,
                                     rowMin.y + rowHeight);

        // The accent bar is drawn behind the label and eases in with the row, which is the
        // only animation in the app that responds to a click rather than a hover.
        if (anim > 0.001f)
        {
            ImVec4 bar = kAccent;
            bar.w      = anim;
            draw->AddRectFilled(ImVec2(rowMin.x, rowMin.y),
                                ImVec2(rowMin.x + 3.0f, rowMax.y),
                                ImGui::GetColorU32(bar), 1.5f);

            ImVec4 wash = kAccent;
            wash.w     = 0.10f * anim;
            draw->AddRectFilled(rowMin, rowMax, ImGui::GetColorU32(wash), 4.0f);
        }

        ImGui::PushStyleColor(ImGuiCol_Text,
                              active ? kAccent : ImGui::GetStyleColorVec4(ImGuiCol_Text));
        ImGui::PushStyleVar(ImGuiStyleVar_SelectableTextAlign, ImVec2(0.0f, 0.5f));

        if (ImGui::Selectable(kLabels[i], active, ImGuiSelectableFlags_None,
                              ImVec2(0.0f, rowHeight)))
        {
            m_panel = target;
        }

        ImGui::PopStyleVar();
        ImGui::PopStyleColor();

        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip))
        {
            ImGui::SetTooltip("%s", kHints[i]);
        }

        ImGui::Spacing();
    }

    ImGui::EndChild();
}

void Application::DrawPanelHeader(const char* title, const char* summary)
{
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(kAccent, "%s", title);

    if (summary != nullptr && *summary != '\0')
    {
        // Right aligned against the content edge so the row does not reflow when the
        // summary text changes length.
        const ImVec2 size = ImGui::CalcTextSize(summary);
        const float  right = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;

        ImGui::SameLine(right - size.x);
        ImGui::TextDisabled("%s", summary);
    }

    ImGui::Separator();
}

void Application::DrawMainPanel()
{
    const float top = ImGui::GetFrameHeight();
    const float displayWidth = ImGui::GetIO().DisplaySize.x;
    const float displayHeight = ImGui::GetIO().DisplaySize.y;

    const float sideWidth = std::clamp(displayWidth * 0.25f, 240.0f, kSidePanelWidth);

    ImGui::SetNextWindowPos(ImVec2(sideWidth, top));
    ImGui::SetNextWindowSize(ImVec2(displayWidth - sideWidth, displayHeight - top -
                                    kStatusHeight));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoSavedSettings;

    if (!ImGui::Begin("##main", nullptr, flags))
    {
        ImGui::End();
        return;
    }

    DrawNavRail();

    ImGui::SameLine(0.0f, 6.0f);

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha *
                                            (0.65f + 0.35f * m_panelFade));

    if (ImGui::BeginChild("##panel", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None))
    {
        DrawActivePanel();
    }

    ImGui::EndChild();
    ImGui::PopStyleVar();

    ImGui::End();
}

void Application::DrawActivePanel()
{
    RefreshFilter();
    RefreshLoadedPath();

    switch (m_panel)
    {
    case Panel::Strings:  DrawStringsTab();  break;
    case Panel::Patches:  DrawPatchesTab();  break;
    case Panel::Mutation: DrawMutationTab(); break;
    case Panel::Junk:     DrawJunkTab();     break;
    case Panel::Vm:       DrawVmTab();       break;
    case Panel::Network:  DrawNetworkTab();  break;
    case Panel::Mcp:      DrawMcpTab();      break;
    case Panel::Debugger: DrawDebuggerTab(); break;
    case Panel::Log:      DrawLogTab();      break;
    case Panel::Info:     DrawInfoTab();     break;
    case Panel::Count:    break;
    }
}

void Application::RefreshFilter()
{
    // The filter is compared against a cached copy instead of reading ImGui's per item
    // edit state, so the check works no matter which panel currently owns the input.
    if (std::strcmp(m_filterRawCache.c_str(), m_filterBuffer.data()) == 0)
    {
        return;
    }

    m_filterRawCache = m_filterBuffer.data();
    m_filterCache    = util::str::ToLower(util::str::Trim(m_filterRawCache));
    m_visibleDirty   = true;
    m_stringPage     = 0;
}

void Application::RefreshLoadedPath()
{
    if (m_loadedCache == m_core.IsLoaded())
    {
        return;
    }

    m_loadedCache = m_core.IsLoaded();
    m_loadedPathCache = m_loadedCache ? m_core.LoadedPath() : std::string();
}

void Application::RefreshNetwork()
{
    if (!m_networkDirty)
    {
        return;
    }

    m_networkDirty = false;
    m_network      = m_core.NetworkSurface();
    m_networkPage  = 0;
}

void Application::RefreshSections()
{
    if (!m_sectionsDirty)
    {
        return;
    }

    m_sectionsDirty = false;
    m_sections      = m_core.Sections();
}

void Application::RefreshStaged()
{
    const std::size_t count = m_core.StagedPatchCount();

    if (count == m_stagedCount)
    {
        return;
    }

    m_stagedCount = count;
    m_staged      = m_core.StagedPatches();
    m_patchPage   = 0;
}

void Application::RefreshPacking()
{
    if (!m_packingDirty)
    {
        return;
    }

    m_packingDirty     = false;
    m_packingReport    = m_core.DetectPacking();
    m_packingSignatures = m_core.PackingSignatures();
}

void Application::RefreshMcpLog()
{
    // RecentLog copies every buffered line and Stats takes the server mutex, so both are
    // sampled on a timer rather than every frame.
    const double now = ImGui::GetTime();

    if (m_mcpLogStamp >= 0.0 && now - m_mcpLogStamp < 0.25)
    {
        return;
    }

    m_mcpLogStamp = now;
    m_mcpStats   = m_mcp.Stats();
    m_mcpLog     = m_mcp.RecentLog();
}

void Application::InvalidateCaches()
{
    m_visibleDirty  = true;
    m_networkDirty  = true;
    m_sectionsDirty = true;
    m_packingDirty  = true;
    m_stagedCount   = static_cast<std::size_t>(-1);
    m_mcpLogStamp   = -1.0;
    m_loadedCache   = m_core.IsLoaded();
    m_loadedPathCache = m_loadedCache ? m_core.LoadedPath() : std::string();
}

void Application::RebuildVisible()
{
    m_visibleStrings.clear();

    const auto& candidates = m_core.StringCandidates();

    m_visibleStrings.reserve(candidates.size());

    if (m_filterCache.empty())
    {
        for (std::size_t i = 0; i < candidates.size(); ++i)
        {
            m_visibleStrings.push_back(i);
        }
    }
    else
    {
        for (std::size_t i = 0; i < candidates.size(); ++i)
        {
            if (ContainsFold(candidates[i].preview, m_filterCache))
            {
                m_visibleStrings.push_back(i);
            }
        }
    }

    m_visibleCount = candidates.size();
    m_visibleDirty = false;
}

void Application::DrawMutationTab()
{
    DrawPanelHeader("Mutation", "IR rewrite passes");

    ImGui::TextWrapped(
        "Mutation rewrites real instructions into equivalent but differently encoded forms. "
        "Each pass has its own intensity, so you can turn one up while leaving the others "
        "alone. Every rewrite below is semantics preserving.");
    ImGui::Separator();

    if (ImGui::CollapsingHeader("Passes", ImGuiTreeNodeFlags_DefaultOpen))
    {
        DrawIntensityRow("sub", "Substitution", m_enableSubstitution, m_substitutionRate);
        DrawIntensityRow("mba", "Mixed boolean arithmetic", m_enableMba, m_mbaRate);
        DrawIntensityRow("opaque", "Opaque predicates", m_enableOpaquePredicate,
                         m_opaquePredicateRate);
        DrawIntensityRow("dead", "Dead code", m_enableDeadCode, m_deadCodeRate);
        DrawIntensityRow("const", "Constant obfuscation", m_enableConstantObfus,
                         m_constantRate);
    }

    ImGui::Spacing();

    if (ImGui::CollapsingHeader("Target selection", ImGuiTreeNodeFlags_DefaultOpen))
    {
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Randomise sites");
        ImGui::SameLine(kCheckColumn);
        ImGui::Checkbox("##randomize", &m_mutationRandomize);
        ImGui::SameLine();
        ImGui::TextDisabled("off = deterministic, same input gives same output");

        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted("Seed");
        ImGui::SameLine(kSliderColumn);
        ImGui::SetNextItemWidth(160.0f);
        if (ImGui::Button("Roll a new seed"))
        {
            m_mutationSeed = static_cast<std::uint32_t>(GetTickCount64());
        }
        ImGui::SameLine();
        ImGui::TextDisabled("%u", m_mutationSeed);
    }

    ImGui::Separator();
    ImGui::TextDisabled("Preview only. Mutation runs on lifted IR, so it is reported here "
                        "rather than written into the image.");
}

void Application::DrawJunkTab()
{
    DrawPanelHeader("Junk", "Junk insertion");

    ImGui::TextWrapped(
        "Junk code inserts runs of instructions that write only to their own destination, so "
        "the surrounding code cannot observe them. Density is the chance of a run at any "
        "insertion point.");
    ImGui::Separator();

    DrawIntensityRow("junk", "Junk insertion", m_junk.enabled, m_junk.rate);

    ImGui::Spacing();

    if (!m_junk.enabled)
    {
        ImGui::BeginDisabled();
    }

    DrawLabeledSlider("junkDensity", "Density", m_junkDensity, 0, 100, "%d%%");
    DrawLabeledSlider("junkMin", "Min run", m_junkMinRun, 1, 16, "%d");
    DrawLabeledSlider("junkMax", "Max run", m_junkMaxRun, 1, 32, "%d");

    if (!m_junk.enabled)
    {
        ImGui::EndDisabled();
    }

    if (m_junkMaxRun < m_junkMinRun)
    {
        m_junkMaxRun = m_junkMinRun;
    }

    ImGui::Separator();
    ImGui::Text("Catalog: %zu run shapes, 1 to 5 bytes each.",
                core::mutate::JunkCodeEngine::Catalog().size());
    ImGui::TextWrapped("Junk is never spliced before a branch, return or two byte opcode in "
                       "the input, so an inserted run cannot swallow a displacement.");
}

void Application::DrawVmTab()
{
    DrawPanelHeader("VM", "Virtualization");

    ImGui::TextWrapped(
        "Virtualization lifts a code range into the bytecode interpreter and executes it in a "
        "handler. Intensity selects how much of the binary is virtualized.");
    ImGui::Separator();

    DrawIntensityRow("vm", "Virtualization", m_vm.enabled, m_vm.rate);

    ImGui::Spacing();

    if (!m_vm.enabled)
    {
        ImGui::BeginDisabled();
    }

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Randomise handler");
    ImGui::SameLine(kCheckColumn);
    ImGui::Checkbox("##vmRandomize", &m_vm.randomize);

    DrawLabeledSlider("vmSeed", "Seed", m_vmSeed, 0, 1000000, "%d");
    m_vm.seed = static_cast<std::uint32_t>(m_vmSeed);

    if (!m_vm.enabled)
    {
        ImGui::EndDisabled();
    }

    ImGui::Separator();
    ImGui::TextWrapped("Not yet wired into the patcher. Lifting, bytecode translation and the "
                       "interpreter all work and are covered by tests, but no bytecode is "
                       "injected into a target image yet, so this tab reports rather than "
                       "protects.");
}

void Application::DrawNetworkTab()
{
    DrawPanelHeader("Network", "Network surface");

    ImGui::TextWrapped(
        "Static survey of the loaded binary: which networking libraries and APIs it imports, "
        "and which of its string literals look like URLs, hosts, API paths, HTTP headers or "
        "JSON keys. This reads the image only and does not observe live traffic.");
    ImGui::Separator();

    if (!m_core.IsLoaded())
    {
        ImGui::TextDisabled("Load a binary first.");
        return;
    }

    RefreshNetwork();

    if (ImGui::Button("Rescan"))
    {
        m_networkDirty = true;
        RefreshNetwork();
    }

    ImGui::SameLine();

    if (ImGui::Button("Select these for encryption"))
    {
        if (m_core.SelectNetworkStrings())
        {
            m_statusMessage = "Selected network strings for encryption";
            m_visibleDirty  = true;
        }
        else
        {
            m_statusMessage = m_core.LastError();
        }
    }

    ImGui::Spacing();

    ImGui::Checkbox("Encrypt network strings on save", &m_encryptNetworkStrings);

    ImGui::Spacing();

    if (m_network.empty())
    {
        ImGui::TextDisabled("Nothing networking related was found in this binary.");
        return;
    }

    Pager pager;
    pager.page     = m_networkPage;
    pager.pageSize = m_pageSize;
    pager.total    = m_network.size();
    pager.Clamp();

    DrawPager(pager, "finding(s)");

    m_networkPage = pager.page;

    ImGui::PushFont(m_fontSmall);

    if (ImGui::BeginTable("##networkTable", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, -1.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Tag", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Finding");
        ImGui::TableHeadersRow();

        for (std::size_t i = pager.First(); i < pager.Last(); ++i)
        {
            const NetworkFinding& finding = m_network[i];

            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(i));

            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", NetworkTag(finding.kind));

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(finding.section.c_str());

            ImGui::TableNextColumn();

            // A URL literal can be far wider than the column, so the cell is given the
            // column's width and the full value stays in a tooltip.
            const ImVec2 cellAvail = ImGui::GetContentRegionAvail();
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + cellAvail.x);
            ImGui::TextUnformatted(finding.value.c_str());
            ImGui::PopTextWrapPos();

            if (ImGui::IsItemHovered())
            {
                ImGui::SetTooltip("%s", finding.value.c_str());
            }

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    ImGui::PopFont();
}

void Application::DrawDebuggerTab()
{
    DrawPanelHeader("Debugger", "Anti-debug");

    ImGui::TextWrapped(
        "Names to watch for while the packed program runs. The extension is added for you, "
        "so typing x64dbg is enough. Matching ignores case and the .exe suffix.");
    ImGui::Separator();

    DrawSectionHeader("Watched processes");

    // Typing a name and pressing the add button, or just pressing enter.
    ImGui::SetNextItemWidth(-90.0f);

    // ImGui writes a fixed size buffer in place. It cannot be a std::string, because the
    // string's length would never change and the text could never be read back out.
    const bool submitted = ImGui::InputTextWithHint("##debuggerName", "Debugger name...",
                                                    m_debuggerInput.data(),
                                                    m_debuggerInput.size());

    ImGui::SameLine();

    bool add = ImGui::Button("+ Add", ImVec2(80.0f, 0.0f));

    if (add || submitted)
    {
        std::string name = m_debuggerInput.data();

        // Trim, then normalise to a bare name so the engine matches either form.
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t'))
        {
            name.erase(name.begin());
        }

        while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
        {
            name.pop_back();
        }

        const std::size_t dot = name.rfind(".exe");

        if (dot != std::string::npos && dot + 4 == name.size())
        {
            name.erase(dot);
        }

        if (name.empty())
        {
            m_statusMessage = "Enter a debugger name first.";
        }
        else if (std::find(m_debuggerNames.begin(), m_debuggerNames.end(), name) !=
                 m_debuggerNames.end())
        {
            m_statusMessage = name + " is already on the list.";
        }
        else
        {
            m_debuggerNames.push_back(name);
            m_debuggerInput[0] = '\0';
        }
    }

    ImGui::Spacing();

    if (m_debuggerNames.empty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted("No debuggers configured. Common ones: x64dbg, x32dbg, windbg, "
                                "ollydbg, ida, ida64, dnspy, cheatengine");
        ImGui::PopTextWrapPos();
        ImGui::PopStyleColor();
    }
    else
    {
        if (ImGui::BeginChild("##debuggerList", ImVec2(0.0f, 150.0f), ImGuiChildFlags_None,
                              ImGuiWindowFlags_HorizontalScrollbar))
        {
            int removeIndex = -1;

            for (std::size_t i = 0; i < m_debuggerNames.size(); ++i)
            {
                ImGui::PushID(static_cast<int>(i));
                ImGui::TextUnformatted((m_debuggerNames[i] + ".exe").c_str());
                ImGui::SameLine(ImGui::GetContentRegionAvail().x - 60.0f);

                if (ImGui::SmallButton("Remove"))
                {
                    removeIndex = static_cast<int>(i);
                }

                ImGui::PopID();
            }

            if (removeIndex >= 0)
            {
                m_debuggerNames.erase(m_debuggerNames.begin() + removeIndex);
            }
        }

        ImGui::EndChild();

        ImGui::SameLine();

        if (ImGui::Button("Clear all"))
        {
            m_debuggerNames.clear();
        }
    }

    ImGui::Separator();

    DrawSectionHeader("Anti-debug");

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Enable anti-debug");
    ImGui::SameLine(kCheckColumn);
    ImGui::Checkbox("##antidebugEnabled", &m_antidebugEnabled);

    ImGui::BeginDisabled(!m_antidebugEnabled);

    static const char* kResponses[] = { "Ignore", "Message box", "Terminate" };

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Poll interval");
    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(180.0f);
    ImGui::SliderInt("##poll", &m_pollIntervalMs, 1, 1000, "%d ms");
    ImGui::SameLine();
    ImGui::TextDisabled("timer based, not a spin loop");

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("On detection");
    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(180.0f);
    ImGui::Combo("##debugResponse", &m_debugResponse, kResponses, 3);

    ImGui::Spacing();
    ImGui::TextDisabled("Checks, each independently switchable:");
    ImGui::Checkbox("Process debug port", &m_checkDebugPort);
    ImGui::SameLine();
    ImGui::Checkbox("Debug object handle", &m_checkDebugObjectHandle);
    ImGui::SameLine();
    ImGui::Checkbox("Debug flags", &m_checkDebugFlags);
    ImGui::Checkbox("Hardware breakpoints", &m_checkHardwareBreakpoints);
    ImGui::SameLine();
    ImGui::Checkbox("Remote debugger", &m_checkRemoteDebugger);
    ImGui::SameLine();
    ImGui::Checkbox("Debugger processes", &m_checkDebuggerProcesses);

    ImGui::EndDisabled();

    ImGui::Separator();

    DrawSectionHeader("Tamper");

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Enable tamper dialog");
    ImGui::SameLine(kCheckColumn);
    ImGui::Checkbox("##tamperEnabled", &m_tamperEnabled);

    ImGui::BeginDisabled(!m_tamperEnabled);

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("On tamper");
    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(180.0f);
    ImGui::Combo("##tamperResponse", &m_tamperResponse, kResponses, 3);

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Message");
    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(-1.0f);
    std::array<char, 256> messageBuffer = {};
    std::snprintf(messageBuffer.data(), messageBuffer.size(), "%s",
                  m_tamperMessage.c_str());

    if (ImGui::InputText("##tamperMessage", messageBuffer.data(), messageBuffer.size()))
    {
        m_tamperMessage = messageBuffer.data();
    }

    ImGui::EndDisabled();
}

void Application::DrawMcpTab()
{
    DrawPanelHeader("MCP", "MCP server");

    ImGui::TextWrapped(
        "Starts a local Model Context Protocol server so an AI assistant can drive Lattic "
        "over HTTP. It binds to the loopback interface only, so nothing off this machine can "
        "reach it.");
    ImGui::Separator();

    RefreshMcpLog();

    DrawSectionHeader("Endpoint");

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Port");
    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputInt("##port", &m_mcpPort);

    if (m_mcpPort < 1024 || m_mcpPort > 65535)
    {
        ImGui::TextColored(kDanger, "Port must be 1024 to 65535.");
    }

    ImGui::Spacing();

    if (m_mcp.IsRunning())
    {
        if (ImGui::Button("Stop server"))
        {
            m_mcp.Stop();
            m_statusMessage = "MCP server stopped";
            m_mcpLogStamp   = -1.0;
        }

        ImGui::SameLine();
        ImGui::TextColored(kSuccess, "Running on %s", m_mcp.Url().c_str());

        if (ImGui::Button("Copy endpoint"))
        {
            ImGui::SetClipboardText(m_mcp.Url().c_str());
            m_statusMessage = "Endpoint copied to the clipboard";
        }
    }
    else
    {
        ImGui::BeginDisabled(m_mcpPort < 1024 || m_mcpPort > 65535);

        if (ImGui::Button("Start server"))
        {
            m_mcp.Attach(&m_core);

            if (m_mcp.Start(static_cast<std::uint16_t>(m_mcpPort)))
            {
                m_statusMessage = "MCP server started on " + m_mcp.Url();
                m_mcpLogStamp   = -1.0;
            }
            else
            {
                m_statusMessage = "MCP server failed to start: " + m_mcp.LastError();
            }
        }

        ImGui::EndDisabled();
    }

    ImGui::Separator();

    DrawSectionHeader("Session");

    char counters[192] = {};
    std::snprintf(counters, sizeof(counters),
                  "Requests %llu     Tools %llu     Errors %llu     Connections %llu",
                  static_cast<unsigned long long>(m_mcpStats.requests),
                  static_cast<unsigned long long>(m_mcpStats.toolCalls),
                  static_cast<unsigned long long>(m_mcpStats.errors),
                  static_cast<unsigned long long>(m_mcpStats.connections));

    ImGui::TextUnformatted(counters);

    ImGui::Spacing();

    if (ImGui::Button("Clear log"))
    {
        m_mcp.ClearLog();
        m_mcpLog.clear();
    }

    ImGui::SameLine();
    ImGui::TextDisabled("last method: %s",
                        m_mcpStats.lastMethod.empty() ? "none" :
                                                        m_mcpStats.lastMethod.c_str());

    ImGui::Spacing();

    if (ImGui::BeginChild("##mcpLog", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None))
    {
        if (m_mcpLog.empty())
        {
            ImGui::TextDisabled("No requests yet.");
        }

        for (const auto& line : m_mcpLog)
        {
            ImGui::TextDisabled("%s", line.time.c_str());
            ImGui::SameLine();

            if (line.isError)
            {
                ImGui::TextColored(kDanger, "%s", line.text.c_str());
            }
            else
            {
                ImGui::TextUnformatted(line.text.c_str());
            }
        }
    }

    ImGui::EndChild();
}

void Application::DrawInfoTab()
{
    if (!m_core.IsLoaded())
    {
        DrawPanelHeader("Info", "Binary info");
        ImGui::TextDisabled("Load a binary first.");
        return;
    }

    RefreshPacking();
    RefreshSections();

    char sizeBuffer[64] = {};
    FormatBytes(m_core.CurrentFileSize(), sizeBuffer);

    DrawPanelHeader("Info", sizeBuffer);

    DrawSectionHeader("Image");

    ImGui::TextUnformatted("File:");
    ImGui::SameLine();
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(m_loadedPathCache.c_str());
    ImGui::PopTextWrapPos();

    if (ImGui::IsItemHovered())
    {
        ImGui::SetTooltip("%s", m_loadedPathCache.c_str());
    }

    char baseBuffer[20] = {};
    char entryBuffer[20] = {};
    FormatVaHex(baseBuffer, m_core.ImageBase());
    FormatVaHex(entryBuffer, m_core.EntryPointRva());

    ImGui::Text("Size: %s", sizeBuffer);
    ImGui::Text("Image base: %s", baseBuffer);
    ImGui::Text("Entry point: %s", entryBuffer);
    ImGui::Text("String candidates: %zu", m_core.StringCandidateCount());
    ImGui::Text("Selected: %zu", m_core.SelectedStrings().size());

    ImGui::Separator();

    DrawSectionHeader("Packing detection");

    if (m_packingSignatures.empty())
    {
        ImGui::TextColored(kSuccess, "No packing signatures found.");
    }
    else
    {
        for (const auto& signature : m_packingSignatures)
        {
            ImGui::BulletText("%s", signature.c_str());
        }
    }

    if (!m_packingReport.empty())
    {
        ImGui::Spacing();
        ImGui::TextWrapped("%s", m_packingReport.c_str());
    }

    ImGui::Separator();

    DrawSectionHeader("Output size");

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Pad output");
    ImGui::SameLine(kCheckColumn);
    ImGui::Checkbox("##padOutput", &m_padOutput);
    ImGui::SameLine();
    ImGui::TextDisabled("grow the file to a fixed size, never shrink it");

    ImGui::BeginDisabled(!m_padOutput);

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Target size");
    ImGui::SameLine(kSliderColumn);
    ImGui::SetNextItemWidth(160.0f);
    ImGui::InputInt("##targetMb", &m_targetFileSizeMb, 1, 10);
    ImGui::SameLine();
    ImGui::TextDisabled("MB, currently %s", sizeBuffer);

    if (m_targetFileSizeMb > 0)
    {
        const std::size_t wanted = static_cast<std::size_t>(m_targetFileSizeMb) * 1024 * 1024;

        if (wanted <= m_core.CurrentFileSize())
        {
            ImGui::TextColored(kDanger, "Target is below the current size and will be ignored.");
        }
        else
        {
            char padBuffer[64] = {};
            FormatBytes(wanted - m_core.CurrentFileSize(), padBuffer);
            ImGui::TextDisabled("Output will be padded by %s.", padBuffer);
        }
    }

    ImGui::EndDisabled();

    ImGui::Separator();

    DrawSectionHeader("Sections");

    if (m_sections.empty())
    {
        ImGui::TextDisabled("The parser reported no sections.");
        return;
    }

    ImGui::PushFont(m_fontSmall);

    if (ImGui::BeginTable("##sectionTable", 6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, -1.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Virtual", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Raw", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        for (const auto& section : m_sections)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(section.name.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%08X", section.rva);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", section.virtualSize);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", section.rawSize);
            ImGui::TableNextColumn();

            std::string flags;

            if (section.Readable())   { flags += "R"; }
            if (section.Writable())   { flags += "W"; }
            if (section.Executable()) { flags += "X"; }

            ImGui::TextUnformatted(flags.c_str());
        }

        ImGui::EndTable();
    }

    ImGui::PopFont();
}

void Application::DrawStringsTab()
{
    if (ImGui::Button("Rescan"))
    {
        RescanStrings();
    }

    ImGui::SameLine();

    if (ImGui::Button("Select all"))
    {
        SelectAllVisible();
    }

    ImGui::SameLine();

    if (ImGui::Button("Invert"))
    {
        InvertStringSelection();
    }

    ImGui::SameLine();

    if (ImGui::Button("Clear selection"))
    {
        ClearStringSelection();
    }

    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##filter", "Filter...", m_filterBuffer.data(),
                             m_filterBuffer.size());

    ImGui::Separator();

    if (!m_core.IsLoaded())
    {
        ImGui::TextDisabled("Load a binary to scan for strings.");
        return;
    }
    // The scan is only re-filtered when the filter text or the candidate set moved, never
    // just because a frame was drawn.
    if (m_visibleDirty || m_visibleCount != m_core.StringCandidateCount())
    {
        RebuildVisible();
    }

    char summary[96] = {};
    std::snprintf(summary, sizeof(summary), "%zu of %zu shown, %zu selected",
                  m_visibleStrings.size(), m_core.StringCandidateCount(),
                  m_selectedStrings.size());

    DrawPanelHeader("Strings", summary);

    Pager pager;
    pager.page     = m_stringPage;
    pager.pageSize = m_pageSize;
    pager.total    = m_visibleStrings.size();
    pager.Clamp();

    DrawPager(pager, "candidates shown");

    m_stringPage = pager.page;
    m_pageSize   = pager.pageSize;

    if (m_visibleStrings.empty())
    {
        ImGui::TextDisabled("Nothing matched. Clear the filter or load a binary.");
        return;
    }

    const auto& candidates = m_core.StringCandidates();

    ImGui::PushFont(m_fontSmall);

    if (ImGui::BeginTable("##stringTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, -1.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("##sel", ImGuiTableColumnFlags_WidthFixed, 34.0f);
        ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 78.0f);
        ImGui::TableSetupColumn("Len", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Preview");
        ImGui::TableHeadersRow();

        for (std::size_t i = pager.First(); i < pager.Last(); ++i)
        {
            const StringInfo& info     = candidates[m_visibleStrings[i]];
            bool              selected = IsSelected(info.rva);

            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(info.rva));

            ImGui::TableNextColumn();

            if (ImGui::Checkbox("##s", &selected))
            {
                ToggleSelection(info.rva);
            }

            ImGui::TableNextColumn();

            char vaBuffer[20] = {};
            FormatVaHex(vaBuffer, info.rva);
            ImGui::TextUnformatted(vaBuffer);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(info.section.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%u", info.byteLength);

            ImGui::TableNextColumn();

            // The selectable is confined to this column. Giving it SpanAllColumns would
            // make it overlap the checkbox, and one click would toggle the row twice.
            if (ImGui::Selectable(info.preview.c_str(), selected,
                                  ImGuiSelectableFlags_AllowDoubleClick))
            {
                ToggleSelection(info.rva);
            }

            if (ImGui::IsItemHovered())
            {
                ImGui::SetTooltip("RVA %s\nfile offset 0x%X\n%u bytes in %s%s",
                                  vaBuffer, info.fileOffset,
                                  info.byteLength, info.section.c_str(),
                                  info.utf16 ? "\nUTF-16LE" : "");
            }

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    ImGui::PopFont();
}

void Application::DrawPatchesTab()
{
    RefreshStaged();

    char summary[48] = {};
    std::snprintf(summary, sizeof(summary), "%zu staged region(s)", m_staged.size());

    DrawPanelHeader("Patches", summary);

    if (!m_staged.empty())
    {
        if (ImGui::Button("Clear all"))
        {
            m_core.ClearStagedPatches();
            m_dirty = false;
        }
    }

    ImGui::Separator();

    if (m_staged.empty())
    {
        ImGui::TextDisabled("No patches staged. Use the side panel to add one.");
        return;
    }

    Pager pager;
    pager.page     = m_patchPage;
    pager.pageSize = m_pageSize;
    pager.total    = m_staged.size();
    pager.Clamp();

    DrawPager(pager, "regions");

    m_patchPage = pager.page;

    ImGui::PushFont(m_fontSmall);

    if (ImGui::BeginTable("##patchTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, -1.0f)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Bytes");
        ImGui::TableSetupColumn("##rm", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableHeadersRow();
        for (std::size_t i = pager.First(); i < pager.Last(); ++i)
        {
            const StagedInfo& info = m_staged[i];

            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(info.va));

            ImGui::TableNextColumn();

            char vaBuffer[20] = {};
            FormatVaHex(vaBuffer, info.va);
            ImGui::TextUnformatted(vaBuffer);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(info.section.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%zu", info.length);

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(util::str::Ellipsize(info.preview, 96).c_str());

            ImGui::TableNextColumn();
            if (ImGui::SmallButton("x"))
            {
                if (m_core.UnstagePatch(info.va))
                {
                    m_statusMessage = "Region removed.";
                }
            }

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    ImGui::PopFont();
}

void Application::DrawLogTab()
{
    const std::vector<util::LogEntry>& entries = util::Logger::Recent();

    char summary[48] = {};
    std::snprintf(summary, sizeof(summary), "%zu line(s)", entries.size());

    DrawPanelHeader("Log", summary);

    // The scroll position has to be read inside the child, because that is the window that
    // actually scrolls. Reading it in the parent tracks the panel, not the log.
    ImGui::BeginChild("##log", ImVec2(0.0f, -ImGui::GetFrameHeightWithSpacing() - 4.0f),
                      ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f;

    if (ImGui::Button("Scroll to end"))
    {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::SameLine();
    if (ImGui::Button("Clear"))
    {
        util::Logger::ClearRecent();
    }

    ImGui::SameLine();
    ImGui::TextDisabled("newest last");

    ImGui::Separator();

    ImGui::PushFont(m_fontSmall);

    for (const auto& entry : entries)
    {
        if (entry.level == "ERR ")
        {
            ImGui::TextColored(kDanger, "%s", entry.message.c_str());
        }
        else if (entry.level == "WARN")
        {
            ImGui::TextColored(kWarning, "%s", entry.message.c_str());
        }
        else
        {
            ImGui::TextUnformatted(entry.message.c_str());
        }
    }

    if (atBottom)
    {
        ImGui::SetScrollHereY(1.0f);
    }

    ImGui::PopFont();
    ImGui::EndChild();
}

void Application::RescanStrings()
{
    m_selectedStrings.clear();
    m_stringPage = 0;

    const std::size_t count =
        m_core.RescanStrings(static_cast<std::size_t>(m_minStringLength), 4096);

    m_dirty       = false;
    m_visibleDirty = true;
    m_networkDirty = true;

    if (m_core.LastError().empty())
    {
        m_statusMessage = "Rescan found " + std::to_string(count) + " candidates.";
    }
    else
    {
        m_statusMessage = m_core.LastError();
    }
}

void Application::SelectAllVisible()
{
    const auto& candidates = m_core.StringCandidates();

    // The visible list is already the filtered set, so this walks that instead of
    // re-running the filter over every candidate.
    m_selectedStrings.clear();
    m_selectedStrings.reserve(m_visibleStrings.size());

    for (std::size_t index : m_visibleStrings)
    {
        m_selectedStrings.push_back(candidates[index].rva);
    }

    std::sort(m_selectedStrings.begin(), m_selectedStrings.end());

    m_statusMessage = "Selected " + std::to_string(m_selectedStrings.size()) + " string(s).";
}

void Application::InvertStringSelection()
{
    const std::vector<std::uint32_t> before = m_selectedStrings;
    const auto&                      candidates = m_core.StringCandidates();

    m_selectedStrings.clear();
    m_selectedStrings.reserve(before.size() + m_visibleStrings.size());

    // Hidden rows keep whatever they had, so inverting what is on screen does not silently
    // drop a selection the user made before filtering.
    for (std::uint32_t rva : before)
    {
        const bool visible = std::any_of(m_visibleStrings.begin(), m_visibleStrings.end(),
                                         [&candidates, rva](std::size_t index)
                                         { return candidates[index].rva == rva; });

        if (!visible)
        {
            m_selectedStrings.push_back(rva);
        }
    }

    for (std::size_t index : m_visibleStrings)
    {
        const std::uint32_t rva = candidates[index].rva;

        if (std::find(before.begin(), before.end(), rva) == before.end())
        {
            m_selectedStrings.push_back(rva);
        }
    }

    std::sort(m_selectedStrings.begin(), m_selectedStrings.end());

    m_statusMessage = "Selection is now " + std::to_string(m_selectedStrings.size()) +
                      " string(s).";
}

void Application::ClearStringSelection()
{
    m_selectedStrings.clear();
    m_statusMessage = "Selection cleared.";
}

bool Application::IsSelected(std::uint32_t rva) const
{
    return std::binary_search(m_selectedStrings.begin(), m_selectedStrings.end(), rva);
}

bool Application::MatchesFilter(const StringInfo& info) const
{
    return ContainsFold(info.preview, m_filterCache);
}

void Application::ToggleSelection(std::uint32_t rva)
{
    const auto it = std::lower_bound(m_selectedStrings.begin(), m_selectedStrings.end(), rva);

    if (it != m_selectedStrings.end() && *it == rva)
    {
        m_selectedStrings.erase(it);
        return;
    }

    m_selectedStrings.insert(it, rva);
}

void Application::DrawStatusBar()
{
    const float width  = ImGui::GetIO().DisplaySize.x;
    const float height = kStatusHeight;

    ImGui::SetNextWindowPos(ImVec2(0.0f, ImGui::GetIO().DisplaySize.y - height));
    ImGui::SetNextWindowSize(ImVec2(width, height));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar |
                             ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoInputs;

    ImGui::Begin("##status", nullptr, flags);

    ImGui::AlignTextToFramePadding();

    // Clipped to the left of the right hand badge, so a long message cannot push the
    // unsaved changes indicator off the end of the bar.
    const float  badgeWidth = 130.0f;
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float  limit = std::max(40.0f, avail.x - (m_dirty ? badgeWidth : 0.0f));

    ImGui::PushClipRect(ImGui::GetCursorScreenPos(),
                       ImVec2(ImGui::GetCursorScreenPos().x + limit,
                              ImGui::GetCursorScreenPos().y + ImGui::GetTextLineHeight()),
                       true);
    ImGui::TextUnformatted(m_statusMessage.c_str());
    ImGui::PopClipRect();

    if (m_dirty)
    {
        const ImVec2 size   = ImGui::CalcTextSize("Unsaved changes");
        const float  right  = ImGui::GetWindowContentRegionMax().x;

        ImGui::SetCursorPosX(right - size.x);
        ImGui::TextColored(kWarning, "Unsaved changes");

        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        {
            ImGui::SetTooltip("The output file on disk does not match these settings.");
        }
    }

    ImGui::End();
}

void Application::DrawAboutModal()
{
    if (m_showAbout)
    {
        ImGui::OpenPopup("About Lattic");
    }

    if (ImGui::BeginPopupModal("About Lattic", &m_showAbout,
                               ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::TextColored(kAccent, "Lattic");
        ImGui::SameLine();
        ImGui::TextDisabled("%s", Lattic::Version());

        ImGui::Separator();
        ImGui::Spacing();

        ImGui::TextWrapped("Next-gen Windows application packer.");
        ImGui::TextWrapped("Load an EXE or DLL, select what to patch, done.");

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Close", ImVec2(120.0f, 0.0f)))
        {
            m_showAbout = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void Application::DrawFileDialog()
{
    if (m_pendingPath != "OPEN")
    {
        return;
    }

    m_pendingPath.clear();

    OPENFILENAMEA ofn = {};
    char          path[MAX_PATH] = {};

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = m_hwnd;
    ofn.lpstrFilter = "PE Files (*.exe;*.dll)\0*.exe;*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (::GetOpenFileNameA(&ofn) == TRUE)
    {
        OpenFile(path);
    }
}

void Application::OpenFile(const std::string& path)
{
    if (m_core.LoadBinary(path))
    {
        m_selectedStrings.clear();
        m_visibleStrings.clear();
        m_stringPage = 0;
        m_patchPage  = 0;
        m_statusMessage = "Loaded " + util::str::FileName(path);
        m_dirty         = false;
        InvalidateCaches();
    }
    else
    {
        m_statusMessage = m_core.LastError();
    }
}

void Application::SavePatched()
{
    if (!m_core.IsLoaded())
    {
        m_statusMessage = "Nothing loaded.";
        return;
    }

    // "Encrypt network strings" folds its selection into whatever the user picked on the
    // Strings tab, rather than replacing it.
    if (m_encryptNetworkStrings && !m_core.SelectNetworkStrings())
    {
        m_statusMessage = m_core.LastError();
        return;
    }

    if (!m_core.SelectStrings(m_selectedStrings))
    {
        m_statusMessage = m_core.LastError();
        return;
    }

    PatchOptions options;
    options.encryptStrings   = m_encryptStrings;
    options.stripDebugInfo   = m_stripDebugInfo;
    options.backupOnSave     = m_backupOnSave;
    options.preserveChecksum = m_preserveChecksum;

    if (m_padOutput && m_targetFileSizeMb > 0)
    {
        options.targetFileSize =
            static_cast<std::size_t>(m_targetFileSizeMb) * 1024u * 1024u;
    }

    const PatchResult result = m_core.ApplyAndSave("", options);

    if (result.success)
    {
        m_statusMessage = result.message;
        m_dirty         = false;

        // Encryption rewrites the image, so the candidate list is stale afterwards.
        m_selectedStrings.clear();
        m_core.RescanStrings(static_cast<std::size_t>(m_minStringLength), 4096);
        m_visibleDirty  = true;
        m_networkDirty  = true;
        m_sectionsDirty = true;
    }
    else
    {
        m_statusMessage = result.message.empty() ? m_core.LastError() : result.message;
    }
}
}
