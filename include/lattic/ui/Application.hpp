#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "lattic/Lattic.hpp"
#include "lattic/mcp/McpServer.hpp"
#include "lattic/ui/Resources.hpp"

struct ImFont;

namespace lattic::ui
{
class Application
{
public:
    Application();
    ~Application();

    Application(const Application&)            = delete;
    Application& operator=(const Application&) = delete;

    bool Init(HWND hwnd);
    void Update();
    void Shutdown();

private:
    // One entry per page of the main panel. The nav rail replaces a tab bar because ten
    // tabs overflow a single row at 1280 wide, and a vertical list grows with the window.
    enum class Panel
    {
        Strings,
        Patches,
        Mutation,
        Junk,
        Vm,
        Network,
        Mcp,
        Debugger,
        Log,
        Info,
        Count
    };

    void ApplyTheme();
    void LoadFonts();

    // Returns the embedded UI font, or null when the resource is missing. sizeOut receives
    // the byte count of the font data.
    const std::uint8_t* EmbeddedFont(std::size_t& byteCount) const;

    void DrawMenuBar();
    void DrawSidePanel();
    void DrawMainPanel();
    void DrawNavRail();
    void DrawPanelHeader(const char* title, const char* summary);
    void DrawActivePanel();
    void DrawStringsTab();
    void DrawPatchesTab();
    void DrawMutationTab();
    void DrawJunkTab();
    void DrawVmTab();
    void DrawNetworkTab();
    void DrawDebuggerTab();
    void DrawMcpTab();
    void DrawInfoTab();
    void DrawLogTab();
    void DrawStatusBar();
    void DrawAboutModal();
    void DrawFileDialog();
    void HandleShortcuts();

    void OpenFile(const std::string& path);
    void SavePatched();

    void RescanStrings();
    void SelectAllVisible();
    void ClearStringSelection();
    void InvertStringSelection();

    // Frame rate independent exponential approach toward target. Used for the nav highlight
    // and the panel fade; nothing here overshoots.
    void Animate(float& value, float target, float rate);

    bool IsSelected(std::uint32_t rva) const;
    bool MatchesFilter(const StringInfo& info) const;
    void ToggleSelection(std::uint32_t rva);

    // Indices into m_visibleStrings, recomputed whenever the filter or the scan changes.
    void RebuildVisible();

    // Cheap per frame guards. The facade accessors below rebuild their backing vector on
    // every call, so each one is copied out once and refreshed only when its inputs move.
    void RefreshFilter();
    void RefreshLoadedPath();
    void RefreshNetwork();
    void RefreshSections();
    void RefreshStaged();
    void RefreshPacking();
    void RefreshMcpLog();
    void InvalidateCaches();

    HWND        m_hwnd = nullptr;
    HINSTANCE   m_hInstance = nullptr;
    bool        m_initialized = false;
    bool        m_showAbout = false;
    bool        m_dirty = false;

    std::string m_statusMessage;
    std::string m_pendingPath;
    std::string m_lastOutputPath;

    Panel       m_panel = Panel::Strings;
    float       m_panelFade = 1.0f;
    float       m_animDelta = 0.0f;
    std::array<float, static_cast<std::size_t>(Panel::Count)> m_navAnim = {};

    std::vector<std::uint32_t> m_selectedStrings;
    std::vector<std::size_t>   m_visibleStrings;
    std::string                m_filterRawCache;
    std::string                m_filterCache;
    std::string                m_loadedPathCache;
    std::size_t                m_visibleCount = 0;
    bool                       m_visibleDirty = true;
    bool                       m_loadedCache   = false;

    std::vector<NetworkFinding> m_network;
    bool                        m_networkDirty = true;
    std::vector<SectionInfo>    m_sections;
    bool                        m_sectionsDirty = true;
    std::vector<StagedInfo>     m_staged;
    std::size_t                 m_stagedCount = static_cast<std::size_t>(-1);
    std::string                 m_packingReport;
    std::vector<std::string>    m_packingSignatures;
    bool                        m_packingDirty = true;

    mcp::ServerStats        m_mcpStats;
    std::vector<mcp::LogLine> m_mcpLog;
    double                  m_mcpLogStamp = -1.0;

    std::string m_scratch;

    std::array<char, 512> m_patchVaBuffer = {};
    std::array<char, 4096> m_patchBytesBuffer = {};
    std::array<char, 256> m_filterBuffer = {};

    bool m_encryptStrings = false;
    bool m_stripDebugInfo = false;
    bool m_backupOnSave = true;
    bool m_preserveChecksum = true;
    int  m_minStringLength = 6;

    // Per pass intensity, mirroring the engine's own options so the numbers here mean the
    // same thing the passes actually use.
    FeatureIntensity m_mutation;
    FeatureIntensity m_junk;
    FeatureIntensity m_vm;

    bool m_enableSubstitution     = true;
    bool m_enableMba              = true;
    bool m_enableOpaquePredicate  = true;
    bool m_enableDeadCode         = true;
    bool m_enableConstantObfus    = true;

    int  m_substitutionRate    = 100;
    int  m_mbaRate             = 40;
    int  m_opaquePredicateRate = 25;
    int  m_deadCodeRate        = 35;
    int  m_constantRate        = 60;

    bool m_mutationRandomize = true;
    std::uint32_t m_mutationSeed = 0xCAFEBABE;

    int  m_junkDensity   = 35;
    int  m_junkMinRun    = 2;
    int  m_junkMaxRun    = 6;

    bool m_encryptNetworkStrings = false;

    int  m_targetFileSizeMb = 0;
    bool m_padOutput        = false;
    int  m_vmSeed           = 0;

    int m_mcpPort = 8765;
    bool m_mcpWantsToRun = false;

    // Anti-debug configuration, shared with the tamper guard.
    std::vector<std::string> m_debuggerNames;
    std::array<char, 128>    m_debuggerInput = {};
    int           m_pollIntervalMs = 10;
    int           m_debugResponse  = 1;   // 0 ignore, 1 message box, 2 terminate
    bool m_antidebugEnabled = false;

    bool m_checkDebugPort           = true;
    bool m_checkDebugObjectHandle   = true;
    bool m_checkDebugFlags          = true;
    bool m_checkHardwareBreakpoints = true;
    bool m_checkRemoteDebugger      = true;
    bool m_checkDebuggerProcesses   = true;

    bool m_tamperEnabled = false;
    int  m_tamperResponse = 1;
    std::string m_tamperMessage = "This executable has been modified and can no longer run.";

    int m_stringPage = 0;
    int m_patchPage  = 0;
    int m_networkPage = 0;
    int m_pageSize   = 100;

    Lattic m_core;
    mcp::McpServer m_mcp;
    ImFont* m_fontRegular = nullptr;
    ImFont* m_fontSmall  = nullptr;
    float   m_fontSize   = 16.0f;
};
}
