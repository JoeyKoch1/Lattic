cmake_minimum_required(VERSION 3.21)

project(Lattic
    VERSION 0.1.0
    DESCRIPTION "Windows application packer for EXE and DLL files"
    LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Lattic targets Windows only.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Lattic targets x64 only. Configure with -A x64.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/utf-8)
endif()

option(LATTIC_BUILD_TESTS "Build the Lattic test suite" ON)

# The UI font is embedded as a resource so the tool stays one executable.
enable_language(RC)

function(lattic_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /EHsc)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# =================================================================================================
# Zydis
# =================================================================================================
# Zydis detects that it is not the root project and defaults its examples, tools, tests and
# documentation targets to OFF, so only the static library ends up in the solution.
add_subdirectory(external/zydis EXCLUDE_FROM_ALL)

# =================================================================================================
# Dear ImGui
# =================================================================================================

set(LATTIC_IMGUI_DIR external/imgui)

add_library(lattic_imgui STATIC
    ${LATTIC_IMGUI_DIR}/imgui.cpp
    ${LATTIC_IMGUI_DIR}/imgui_draw.cpp
    ${LATTIC_IMGUI_DIR}/imgui_tables.cpp
    ${LATTIC_IMGUI_DIR}/imgui_widgets.cpp
    ${LATTIC_IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    ${LATTIC_IMGUI_DIR}/backends/imgui_impl_win32.cpp)

target_include_directories(lattic_imgui PUBLIC
    ${LATTIC_IMGUI_DIR}
    ${LATTIC_IMGUI_DIR}/backends)

target_link_libraries(lattic_imgui PUBLIC d3d11 dxgi user32 dwmapi)

# =================================================================================================
# Core
# =================================================================================================

add_library(lattic_core STATIC
    src/Lattic.cpp
    src/core/AntiDebug.cpp
    src/core/Binary.cpp
    src/core/IntegrityGuard.cpp
    src/core/PackerDetector.cpp
    src/core/PeParser.cpp
    src/core/Patcher.cpp
    src/core/Signature.cpp
    src/core/StringEncryptor.cpp
    src/core/StringScanner.cpp
    src/core/mutate/JunkCodeEngine.cpp
    src/core/mutate/MutationEngine.cpp
    src/core/mutate/MutationPasses.cpp
    src/core/vm/Bytecode.cpp
    src/core/vm/CodeVirtualizer.cpp
    src/core/vm/HandlerGenerator.cpp
    src/core/vm/Interpreter.cpp
    src/core/vm/Ir.cpp
    src/core/vm/Lifter.cpp
    src/core/vm/Translator.cpp
    src/core/vm/VmArchitecture.cpp
    src/mcp/McpServer.cpp
    src/util/Json.cpp
    src/util/Logger.cpp
    src/util/StringUtil.cpp)

target_include_directories(lattic_core PUBLIC include)

target_link_libraries(lattic_core PUBLIC Zydis::Zydis ws2_32)

lattic_set_warnings(lattic_core)

# =================================================================================================
# Application
# =================================================================================================

add_executable(Lattic WIN32
    src/Lattic.rc
    src/main.cpp
    src/ui/Application.cpp)

set_source_files_properties(src/Lattic.rc PROPERTIES
    INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(Lattic PRIVATE
    lattic_core
    lattic_imgui
    comdlg32
    d3d11
    dxgi
    user32
    ws2_32)

lattic_set_warnings(Lattic)

# =================================================================================================
# Tests
# =================================================================================================

if(LATTIC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
