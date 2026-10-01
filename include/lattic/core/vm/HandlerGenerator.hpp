#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "lattic/core/vm/VmArchitecture.hpp"

namespace lattic::core::vm
{
using VmHandlerFn = bool (*)(void* ctx, std::uint64_t immediate, std::uint8_t reg);

struct HandlerTableEntry
{
    VmOp          op      = VmOp::Nop;
    VmHandlerFn   handler = nullptr;
    std::uint32_t seed    = 0;
};

class HandlerGenerator
{
public:
    HandlerGenerator();

    void Generate();
    void Shuffle(std::uint32_t seed);

    const std::vector<HandlerTableEntry>& Table() const;

    std::size_t HandlerCount() const;

    std::vector<std::uint8_t> SerializeTable() const;

    const std::string& LastError() const;

private:
    std::vector<HandlerTableEntry> m_table;
    std::string m_lastError;
};
}