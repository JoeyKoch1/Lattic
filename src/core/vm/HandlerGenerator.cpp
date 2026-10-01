#include "lattic/core/vm/HandlerGenerator.hpp"

#include <algorithm>
#include <cstring>
#include <random>

namespace lattic::core::vm
{
namespace
{
struct HandlerCtx
{
    std::uint64_t* regs = nullptr;
    std::uint8_t*  stack = nullptr;
    std::size_t    sp = 0;
    std::size_t    stackSize = 0;
    std::uint64_t  lastCmp = 0;
};

bool Placeholder(void*, std::uint64_t, std::uint8_t)
{
    return true;
}

std::uint32_t HashOp(VmOp op)
{
    std::uint32_t h = 2166136261u;
    h = (h ^ static_cast<std::uint32_t>(op)) * 16777619u;
    return h;
}
}

HandlerGenerator::HandlerGenerator()
{
    Generate();
}

void HandlerGenerator::Generate()
{
    m_table.clear();
    m_table.reserve(static_cast<std::size_t>(VmOp::Count));

    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(VmOp::Count); ++i)
    {
        HandlerTableEntry entry;
        entry.op      = static_cast<VmOp>(i);
        entry.handler = &Placeholder;
        entry.seed    = HashOp(entry.op);
        m_table.push_back(entry);
    }
}

void HandlerGenerator::Shuffle(std::uint32_t seed)
{
    std::mt19937 rng(seed);
    std::shuffle(m_table.begin(), m_table.end(), rng);
}

const std::vector<HandlerTableEntry>& HandlerGenerator::Table() const
{
    return m_table;
}

std::size_t HandlerGenerator::HandlerCount() const
{
    return m_table.size();
}

std::vector<std::uint8_t> HandlerGenerator::SerializeTable() const
{
    std::vector<std::uint8_t> out;

    out.reserve(m_table.size() * 6);

    for (const auto& entry : m_table)
    {
        out.push_back(static_cast<std::uint8_t>(entry.op));

        const auto ptr = reinterpret_cast<std::uintptr_t>(entry.handler);

        for (int i = 0; i < 8; ++i)
        {
            out.push_back(static_cast<std::uint8_t>((ptr >> (i * 8)) & 0xFF));
        }
    }

    return out;
}

const std::string& HandlerGenerator::LastError() const
{
    return m_lastError;
}
}