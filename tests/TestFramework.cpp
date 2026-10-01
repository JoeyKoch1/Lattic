#include "TestFramework.hpp"

#include <cstring>
#include <vector>

namespace lattic::test
{
namespace
{
std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> registry;
    return registry;
}

int g_failuresInCurrentTest = 0;
}

void Register(const char* suite, const char* name, void (*fn)())
{
    Registry().push_back(TestCase{ suite, name, fn });
}

void Fail(const char* file, int line, const std::string& message)
{
    ++g_failuresInCurrentTest;
    std::fprintf(stderr, "    %s:%d: %s\n", file, line, message.c_str());
}

int RunAll()
{
    int failed = 0;
    int passed = 0;

    for (const auto& test : Registry())
    {
        g_failuresInCurrentTest = 0;

        std::fprintf(stderr, "[ RUN      ] %s.%s\n", test.suite, test.name);
        test.fn();

        if (g_failuresInCurrentTest == 0)
        {
            ++passed;
            std::fprintf(stderr, "[       OK ] %s.%s\n", test.suite, test.name);
        }
        else
        {
            ++failed;
            std::fprintf(stderr, "[  FAILED  ] %s.%s\n", test.suite, test.name);
        }
    }

    std::fprintf(stderr, "\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
}
