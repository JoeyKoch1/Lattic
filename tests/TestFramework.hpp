#pragma once

#include <cstdio>
#include <string>

namespace lattic::test
{
struct TestCase
{
    const char* suite;
    const char* name;
    void (*fn)();
};

void Register(const char* suite, const char* name, void (*fn)());
int RunAll();
void Fail(const char* file, int line, const std::string& message);

struct Registrar
{
    Registrar(const char* suite, const char* name, void (*fn)())
    {
        Register(suite, name, fn);
    }
};
}

#define LATTIC_TEST(suite, name)                                                      \
    static void suite##_##name##_Body();                                              \
    static const ::lattic::test::Registrar suite##_##name##_Reg(                      \
        #suite, #name, &suite##_##name##_Body);                                       \
    static void suite##_##name##_Body()

#define CHECK(expr)                                                                   \
    do                                                                                \
    {                                                                                 \
        if (!(expr))                                                                  \
        {                                                                             \
            ::lattic::test::Fail(__FILE__, __LINE__, "CHECK failed: " #expr);         \
            return;                                                                   \
        }                                                                             \
    } while (false)

#define CHECK_EQ(lhs, rhs)                                                            \
    do                                                                                \
    {                                                                                 \
        const auto latticLhs = (lhs);                                                 \
        const auto latticRhs = (rhs);                                                 \
        if (!(latticLhs == latticRhs))                                                \
        {                                                                             \
            ::lattic::test::Fail(__FILE__, __LINE__, "CHECK_EQ failed: " #lhs        \
                                                    " == " #rhs);                     \
            return;                                                                   \
        }                                                                             \
    } while (false)
