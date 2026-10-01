#include "TestFramework.hpp"

#include "lattic/util/Logger.hpp"

int main()
{
    lattic::util::Logger::Init("lattic-tests.log");
    lattic::util::Logger::Info("Lattic test run starting");

    const int result = lattic::test::RunAll();

    lattic::util::Logger::Info("Lattic test run finished");
    lattic::util::Logger::Shutdown();
    return result;
}
