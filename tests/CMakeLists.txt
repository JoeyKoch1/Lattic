add_executable(lattic_tests
    TestFramework.cpp
    test_antidebug.cpp
    test_binary.cpp
    test_main.cpp
    test_detection.cpp
    test_json.cpp
    test_mcp.cpp
    test_mutation.cpp
    test_peparser.cpp
    test_patcher.cpp
    test_runtime_execution.cpp
    test_signature.cpp
    test_string_encryptor.cpp
    test_string_scanner.cpp
    test_stringutil.cpp
    test_vm_interpreter.cpp
    test_vm_lifter.cpp
    test_vm_translator.cpp)

target_include_directories(lattic_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(lattic_tests PRIVATE lattic_core)

# The fixtures write throwaway files with the plain C API on purpose.
target_compile_definitions(lattic_tests PRIVATE _CRT_SECURE_NO_WARNINGS)

lattic_set_warnings(lattic_tests)

add_test(NAME lattic_tests COMMAND lattic_tests)
