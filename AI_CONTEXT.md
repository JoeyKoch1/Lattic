# Lattic - AI Development Context

This file tells any AI coding assistant how to work on Lattic. Read it before touching code. Follow it exactly.

## What Lattic Is

Lattic is a Windows application packer for EXE and DLL files. A user opens the tool, loads a compiled binary, selects what they want protected or patched, and gets a new binary back. The tool does not require the target's source code.

The core features, in build order:

1. **PE parsing** - reads headers, sections, imports, exports, string candidates
2. **String encryption** - finds strings in the target, encrypts them, injects a runtime decryptor
3. **Code virtualization** - lifts x86-64 instructions, translates to a custom VM bytecode, injects an interpreter
4. **Mutation** - rewrites the IR with substitution, MBA, dead code, junk code, opaque predicates
5. **Watermarking** - appends a signed metadata block to the output binary
6. **Anti-tamper** - injects runtime checks for debuggers, injection, integrity violations

The UI is ImGui with a DirectX 11 backend. The tool itself is native C++20, built with CMake, targeting x64 Windows only.

## Project Layout

```
include/lattic/        public headers, mirror the src tree
src/                   implementations
  core/                binary manipulation, no UI allowed here
  core/vm/             virtualization engine
  core/mutate/         IR transformation passes
  core/watermark/      output metadata
  core/antitamper/     runtime protection (injected, not part of the tool)
  ui/                  ImGui panels, no core logic allowed here
  util/                shared helpers
external/              submodules: imgui, zydis, pe-parse, minhook
tests/                 one test file per module
```

The `core` and `ui` split is not decorative. Nothing in `core` may include anything from `ui`. Nothing in `ui` may implement parsing, patching, or VM logic. The UI calls into the `Lattic` facade and displays what it returns.

## Code Style

**Braces.** Allman. Opening brace on its own line, always, for functions, classes, if, for, while, switch.

```cpp
if (condition)
{
    DoThing();
}
```

**Indent.** 4 spaces. Never tabs.

**Line length.** 100 columns. Break longer lines at logical points, not at the column limit.

**Naming.**
- Classes and structs: `PascalCase`
- Functions and methods: `PascalCase`
- Local variables and parameters: `camelCase`
- Member variables: `m_camelCase`
- Constants and constexpr: `kPascalCase`
- Enum values: `PascalCase`
- Namespaces: lowercase, nested with `::`

**Headers.** Include guards replaced by `#pragma once`. Include order: own header, blank, standard library, blank, external libraries, blank, project headers.

**Types.** Use `std::uint32_t`, `std::size_t`, etc. Never `unsigned int` or bare `int` for sizes. Use `auto` only when the type is obvious from the right side.

**No using directives.** Write `std::string`, not `using namespace std;`. Inside a `.cpp` file, a narrow `using namespace lattic::core;` is acceptable when it saves significant noise, but never in a header.

## Comments

Write clean, self-explanatory code. Comments are the exception, not the rule.

**Do not comment:**
- What a function does when the name already says it
- Every line of a straightforward loop
- Parameter names that are already descriptive
- Sections with obvious boundaries

**Do comment:**
- Non-obvious bit manipulation, especially in the PE and VM code
- Magic numbers that are not defined as a named constant
- Workarounds for external library quirks
- Public API functions in headers, one short line each
- Anything a reader would otherwise have to reverse-engineer from the code

Bad:

```cpp
// Increment the counter
++counter;

// Loop over all sections
for (const auto& section : m_sections)
{
    // Get the name
    const std::string name = section.name;
}
```

Good:

```cpp
// PE section names are limited to 8 bytes and are not null-terminated
// when they fill all 8. Read exactly 8 and stop at the first null.
```

The rule: if removing the comment makes the code harder to understand six months from now, keep it. Otherwise delete it.

## What To Do

- Write code that compiles on the first try. No placeholder calls to functions that do not exist.
- If a helper is missing, either write it in the same response or state clearly that it needs to be written and stop.
- Match the style of the surrounding file. If the file uses `m_member` naming, so do you.
- Prefer return codes and error strings over exceptions. The codebase does not throw.
- Prefer `std::vector` and `std::string` over raw pointers and manual allocation.
- Bound every loop that walks untrusted input, especially anything reading from a loaded binary. Files in the wild are hostile until proven otherwise.
- Log through `util::Logger`, not `std::cout`.
- When a function can fail, return `bool` and set an error string, or return a result struct. Do not return `void` and silently do nothing.
- Keep functions under 60 lines where practical. If a function is longer, the shape is probably wrong.

## What Not To Do

- Do not write functions that call APIs that do not exist in the project. If you reference `Foo::Bar()`, `Foo::Bar()` must have been written or must already exist.
- Do not invent methods on classes you have not seen. Ask for the header if you need it.
- Do not add comments that restate the code.
- Do not add `TODO` markers unless the user explicitly asks for a stub.
- Do not put business logic in UI files or UI code in core files.
- Do not introduce new third-party dependencies without asking first. The external folder is intentionally small.
- Do not use exceptions for control flow.
- Do not use RTTI or dynamic_cast.
- Do not use `std::shared_ptr` when `std::unique_ptr` will do. Own things with unique_ptr, pass references.
- Do not write code that assumes the input binary is well-formed. Every read from a loaded file goes through a bounds check.
- Do not describe what you are about to write. Write it.
- Do not explain the code after writing it unless the user asks.
- Do not use em dashes in prose.
- Do not mention Python. This project has no Python and never will.

## Error Handling Pattern

Every class that does non-trivial work has this shape:

```cpp
bool DoThing(const Input& in, Output& out);
const std::string& LastError() const;

private:
    void SetError(std::string message);
    std::string m_lastError;
```

`SetError` sets the message and logs it. Callers check the return value and read `LastError()` when it is false. This pattern is consistent across `Binary`, `PeParser`, `Signature`, `Watermarker`, `Interpreter`, and everything else. Follow it.

## Facade Rules

The `Lattic` class in `src/Lattic.cpp` is the only entry point the UI is allowed to call. Its method signatures are the contract. If a new feature needs to be exposed, add a method to `Lattic`, do not reach into `core` from `ui`.

## Build

CMake 3.21 or newer, MSVC v143 toolset, C++20, x64 only.

```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Submodules must be initialized before the first build:

```
git submodule update --init --recursive
```

## Testing

Every non-trivial function gets a test. Test files live in `tests/` and use a minimal assertion framework, one file per module. Run the full suite before considering any feature done. The VM, the patcher, and the watermark reader are the three places where a bug means corrupt output, so those get the most coverage.

## When You Are Unsure

Ask. Do not guess at an interface you have not seen, do not assume a type, and do not write code against a class you have not read. A short clarifying question is faster than a compile error and cleaner than a wrong guess.

## Summary

Clean code. No noise comments. No invented APIs. No exceptions. No Python. Match the surrounding style, keep the core and UI separated, and bound every read from an untrusted file. That is the whole contract.
