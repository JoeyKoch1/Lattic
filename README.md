# Lattic

[![Release](https://img.shields.io/github/v/release/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/releases)
[![Downloads](https://img.shields.io/github/downloads/Joeykoch1/Lattic/total?style=flat-square)](https://github.com/Joeykoch1/Lattic/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)](#)
[![Made with](https://img.shields.io/badge/made%20with-C%2B%2B-blue?style=flat-square)](#)
[![Issues](https://img.shields.io/github/issues/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/issues)
[![Stars](https://img.shields.io/github/stars/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/stargazers)
[![License](https://img.shields.io/github/license/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/blob/main/LICENSE)

Lattic is a next-gen application packer. It is one executable. You run it, load your EXE or DLL, select what you want, and it patches. Done.

No installer. No runtime. No toolchain. No config file that needs a config file. You double click a thing, point it at a binary, and get a patched binary back. That is the entire pitch.

If you came here looking for a build system, a package manager, or something that asks you to install four other things first, this is not that. Lattic assumes you already have a compiled binary and a reason to change it.

## What it does

- Loads `.exe` and `.dll` files.
- Lets you select the patches you want.
- Writes a patched binary. Done.
- Windows native. One executable.
- No dependencies, no runtime, no setup wizard.
- Self-contained output.

## Quickstart

1. Grab the latest build from [Releases](https://github.com/Joeykoch1/Lattic/releases).
2. Run `Lattic.exe`.
3. Load your `.exe` or `.dll`.
4. Select what you want patched.
5. Hit Patch.
6. Done.

If Windows SmartScreen gives you the sideways look it gives every unsigned tool, that is normal. Check the source, build it yourself, or click through. Your call, your machine.

## Why Lattic

Most packers start with a toolchain and end with a stack trace. Lattic starts with your binary and ends with your binary, slightly different. It does not care what the target was written in. It loads the file, applies what you selected, and writes the result.

Other tools will happily spend your afternoon on dependency resolution. Lattic is for when you want the job finished before your coffee gets cold.

## Building

Prebuilt binaries live in [Releases](https://github.com/Joeykoch1/Lattic/releases). To build from source, clone the repo and follow the build notes for your toolchain.

## Contributing

Issues and pull requests are welcome. Open an issue before a large PR so we can agree on whether it belongs in the core tool. Keep changes focused, keep the code clean, and test your changes.

## License

See [LICENSE](LICENSE).

## Maintained by

[Joeykoch1](https://github.com/Joeykoch1)
