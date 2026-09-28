# Lattic

[![Release](https://img.shields.io/github/v/release/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/releases)
[![Downloads](https://img.shields.io/github/downloads/Joeykoch1/Lattic/total?style=flat-square)](https://github.com/Joeykoch1/Lattic/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-blue?style=flat-square)](#)
[![No Python](https://img.shields.io/badge/python-none-red?style=flat-square)](#)
[![Issues](https://img.shields.io/github/issues/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/issues)
[![Stars](https://img.shields.io/github/stars/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/stargazers)
[![License](https://img.shields.io/github/license/Joeykoch1/Lattic?style=flat-square)](https://github.com/Joeykoch1/Lattic/blob/main/LICENSE)

Lattic is a next-gen application packer. It is not a Python package. It is not a pip install. It is an exe. You run it, load your exe or dll, select the stuff you want, and it patches. Done.

If you came here looking for `pip install lattic`, this is not that. This is a Windows tool for patching binaries.

## What it does

Lattic takes a compiled `.exe` or `.dll`, lets you pick what to patch, and writes the patched result. No interpreter, no virtualenv, no runtime, no dependency resolver having a breakdown because your lockfile looked at it wrong.

- Single executable. No installer.
- Load `.exe` and `.dll` files.
- Select patches and options.
- Patch and save.
- Windows native.
- No Python. No pip. No runtime.

## Quickstart

1. Download the latest release from [Releases](https://github.com/Joeykoch1/Lattic/releases).
2. Run `Lattic.exe`.
3. Load your `.exe` or `.dll`.
4. Select what you want patched.
5. Click Patch.
6. Done.

If Windows SmartScreen acts like you just handed it a suspicious sandwich, that is normal for unsigned tools. Check the source, build it yourself, or click through. Your call.

## Why Lattic

Most packers make you install a toolchain, configure a build, and question your choices. Lattic assumes you already have a binary and a reason to patch it. It does not care what language the target was written in. It loads the file, applies what you selected, and writes the output.

If you enjoy dependency hell, there are plenty of other tools. Lattic is for when you want the job done before your coffee gets cold.

## Building

Release builds are in [Releases](https://github.com/Joeykoch1/Lattic/releases). To build from source, clone the repo and follow the build notes for your toolchain.

## Contributing

Issues and pull requests are welcome. Open an issue before a large PR so we can agree on whether it belongs in the tool. Keep changes focused. Test your changes. Keep the code clean. Do not add a Python dependency. Seriously.

## License

See [LICENSE](LICENSE).

## Maintained by

[Joeykoch1](https://github.com/Joeykoch1)
