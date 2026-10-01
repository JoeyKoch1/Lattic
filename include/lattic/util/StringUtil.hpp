#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lattic::util::str
{

std::string  ToLower(std::string_view input);
std::string  ToUpper(std::string_view input);

std::string        Trim(std::string_view input);
std::string        TrimLeft(std::string_view input);
std::string        TrimRight(std::string_view input);

bool StartsWith(std::string_view input, std::string_view prefix);
bool EndsWith(std::string_view input, std::string_view suffix);

std::vector<std::string> Split(std::string_view input, char delimiter);
std::string              Join(const std::vector<std::string>& parts, std::string_view delimiter);

std::string BytesToHex(const std::vector<std::uint8_t>& bytes);
std::string BytesToHex(const std::uint8_t* data, std::size_t length);

std::string BytesToHexSpaced(const std::vector<std::uint8_t>& bytes);

bool HexToBytes(std::string_view hex, std::vector<std::uint8_t>& out);

std::string FormatVA(std::uint64_t va);

std::string FormatBytes(std::uint64_t byteCount);

std::string FileName(std::string_view path);
std::string FileExtension(std::string_view path);
std::string DirectoryOf(std::string_view path);

std::string Printable(std::string_view input);

std::string Ellipsize(std::string_view input, std::size_t maxLen);

std::string  Narrow(const std::wstring& wide);
std::wstring Widen(const std::string& narrow);
}