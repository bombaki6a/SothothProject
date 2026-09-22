#pragma once

#include "framework.h"
#include <sstream>
#include <string>

namespace Sothoth::Core::Support
{
/// Removes trailing console whitespace without changing the meaningful contents of a value.
std::wstring TrimTrailingWhitespace(std::wstring value);

/// Removes embedded nulls and unsupported control characters so Win32 text controls display the entire result.
std::wstring NormalizeDisplayText(std::wstring value);

/// Formats a Win32 error code using the system message table and supplies a numeric fallback.
std::wstring FormatErrorMessage(DWORD errorCode);

/// Decodes captured command output, accepting UTF-16 and falling back to the active console encoding.
std::wstring DecodeConsoleBytes(const std::string& bytes);

/// Combines a Windows status code with its error description for diagnostics.
std::wstring FormatStatusCode(DWORD status);

/// Compares a collected string with a fixed label using an ordinal, case-insensitive comparison.
bool EqualsIgnoreCase(const std::wstring& value, const wchar_t* other);

/// Checks a label prefix without depending on the casing of command output.
bool StartsWithIgnoreCase(const std::wstring& value, const wchar_t* prefix);

/// Normalizes character case for the existing account and status matching rules.
std::wstring ToLowerInvariant(std::wstring value);

/// Expands environment variables in registry paths and removes the terminating null.
std::wstring ExpandEnvironmentStringsValue(const std::wstring& value);

/// Sanitizes a collected value and substitutes the caller's fallback when no displayable text remains.
std::wstring DefaultIfEmpty(const std::wstring& value, const wchar_t* fallback = L"(not set)");

/// Reads a registry string, expands environment variables where applicable, and returns an empty value on failure.
std::wstring QueryRegistryStringValue(HKEY rootKey, const wchar_t* subKey, const wchar_t* valueName);

/// Flattens a value to one readable line and supplies a fallback for missing information.
std::wstring SingleLineText(std::wstring value, const wchar_t* fallback = L"(not set)");

/// Appends a section heading and underline to the plain-text report.
void AppendHeader(std::wostringstream& stream, const wchar_t* title, wchar_t underlineCharacter);

/// Appends one sanitized label/value pair using the established report format.
void AppendField(std::wostringstream& stream, const wchar_t* label, const std::wstring& value, const wchar_t* fallback = L"(not set)");
} // namespace Sothoth::Core::Support
