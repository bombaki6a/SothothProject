#include "CollectorSupport.h"

#include <algorithm>
#include <cwctype>

namespace Sothoth::Core::Support
{
/// Removes trailing console whitespace without changing the meaningful contents of a value.
std::wstring TrimTrailingWhitespace(std::wstring value)
{
    while (!value.empty())
    {
        const wchar_t ch = value.back();
        if (ch != L'\r' && ch != L'\n' && ch != L' ' && ch != L'\t')
        {
            break;
        }
        value.pop_back();
    }
    return value;
}

/// Removes embedded nulls and unsupported control characters so Win32 text controls display the entire result.
std::wstring NormalizeDisplayText(std::wstring value)
{
    std::wstring normalized;
    normalized.reserve(value.size());

    for (wchar_t ch : value)
    {
        if (ch == L'\0')
        {
            continue;
        }

        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
        {
            normalized.push_back(ch);
            continue;
        }

        if (iswcntrl(ch))
        {
            continue;
        }

        normalized.push_back(ch);
    }

    return TrimTrailingWhitespace(normalized);
}

/// Formats a Win32 error code using the system message table and supplies a numeric fallback.
std::wstring FormatErrorMessage(DWORD errorCode)
{
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags, nullptr, errorCode, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message;
    if (length != 0 && buffer != nullptr)
    {
        message.assign(buffer, length);
        LocalFree(buffer);
        return TrimTrailingWhitespace(message);
    }

    std::wostringstream stream;
    stream << L"Unknown error (" << errorCode << L')';
    return stream.str();
}

/// Decodes captured command output, accepting UTF-16 and falling back to the active console encoding.
std::wstring DecodeConsoleBytes(const std::string& bytes)
{
    if (bytes.empty())
    {
        return {};
    }

    const bool hasUtf16Bom =
        bytes.size() >= 2 &&
        static_cast<unsigned char>(bytes[0]) == 0xFF &&
        static_cast<unsigned char>(bytes[1]) == 0xFE;

    const bool looksLikeUtf16 =
        !hasUtf16Bom &&
        bytes.size() >= 4 &&
        std::count(bytes.begin() + 1, bytes.end(), '\0') > static_cast<int>(bytes.size() / 4);

    if (hasUtf16Bom || looksLikeUtf16)
    {
        const size_t offset = hasUtf16Bom ? 2u : 0u;
        const size_t wcharCount = (bytes.size() - offset) / sizeof(wchar_t);
        return std::wstring(reinterpret_cast<const wchar_t*>(bytes.data() + offset), wcharCount);
    }

    int wideLength = MultiByteToWideChar(CP_OEMCP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (wideLength <= 0)
    {
        wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        if (wideLength <= 0)
        {
            return L"Failed to decode command output.";
        }

        std::wstring decoded(static_cast<size_t>(wideLength), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), decoded.data(), wideLength);
        return decoded;
    }

    std::wstring decoded(static_cast<size_t>(wideLength), L'\0');
    MultiByteToWideChar(CP_OEMCP, 0, bytes.data(), static_cast<int>(bytes.size()), decoded.data(), wideLength);
    return decoded;
}

/// Combines a Windows status code with its error description for diagnostics.
std::wstring FormatStatusCode(DWORD status)
{
    std::wostringstream stream;
    stream << status << L" (" << FormatErrorMessage(status) << L')';
    return stream.str();
}

/// Compares a collected string with a fixed label using an ordinal, case-insensitive comparison.
bool EqualsIgnoreCase(const std::wstring& value, const wchar_t* other)
{
    return CompareStringOrdinal(value.c_str(), -1, other, -1, TRUE) == CSTR_EQUAL;
}

/// Checks a label prefix without depending on the casing of command output.
bool StartsWithIgnoreCase(const std::wstring& value, const wchar_t* prefix)
{
    const size_t prefixLength = wcslen(prefix);
    return value.size() >= prefixLength &&
           CompareStringOrdinal(value.c_str(), static_cast<int>(prefixLength), prefix, static_cast<int>(prefixLength), TRUE) == CSTR_EQUAL;
}

/// Normalizes character case for the existing account and status matching rules.
std::wstring ToLowerInvariant(std::wstring value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t ch)
        {
            return static_cast<wchar_t>(towlower(ch));
        });
    return value;
}

/// Expands environment variables in registry paths and removes the terminating null.
std::wstring ExpandEnvironmentStringsValue(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const DWORD required = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (required == 0)
    {
        return value;
    }

    std::wstring expanded(static_cast<size_t>(required), L'\0');
    const DWORD written = ExpandEnvironmentStringsW(value.c_str(), expanded.data(), required);
    if (written == 0)
    {
        return value;
    }

    if (!expanded.empty() && expanded.back() == L'\0')
    {
        expanded.pop_back();
    }

    return expanded;
}

/// Sanitizes a collected value and substitutes the caller's fallback when no displayable text remains.
std::wstring DefaultIfEmpty(const std::wstring& value, const wchar_t* fallback)
{
    const std::wstring normalized = NormalizeDisplayText(value);
    return normalized.empty() ? std::wstring(fallback) : normalized;
}

/// Reads a registry string, expands environment variables where applicable, and returns an empty value on failure.
std::wstring QueryRegistryStringValue(HKEY rootKey, const wchar_t* subKey, const wchar_t* valueName)
{
    DWORD type = 0;
    DWORD size = 0;
    LONG status = RegGetValueW(
        rootKey,
        subKey,
        valueName,
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
        &type,
        nullptr,
        &size);

    if (status != ERROR_SUCCESS || size == 0)
    {
        return {};
    }

    std::wstring value(size / sizeof(wchar_t), L'\0');
    status = RegGetValueW(
        rootKey,
        subKey,
        valueName,
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
        &type,
        value.data(),
        &size);

    if (status != ERROR_SUCCESS)
    {
        return {};
    }

    if (!value.empty() && value.back() == L'\0')
    {
        value.pop_back();
    }

    return NormalizeDisplayText(type == REG_EXPAND_SZ ? ExpandEnvironmentStringsValue(value) : value);
}

/// Flattens a value to one readable line and supplies a fallback for missing information.
std::wstring SingleLineText(std::wstring value, const wchar_t* fallback)
{
    value = DefaultIfEmpty(value, fallback);

    for (wchar_t& ch : value)
    {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t')
        {
            ch = L' ';
        }
    }

    return NormalizeDisplayText(value);
}

/// Appends a section heading and underline to the plain-text report.
void AppendHeader(std::wostringstream& stream, const wchar_t* title, wchar_t underlineCharacter)
{
    if (stream.tellp() > 0)
    {
        stream << L"\r\n";
    }

    stream << title << L"\r\n";
    stream << std::wstring(wcslen(title), underlineCharacter) << L"\r\n";
}

/// Appends one sanitized label/value pair using the established report format.
void AppendField(std::wostringstream& stream, const wchar_t* label, const std::wstring& value, const wchar_t* fallback)
{
    stream << label << L": " << SingleLineText(value, fallback) << L"\r\n";
}
} // namespace Sothoth::Core::Support
