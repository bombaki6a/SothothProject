#include <winsock2.h>
#include <ws2tcpip.h>

#include "framework.h"
#include "ForensicCollector.h"

#include <iphlpapi.h>
#include <lm.h>
#include <sddl.h>
#include <wlanapi.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Sothoth::Core
{
namespace
{
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

std::wstring TrimWhitespace(std::wstring value)
{
    value = TrimTrailingWhitespace(std::move(value));

    std::size_t index = 0;
    while (index < value.size())
    {
        const wchar_t ch = value[index];
        if (ch != L' ' && ch != L'\t' && ch != L'\r' && ch != L'\n')
        {
            break;
        }
        ++index;
    }

    return index == 0 ? value : value.substr(index);
}

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

std::wstring RunCommandCapture(const std::wstring& command)
{
    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &securityAttributes, 0))
    {
        return L"Unable to create capture pipe.\r\n" + FormatErrorMessage(GetLastError());
    }

    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    startupInfo.wShowWindow = SW_HIDE;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = writePipe;
    startupInfo.hStdError = writePipe;

    PROCESS_INFORMATION processInfo{};
    std::wstring commandLine = L"cmd.exe /d /c \"" + command + L"\"";

    const BOOL created = CreateProcessW(
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startupInfo,
        &processInfo);

    CloseHandle(writePipe);
    writePipe = nullptr;

    if (!created)
    {
        CloseHandle(readPipe);
        return L"Unable to start command:\r\n" + command + L"\r\n\r\n" + FormatErrorMessage(GetLastError());
    }

    std::string outputBytes;
    std::array<char, 4096> buffer{};
    DWORD bytesRead = 0;
    while (ReadFile(readPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) && bytesRead > 0)
    {
        outputBytes.append(buffer.data(), bytesRead);
        bytesRead = 0;
    }

    CloseHandle(readPipe);
    readPipe = nullptr;

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);

    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    std::wstring output = DecodeConsoleBytes(outputBytes);
    output = TrimTrailingWhitespace(output);

    if (output.empty())
    {
        std::wostringstream stream;
        stream << L"Command returned no output: " << command;
        if (exitCode != 0)
        {
            stream << L"\r\nExit code: " << exitCode;
        }
        return stream.str();
    }

    if (exitCode != 0)
    {
        std::wostringstream stream;
        stream << output << L"\r\n\r\nExit code: " << exitCode;
        return stream.str();
    }

    return output;
}

std::wstring FormatLocalTimestamp()
{
    SYSTEMTIME localTime{};
    GetLocalTime(&localTime);

    wchar_t buffer[64]{};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        localTime.wYear,
        localTime.wMonth,
        localTime.wDay,
        localTime.wHour,
        localTime.wMinute,
        localTime.wSecond);

    return buffer;
}

std::wstring FormatUnixTimestamp(DWORD seconds)
{
    if (seconds == 0)
    {
        return L"Never";
    }

    constexpr ULONGLONG kUnixEpochToFileTime = 11644473600ULL;
    ULARGE_INTEGER value{};
    value.QuadPart = (static_cast<ULONGLONG>(seconds) + kUnixEpochToFileTime) * 10000000ULL;

    FILETIME utcFileTime{};
    utcFileTime.dwLowDateTime = value.LowPart;
    utcFileTime.dwHighDateTime = value.HighPart;

    FILETIME localFileTime{};
    if (!FileTimeToLocalFileTime(&utcFileTime, &localFileTime))
    {
        return L"Unavailable";
    }

    SYSTEMTIME localTime{};
    if (!FileTimeToSystemTime(&localFileTime, &localTime))
    {
        return L"Unavailable";
    }

    wchar_t buffer[64]{};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        localTime.wYear,
        localTime.wMonth,
        localTime.wDay,
        localTime.wHour,
        localTime.wMinute,
        localTime.wSecond);

    return buffer;
}

std::wstring YesNo(bool value)
{
    return value ? L"Yes" : L"No";
}

std::wstring UserPrivilegeToString(DWORD privilege)
{
    switch (privilege)
    {
    case USER_PRIV_GUEST:
        return L"Guest";
    case USER_PRIV_USER:
        return L"User";
    case USER_PRIV_ADMIN:
        return L"Administrator";
    default:
        return L"Unknown";
    }
}

std::wstring FormatStatusCode(DWORD status)
{
    std::wostringstream stream;
    stream << status << L" (" << FormatErrorMessage(status) << L')';
    return stream.str();
}

std::wstring SidToString(PSID sid)
{
    if (sid == nullptr)
    {
        return L"Unavailable";
    }

    LPWSTR sidText = nullptr;
    if (!ConvertSidToStringSidW(sid, &sidText) || sidText == nullptr)
    {
        return L"Unavailable";
    }

    std::wstring value = sidText;
    LocalFree(sidText);
    return value;
}

bool EqualsIgnoreCase(const std::wstring& value, const wchar_t* other)
{
    return CompareStringOrdinal(value.c_str(), -1, other, -1, TRUE) == CSTR_EQUAL;
}

bool StartsWithIgnoreCase(const std::wstring& value, const wchar_t* prefix)
{
    const size_t prefixLength = wcslen(prefix);
    return value.size() >= prefixLength &&
           CompareStringOrdinal(value.c_str(), static_cast<int>(prefixLength), prefix, static_cast<int>(prefixLength), TRUE) == CSTR_EQUAL;
}

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

bool DirectoryExists(const std::wstring& path)
{
    if (path.empty())
    {
        return false;
    }

    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool FileExists(const std::wstring& path)
{
    if (path.empty())
    {
        return false;
    }

    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

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

std::wstring DefaultIfEmpty(const std::wstring& value, const wchar_t* fallback = L"(not set)")
{
    const std::wstring normalized = NormalizeDisplayText(value);
    return normalized.empty() ? std::wstring(fallback) : normalized;
}

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

bool QueryRegistryDwordValue(HKEY rootKey, const wchar_t* subKey, const wchar_t* valueName, DWORD& value)
{
    DWORD size = sizeof(value);
    return RegGetValueW(rootKey, subKey, valueName, RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS;
}

std::wstring QueryComputerNameValue(COMPUTER_NAME_FORMAT format)
{
    DWORD size = 0;
    GetComputerNameExW(format, nullptr, &size);
    if (size == 0)
    {
        return {};
    }

    std::wstring value(size, L'\0');
    if (!GetComputerNameExW(format, value.data(), &size))
    {
        return {};
    }

    value.resize(size);
    return NormalizeDisplayText(value);
}

std::wstring QueryLocaleDisplayValue(const std::wstring& localeName)
{
    if (localeName.empty())
    {
        return L"Unavailable";
    }

    wchar_t displayName[128]{};
    if (GetLocaleInfoEx(localeName.c_str(), LOCALE_SLOCALIZEDDISPLAYNAME, displayName, static_cast<int>(std::size(displayName))) == 0)
    {
        displayName[0] = L'\0';
    }

    std::wstring value = localeName;
    if (displayName[0] != L'\0')
    {
        value += L" (";
        value += displayName;
        value += L')';
    }

    return NormalizeDisplayText(value);
}

std::wstring QuerySystemLocaleValue()
{
    wchar_t localeName[LOCALE_NAME_MAX_LENGTH]{};
    if (GetSystemDefaultLocaleName(localeName, static_cast<int>(std::size(localeName))) == 0)
    {
        return L"Unavailable";
    }

    return QueryLocaleDisplayValue(localeName);
}

std::wstring QueryInputLocaleValue()
{
    const HKL keyboardLayout = GetKeyboardLayout(0);
    const LANGID languageId = LOWORD(reinterpret_cast<UINT_PTR>(keyboardLayout));

    wchar_t localeName[LOCALE_NAME_MAX_LENGTH]{};
    if (LCIDToLocaleName(MAKELCID(languageId, SORT_DEFAULT), localeName, LOCALE_NAME_MAX_LENGTH, 0) == 0)
    {
        return L"Unavailable";
    }

    return QueryLocaleDisplayValue(localeName);
}

std::wstring FormatUtcOffset(LONG biasMinutes)
{
    LONG offsetMinutes = -biasMinutes;
    const wchar_t sign = offsetMinutes >= 0 ? L'+' : L'-';
    if (offsetMinutes < 0)
    {
        offsetMinutes = -offsetMinutes;
    }

    const LONG hours = offsetMinutes / 60;
    const LONG minutes = offsetMinutes % 60;

    wchar_t buffer[16]{};
    swprintf_s(buffer, L"%c%02ld:%02ld", sign, hours, minutes);
    return buffer;
}

std::wstring QueryTimeZoneValue()
{
    DYNAMIC_TIME_ZONE_INFORMATION timeZone{};
    const DWORD timeZoneId = GetDynamicTimeZoneInformation(&timeZone);

    LONG effectiveBias = timeZone.Bias;
    if (timeZoneId == TIME_ZONE_ID_DAYLIGHT)
    {
        effectiveBias += timeZone.DaylightBias;
    }
    else if (timeZoneId == TIME_ZONE_ID_STANDARD)
    {
        effectiveBias += timeZone.StandardBias;
    }

    std::wstring name;
    if (timeZone.TimeZoneKeyName[0] != L'\0')
    {
        name = timeZone.TimeZoneKeyName;
    }
    else if (timeZoneId == TIME_ZONE_ID_DAYLIGHT && timeZone.DaylightName[0] != L'\0')
    {
        name = timeZone.DaylightName;
    }
    else if (timeZone.StandardName[0] != L'\0')
    {
        name = timeZone.StandardName;
    }

    return NormalizeDisplayText(L"(UTC" + FormatUtcOffset(effectiveBias) + L") " + DefaultIfEmpty(name, L"Unavailable"));
}

std::wstring QueryDomainValue()
{
    LPWSTR buffer = nullptr;
    NETSETUP_JOIN_STATUS joinStatus = NetSetupUnknownStatus;
    const NET_API_STATUS status = NetGetJoinInformation(nullptr, &buffer, &joinStatus);

    std::wstring value;
    if (status == NERR_Success && buffer != nullptr)
    {
        value = buffer;
        NetApiBufferFree(buffer);
        buffer = nullptr;
    }

    if (status == NERR_Success)
    {
        if (joinStatus == NetSetupUnjoined)
        {
            return L"(not joined)";
        }

        return DefaultIfEmpty(value);
    }

    if (buffer != nullptr)
    {
        NetApiBufferFree(buffer);
    }

    return DefaultIfEmpty(QueryComputerNameValue(ComputerNameDnsDomain), L"(not joined)");
}

std::wstring QuerySystemModelValue()
{
    const wchar_t* biosKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";

    std::wstring model = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, biosKey, L"SystemProductName");
    if (model.empty())
    {
        model = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, biosKey, L"BaseBoardProduct");
    }

    return DefaultIfEmpty(model, L"Unavailable");
}

DWORD QueryCurrentBuildNumber()
{
    const std::wstring currentBuild = QueryRegistryStringValue(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"CurrentBuildNumber");

    DWORD buildNumber = 0;
    std::wistringstream stream(currentBuild);
    stream >> buildNumber;
    return buildNumber;
}

std::wstring QueryOsNameValue()
{
    const wchar_t* currentVersionKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    std::wstring productName = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"ProductName");
    const DWORD buildNumber = QueryCurrentBuildNumber();

    if (productName.empty())
    {
        return buildNumber >= 22000 ? L"Windows 11" : L"Windows 10";
    }

    if (buildNumber >= 22000 && StartsWithIgnoreCase(productName, L"Windows 10"))
    {
        productName.replace(0, wcslen(L"Windows 10"), L"Windows 11");
    }
    else if (buildNumber > 0 && buildNumber < 22000 && StartsWithIgnoreCase(productName, L"Windows 11"))
    {
        productName.replace(0, wcslen(L"Windows 11"), L"Windows 10");
    }

    return DefaultIfEmpty(productName, L"Unavailable");
}

std::wstring QueryOsVersionValue()
{
    const wchar_t* currentVersionKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    DWORD majorVersion = 0;
    DWORD minorVersion = 0;
    DWORD updateBuildRevision = 0;
    const bool hasMajorVersion = QueryRegistryDwordValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"CurrentMajorVersionNumber", majorVersion);
    const bool hasMinorVersion = QueryRegistryDwordValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"CurrentMinorVersionNumber", minorVersion);
    const bool hasUpdateBuildRevision = QueryRegistryDwordValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"UBR", updateBuildRevision);

    const std::wstring currentVersion = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"CurrentVersion");
    const std::wstring currentBuild = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"CurrentBuildNumber");

    std::wostringstream stream;
    if (hasMajorVersion || hasMinorVersion)
    {
        stream << majorVersion << L'.' << minorVersion;
        if (!currentBuild.empty())
        {
            stream << L'.' << currentBuild;
        }
    }
    else if (!currentVersion.empty())
    {
        stream << currentVersion;
    }

    if (!currentBuild.empty())
    {
        stream << L" (Build " << currentBuild;
        if (hasUpdateBuildRevision)
        {
            stream << L'.' << updateBuildRevision;
        }
        stream << L')';
    }

    return DefaultIfEmpty(NormalizeDisplayText(stream.str()), L"Unavailable");
}

std::wstring QueryTotalPhysicalMemoryValue()
{
    ULONGLONG memoryInKilobytes = 0;
    if (GetPhysicallyInstalledSystemMemory(&memoryInKilobytes))
    {
        const double memoryInGiB = static_cast<double>(memoryInKilobytes) / (1024.0 * 1024.0);
        const ULONGLONG memoryInMiB = memoryInKilobytes / 1024ULL;

        std::wostringstream stream;
        stream << std::fixed << std::setprecision(1) << memoryInGiB << L" GB (" << memoryInMiB << L" MB)";
        return NormalizeDisplayText(stream.str());
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (!GlobalMemoryStatusEx(&memoryStatus))
    {
        return L"Unavailable";
    }

    const double memoryInGiB = static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
    const ULONGLONG memoryInMiB = memoryStatus.ullTotalPhys / (1024ULL * 1024ULL);

    std::wostringstream stream;
    stream << std::fixed << std::setprecision(1) << memoryInGiB << L" GB (" << memoryInMiB << L" MB)";
    return stream.str();
}

std::wstring SingleLineText(std::wstring value, const wchar_t* fallback = L"(not set)")
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

void AppendHeader(std::wostringstream& stream, const wchar_t* title, wchar_t underlineCharacter)
{
    if (stream.tellp() > 0)
    {
        stream << L"\r\n";
    }

    stream << title << L"\r\n";
    stream << std::wstring(wcslen(title), underlineCharacter) << L"\r\n";
}

void AppendField(std::wostringstream& stream, const wchar_t* label, const std::wstring& value, const wchar_t* fallback = L"(not set)")
{
    stream << label << L": " << SingleLineText(value, fallback) << L"\r\n";
}

void AppendSingleLineEntry(std::wostringstream& stream, const std::wstring& value)
{
    stream << SingleLineText(value, L"-") << L"\r\n";
}

std::wstring QueryProfileImagePath(PSID sid)
{
    const std::wstring sidText = SidToString(sid);
    if (sidText.empty() || sidText == L"Unavailable")
    {
        return {};
    }

    const std::wstring registryPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sidText;
    HKEY profileKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryPath.c_str(), 0, KEY_READ, &profileKey) != ERROR_SUCCESS)
    {
        return {};
    }

    DWORD type = 0;
    DWORD size = 0;
    LONG queryStatus = RegQueryValueExW(profileKey, L"ProfileImagePath", nullptr, &type, nullptr, &size);
    if (queryStatus != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || size == 0)
    {
        RegCloseKey(profileKey);
        return {};
    }

    std::wstring rawValue(size / sizeof(wchar_t), L'\0');
    queryStatus = RegQueryValueExW(
        profileKey,
        L"ProfileImagePath",
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(rawValue.data()),
        &size);
    RegCloseKey(profileKey);

    if (queryStatus != ERROR_SUCCESS)
    {
        return {};
    }

    if (!rawValue.empty() && rawValue.back() == L'\0')
    {
        rawValue.pop_back();
    }

    return ExpandEnvironmentStringsValue(rawValue);
}

DWORD GetLastSidRid(PSID sid)
{
    if (sid == nullptr || !IsValidSid(sid))
    {
        return 0;
    }

    UCHAR* subAuthorityCount = GetSidSubAuthorityCount(sid);
    if (subAuthorityCount == nullptr || *subAuthorityCount == 0)
    {
        return 0;
    }

    DWORD* rid = GetSidSubAuthority(sid, *subAuthorityCount - 1);
    return rid != nullptr ? *rid : 0;
}

bool IsSystemManagedUserAccount(const std::wstring& userName, PSID sid)
{
    if (userName.empty())
    {
        return false;
    }

    if (EqualsIgnoreCase(userName, L"Administrator") ||
        EqualsIgnoreCase(userName, L"Guest") ||
        EqualsIgnoreCase(userName, L"DefaultAccount") ||
        EqualsIgnoreCase(userName, L"WDAGUtilityAccount") ||
        StartsWithIgnoreCase(userName, L"defaultuser"))
    {
        return true;
    }

    if (!userName.empty() && userName.back() == L'$')
    {
        return true;
    }

    const DWORD rid = GetLastSidRid(sid);
    return rid == 500 || rid == 501 || rid == 503 || rid == 504;
}

bool LooksLikeApplicationManagedUserName(const std::wstring& userName)
{
    const std::wstring lower = ToLowerInvariant(userName);
    static constexpr const wchar_t* kSuspiciousTokens[] = {
        L"sandbox",
        L"appcontainer",
        L"daemon",
        L"agent",
        L"worker",
        L"runner",
        L"utility",
        L"updater"
    };

    for (const wchar_t* token : kSuspiciousTokens)
    {
        if (lower.find(token) != std::wstring::npos)
        {
            return true;
        }
    }

    return StartsWithIgnoreCase(userName, L"svc") || StartsWithIgnoreCase(userName, L"_");
}

bool IsLikelyInteractiveProfilePath(const std::wstring& profilePath)
{
    if (profilePath.empty())
    {
        return false;
    }

    if (!DirectoryExists(profilePath))
    {
        return false;
    }

    const std::wstring lowerPath = ToLowerInvariant(profilePath);
    if (lowerPath.find(L"\\windows\\serviceprofiles\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\system32\\config\\systemprofile") != std::wstring::npos)
    {
        return false;
    }

    wchar_t systemDrive[MAX_PATH]{};
    DWORD length = GetEnvironmentVariableW(L"SystemDrive", systemDrive, static_cast<DWORD>(std::size(systemDrive)));
    std::wstring usersRoot = length > 0 ? std::wstring(systemDrive, length) + L"\\Users\\" : L"C:\\Users\\";

    if (!StartsWithIgnoreCase(profilePath, usersRoot.c_str()))
    {
        return false;
    }

    const bool hasNtUserDat = FileExists(profilePath + L"\\NTUSER.DAT");
    const bool hasInteractiveFolders =
        DirectoryExists(profilePath + L"\\Desktop") ||
        DirectoryExists(profilePath + L"\\Documents") ||
        DirectoryExists(profilePath + L"\\Downloads");

    return hasNtUserDat || hasInteractiveFolders;
}

bool IsLikelyHumanInteractiveLocalAccount(const std::wstring& userName, PSID sid, bool isEnabled)
{
    if (!isEnabled)
    {
        return false;
    }

    if (IsSystemManagedUserAccount(userName, sid))
    {
        return false;
    }

    if (LooksLikeApplicationManagedUserName(userName))
    {
        return false;
    }

    return IsLikelyInteractiveProfilePath(QueryProfileImagePath(sid));
}

struct CachedMicrosoftIdentity
{
    std::wstring email;
    std::wstring displayName;
};

std::wstring NormalizeAccountMatchValue(std::wstring value)
{
    value = NormalizeDisplayText(value);

    std::wstring normalized;
    normalized.reserve(value.size());

    for (wchar_t ch : value)
    {
        if (iswalnum(ch))
        {
            normalized.push_back(static_cast<wchar_t>(towlower(ch)));
            continue;
        }

        if (ch == L'@' || ch == L'.' || ch == L'_' || ch == L'-')
        {
            normalized.push_back(static_cast<wchar_t>(towlower(ch)));
        }
    }

    return normalized;
}

std::wstring ExtractLeafName(const std::wstring& path)
{
    const std::size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

void TryAddCachedMicrosoftIdentity(const std::wstring& registryPath, std::vector<CachedMicrosoftIdentity>& identities)
{
    const std::wstring authority = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, registryPath.c_str(), L"AuthenticatingAuthority");
    const std::wstring identityName = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, registryPath.c_str(), L"IdentityName");

    if (!EqualsIgnoreCase(authority, L"MicrosoftAccount") || identityName.find(L'@') == std::wstring::npos)
    {
        return;
    }

    for (const auto& identity : identities)
    {
        if (EqualsIgnoreCase(identity.email, identityName.c_str()))
        {
            return;
        }
    }

    identities.push_back({
        identityName,
        QueryRegistryStringValue(HKEY_LOCAL_MACHINE, registryPath.c_str(), L"DisplayName")
    });
}

void EnumerateCachedMicrosoftIdentities(const std::wstring& registryPath, int depth, std::vector<CachedMicrosoftIdentity>& identities)
{
    if (depth > 4)
    {
        return;
    }

    TryAddCachedMicrosoftIdentity(registryPath, identities);

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, registryPath.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
    {
        return;
    }

    for (DWORD index = 0;; ++index)
    {
        wchar_t subKeyName[256]{};
        DWORD subKeyNameLength = static_cast<DWORD>(std::size(subKeyName));
        FILETIME lastWriteTime{};

        const LONG status = RegEnumKeyExW(
            key,
            index,
            subKeyName,
            &subKeyNameLength,
            nullptr,
            nullptr,
            nullptr,
            &lastWriteTime);

        if (status == ERROR_NO_MORE_ITEMS)
        {
            break;
        }

        if (status != ERROR_SUCCESS)
        {
            continue;
        }

        EnumerateCachedMicrosoftIdentities(
            registryPath + L"\\" + std::wstring(subKeyName, subKeyNameLength),
            depth + 1,
            identities);
    }

    RegCloseKey(key);
}

std::vector<CachedMicrosoftIdentity> QueryCachedMicrosoftIdentities()
{
    std::vector<CachedMicrosoftIdentity> identities;
    EnumerateCachedMicrosoftIdentities(L"SOFTWARE\\Microsoft\\IdentityStore\\LogonCache", 0, identities);
    return identities;
}

std::wstring ResolveUserIdentityLabel(
    const std::vector<CachedMicrosoftIdentity>& identities,
    const std::wstring& userName,
    const std::wstring& fullName,
    PSID sid)
{
    const std::wstring normalizedUserName = NormalizeAccountMatchValue(userName);
    const std::wstring normalizedFullName = NormalizeAccountMatchValue(fullName);
    const std::wstring normalizedProfileLeaf = NormalizeAccountMatchValue(ExtractLeafName(QueryProfileImagePath(sid)));

    for (const auto& identity : identities)
    {
        const std::wstring normalizedDisplayName = NormalizeAccountMatchValue(identity.displayName);
        const std::wstring normalizedEmail = NormalizeAccountMatchValue(identity.email);
        const std::size_t separator = normalizedEmail.find(L'@');
        const std::wstring emailLocalPart =
            separator == std::wstring::npos ? normalizedEmail : normalizedEmail.substr(0, separator);

        if (!normalizedFullName.empty() && !normalizedDisplayName.empty() && normalizedFullName == normalizedDisplayName)
        {
            return identity.email;
        }

        if (!normalizedUserName.empty() && !normalizedDisplayName.empty() && normalizedUserName == normalizedDisplayName)
        {
            return identity.email;
        }

        if (!normalizedProfileLeaf.empty() && !emailLocalPart.empty() && normalizedProfileLeaf == emailLocalPart)
        {
            return identity.email;
        }

        if (!normalizedUserName.empty() && !emailLocalPart.empty() && normalizedUserName == emailLocalPart)
        {
            return identity.email;
        }
    }

    return L"Local account";
}

std::wstring CollectOperatingSystemInformation()
{
    const wchar_t* currentVersionKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    const std::wstring hostName = QueryComputerNameValue(ComputerNamePhysicalDnsHostname);
    const std::wstring domain = QueryDomainValue();
    const std::wstring osName = QueryOsNameValue();
    const std::wstring osVersion = QueryOsVersionValue();
    const std::wstring registeredOwner = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"RegisteredOwner");
    const std::wstring registeredOrganization = QueryRegistryStringValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"RegisteredOrganization");
    const std::wstring systemModel = QuerySystemModelValue();
    const std::wstring systemLocale = QuerySystemLocaleValue();
    const std::wstring inputLocale = QueryInputLocaleValue();
    const std::wstring timeZone = QueryTimeZoneValue();
    const std::wstring totalPhysicalMemory = QueryTotalPhysicalMemoryValue();
    const std::wstring currentDateTime = FormatLocalTimestamp();

    DWORD installDate = 0;
    const bool hasInstallDate = QueryRegistryDwordValue(HKEY_LOCAL_MACHINE, currentVersionKey, L"InstallDate", installDate);
    const std::wstring originalInstallDate = hasInstallDate ? FormatUnixTimestamp(installDate) : L"Unavailable";

    std::wostringstream stream;
    AppendHeader(stream, L"Machine Identity", L'=');
    AppendField(stream, L"Host Name", hostName, L"Unavailable");
    AppendField(stream, L"Domain", domain, L"Unavailable");

    AppendHeader(stream, L"Operating System", L'=');
    AppendField(stream, L"OS Name", osName, L"Unavailable");
    AppendField(stream, L"OS Version", osVersion, L"Unavailable");
    AppendField(stream, L"Original Install Date", originalInstallDate, L"Unavailable");
    AppendField(stream, L"Current Date/Time", currentDateTime, L"Unavailable");
    AppendField(stream, L"Registered Owner", registeredOwner);
    AppendField(stream, L"Registered Organization", registeredOrganization);

    AppendHeader(stream, L"Regional Settings", L'=');
    AppendField(stream, L"System Locale", systemLocale, L"Unavailable");
    AppendField(stream, L"Input Locale", inputLocale, L"Unavailable");
    AppendField(stream, L"Time Zone", timeZone, L"Unavailable");

    AppendHeader(stream, L"Hardware", L'=');
    AppendField(stream, L"System Model", systemModel, L"Unavailable");
    AppendField(stream, L"Total Physical Memory", totalPhysicalMemory, L"Unavailable");

    return NormalizeDisplayText(stream.str());
}

std::wstring CollectUserAccountInformation()
{
    std::wostringstream stream;
    AppendHeader(stream, L"Local Accounts", L'=');
    const std::vector<CachedMicrosoftIdentity> microsoftIdentities = QueryCachedMicrosoftIdentities();

    LPUSER_INFO_0 users = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    DWORD totalCollected = 0;

    NET_API_STATUS status = NERR_Success;
    do
    {
        status = NetUserEnum(
            nullptr,
            0,
            FILTER_NORMAL_ACCOUNT,
            reinterpret_cast<LPBYTE*>(&users),
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle);

        if (status != NERR_Success && status != ERROR_MORE_DATA)
        {
            stream << L"NetUserEnum failed: " << FormatStatusCode(status) << L"\r\n";
            return NormalizeDisplayText(stream.str());
        }

        for (DWORD i = 0; i < entriesRead; ++i)
        {
            const std::wstring userName = (users[i].usri0_name && *users[i].usri0_name) ? users[i].usri0_name : L"(unknown)";

            LPUSER_INFO_23 userInfo23 = nullptr;
            NET_API_STATUS fallbackStatus = NetUserGetInfo(nullptr, userName.c_str(), 23, reinterpret_cast<LPBYTE*>(&userInfo23));
            const bool isEnabled = userInfo23 == nullptr || (userInfo23->usri23_flags & UF_ACCOUNTDISABLE) == 0;

            if (!IsLikelyHumanInteractiveLocalAccount(userName, userInfo23 != nullptr ? userInfo23->usri23_user_sid : nullptr, isEnabled))
            {
                if (userInfo23 != nullptr)
                {
                    NetApiBufferFree(userInfo23);
                }
                continue;
            }

            PSID userSid = userInfo23 != nullptr ? userInfo23->usri23_user_sid : nullptr;
            std::wstring fullName = userInfo23 != nullptr && userInfo23->usri23_full_name && *userInfo23->usri23_full_name
                ? userInfo23->usri23_full_name
                : L"(not set)";
            std::wstring privilege = L"Unknown";

            LPUSER_INFO_3 userInfo3 = nullptr;
            NET_API_STATUS infoStatus = NetUserGetInfo(nullptr, userName.c_str(), 3, reinterpret_cast<LPBYTE*>(&userInfo3));

            if (infoStatus == NERR_Success && userInfo3 != nullptr)
            {
                fullName = userInfo3->usri3_full_name && *userInfo3->usri3_full_name ? userInfo3->usri3_full_name : L"(not set)";
                privilege = UserPrivilegeToString(userInfo3->usri3_priv);
            }
            else
            {
                if (fallbackStatus == NERR_Success && userInfo23 != nullptr)
                {
                    fullName = userInfo23->usri23_full_name && *userInfo23->usri23_full_name ? userInfo23->usri23_full_name : L"(not set)";
                }
            }

            if (userInfo3 != nullptr)
            {
                NetApiBufferFree(userInfo3);
                userInfo3 = nullptr;
            }

            if (totalCollected > 0)
            {
                stream << L"\r\n";
            }

            const std::wstring identity = ResolveUserIdentityLabel(microsoftIdentities, userName, fullName, userSid);
            const std::wstring formattedIdentity = identity.find(L'@') != std::wstring::npos
                ? identity + L" (Microsoft Account)"
                : identity;

            AppendField(stream, L"Name", userName, L"(unknown)");
            AppendField(stream, L"Full Name", fullName);
            AppendField(stream, L"Privilege", privilege, L"Unknown");
            AppendField(stream, L"Type", formattedIdentity, L"Local account");

            if (userInfo23 != nullptr)
            {
                NetApiBufferFree(userInfo23);
                userInfo23 = nullptr;
            }

            ++totalCollected;
        }

        if (users != nullptr)
        {
            NetApiBufferFree(users);
            users = nullptr;
        }
    } while (status == ERROR_MORE_DATA);

    if (totalCollected == 0)
    {
        stream << L"No end-user local accounts matched the current filter.\r\n";
    }

    return NormalizeDisplayText(stream.str());
}

std::wstring TcpStateToString(DWORD state)
{
    switch (state)
    {
    case MIB_TCP_STATE_CLOSED:
        return L"CLOSED";
    case MIB_TCP_STATE_LISTEN:
        return L"LISTEN";
    case MIB_TCP_STATE_SYN_SENT:
        return L"SYN-SENT";
    case MIB_TCP_STATE_SYN_RCVD:
        return L"SYN-RECEIVED";
    case MIB_TCP_STATE_ESTAB:
        return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:
        return L"FIN-WAIT-1";
    case MIB_TCP_STATE_FIN_WAIT2:
        return L"FIN-WAIT-2";
    case MIB_TCP_STATE_CLOSE_WAIT:
        return L"CLOSE-WAIT";
    case MIB_TCP_STATE_CLOSING:
        return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK:
        return L"LAST-ACK";
    case MIB_TCP_STATE_TIME_WAIT:
        return L"TIME-WAIT";
    case MIB_TCP_STATE_DELETE_TCB:
        return L"DELETE-TCB";
    default:
        return L"UNKNOWN";
    }
}

std::wstring ShareTypeToString(DWORD type)
{
    std::wstring baseType;
    switch (type & 0xFF)
    {
    case STYPE_DISKTREE:
        baseType = L"Disk";
        break;
    case STYPE_PRINTQ:
        baseType = L"Printer";
        break;
    case STYPE_DEVICE:
        baseType = L"Device";
        break;
    case STYPE_IPC:
        baseType = L"IPC";
        break;
    default:
        baseType = L"Other";
        break;
    }

    if ((type & STYPE_SPECIAL) != 0)
    {
        baseType += L" (special)";
    }

    return baseType;
}

std::wstring FormatIpv4Address(DWORD address)
{
    IN_ADDR inAddress{};
    inAddress.S_un.S_addr = address;

    wchar_t buffer[INET_ADDRSTRLEN]{};
    if (InetNtopW(AF_INET, &inAddress, buffer, INET_ADDRSTRLEN) == nullptr)
    {
        return L"(invalid IPv4)";
    }

    return buffer;
}

std::wstring FormatIpv6Address(const UCHAR address[16], DWORD scopeId)
{
    IN6_ADDR inAddress{};
    memcpy(inAddress.u.Byte, address, 16);

    wchar_t buffer[INET6_ADDRSTRLEN]{};
    if (InetNtopW(AF_INET6, &inAddress, buffer, INET6_ADDRSTRLEN) == nullptr)
    {
        return L"(invalid IPv6)";
    }

    std::wstring result = buffer;
    if (scopeId != 0)
    {
        result += L'%';
        result += std::to_wstring(scopeId);
    }
    return result;
}

std::wstring FormatPort(DWORD port)
{
    return std::to_wstring(ntohs(static_cast<u_short>(port)));
}

std::wstring SockaddrToAddressString(const SOCKADDR* address)
{
    if (address == nullptr)
    {
        return {};
    }

    wchar_t buffer[NI_MAXHOST]{};
    const int length = address->sa_family == AF_INET
        ? static_cast<int>(sizeof(SOCKADDR_IN))
        : static_cast<int>(sizeof(SOCKADDR_IN6));

    if (GetNameInfoW(address, length, buffer, static_cast<DWORD>(std::size(buffer)), nullptr, 0, NI_NUMERICHOST) != 0)
    {
        return {};
    }

    return NormalizeDisplayText(buffer);
}

void AddUniqueValue(std::vector<std::wstring>& values, const std::wstring& value)
{
    if (value.empty())
    {
        return;
    }

    for (const auto& existingValue : values)
    {
        if (EqualsIgnoreCase(existingValue, value.c_str()))
        {
            return;
        }
    }

    values.push_back(value);
}

std::wstring JoinValues(const std::vector<std::wstring>& values, const wchar_t* fallback = L"Unavailable")
{
    if (values.empty())
    {
        return fallback;
    }

    std::wstring result;
    for (std::size_t index = 0; index < values.size(); ++index)
    {
        if (index > 0)
        {
            result += L", ";
        }
        result += values[index];
    }

    return NormalizeDisplayText(result);
}

std::wstring FormatMacAddress(const BYTE* addressBytes, ULONG addressLength)
{
    if (addressBytes == nullptr || addressLength == 0)
    {
        return L"Unavailable";
    }

    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');

    for (ULONG index = 0; index < addressLength; ++index)
    {
        if (index > 0)
        {
            stream << L'-';
        }

        stream << std::setw(2) << static_cast<unsigned int>(addressBytes[index]);
    }

    return NormalizeDisplayText(stream.str());
}

std::wstring AdapterTypeToString(ULONG ifType)
{
    if (ifType == IF_TYPE_IEEE80211)
    {
        return L"WiFi";
    }

    if (ifType == IF_TYPE_ETHERNET_CSMACD)
    {
        return L"LAN";
    }

    return L"Other";
}

std::wstring NormalizeLookupKey(std::wstring value)
{
    value = NormalizeDisplayText(value);

    std::wstring normalized;
    normalized.reserve(value.size());

    for (wchar_t ch : value)
    {
        if (iswalnum(ch))
        {
            normalized.push_back(static_cast<wchar_t>(towlower(ch)));
        }
    }

    return normalized;
}

std::wstring DecodeSsid(const DOT11_SSID& ssid)
{
    if (ssid.uSSIDLength == 0)
    {
        return L"(hidden)";
    }

    const std::string raw(reinterpret_cast<const char*>(ssid.ucSSID), ssid.uSSIDLength);

    int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), nullptr, 0);
    if (wideLength > 0)
    {
        std::wstring decoded(static_cast<std::size_t>(wideLength), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), decoded.data(), wideLength);
        return NormalizeDisplayText(decoded);
    }

    wideLength = MultiByteToWideChar(CP_ACP, 0, raw.data(), static_cast<int>(raw.size()), nullptr, 0);
    if (wideLength > 0)
    {
        std::wstring decoded(static_cast<std::size_t>(wideLength), L'\0');
        MultiByteToWideChar(CP_ACP, 0, raw.data(), static_cast<int>(raw.size()), decoded.data(), wideLength);
        return NormalizeDisplayText(decoded);
    }

    std::wstring decoded;
    decoded.reserve(raw.size());
    for (unsigned char ch : raw)
    {
        decoded.push_back(static_cast<wchar_t>(ch));
    }
    return NormalizeDisplayText(decoded);
}

std::wstring QueryWifiNetworkName(const std::wstring& adapterFriendlyName)
{
    HANDLE clientHandle = nullptr;
    DWORD negotiatedVersion = 0;
    if (WlanOpenHandle(2, nullptr, &negotiatedVersion, &clientHandle) != ERROR_SUCCESS)
    {
        return {};
    }

    PWLAN_INTERFACE_INFO_LIST interfaceList = nullptr;
    if (WlanEnumInterfaces(clientHandle, nullptr, &interfaceList) != ERROR_SUCCESS || interfaceList == nullptr)
    {
        if (interfaceList != nullptr)
        {
            WlanFreeMemory(interfaceList);
        }
        WlanCloseHandle(clientHandle, nullptr);
        return {};
    }

    const std::wstring normalizedAdapterName = NormalizeLookupKey(adapterFriendlyName);
    std::wstring firstConnectedSsid;

    for (DWORD index = 0; index < interfaceList->dwNumberOfItems; ++index)
    {
        const WLAN_INTERFACE_INFO& interfaceInfo = interfaceList->InterfaceInfo[index];
        if (interfaceInfo.isState != wlan_interface_state_connected)
        {
            continue;
        }

        DWORD dataSize = 0;
        WLAN_OPCODE_VALUE_TYPE valueType = wlan_opcode_value_type_invalid;
        PWLAN_CONNECTION_ATTRIBUTES connectionAttributes = nullptr;

        const DWORD status = WlanQueryInterface(
            clientHandle,
            &interfaceInfo.InterfaceGuid,
            wlan_intf_opcode_current_connection,
            nullptr,
            &dataSize,
            reinterpret_cast<PVOID*>(&connectionAttributes),
            &valueType);

        if (status != ERROR_SUCCESS || connectionAttributes == nullptr)
        {
            if (connectionAttributes != nullptr)
            {
                WlanFreeMemory(connectionAttributes);
            }
            continue;
        }

        const std::wstring ssid = DecodeSsid(connectionAttributes->wlanAssociationAttributes.dot11Ssid);
        if (firstConnectedSsid.empty())
        {
            firstConnectedSsid = ssid;
        }

        const std::wstring interfaceDescription = NormalizeLookupKey(interfaceInfo.strInterfaceDescription);
        WlanFreeMemory(connectionAttributes);

        if (!normalizedAdapterName.empty() && normalizedAdapterName == interfaceDescription)
        {
            WlanFreeMemory(interfaceList);
            WlanCloseHandle(clientHandle, nullptr);
            return ssid;
        }
    }

    WlanFreeMemory(interfaceList);
    WlanCloseHandle(clientHandle, nullptr);
    return firstConnectedSsid;
}

std::wstring QueryPublicIpAddress(const wchar_t* hostName)
{
    HINTERNET session = WinHttpOpen(
        L"Tenta Trace/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (session == nullptr)
    {
        return L"Unavailable";
    }

    WinHttpSetTimeouts(session, 2000, 2000, 3000, 3000);

    HINTERNET connection = WinHttpConnect(session, hostName, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (connection == nullptr)
    {
        WinHttpCloseHandle(session);
        return L"Unavailable";
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        L"GET",
        L"/",
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (request == nullptr)
    {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return L"Unavailable";
    }

    std::wstring result = L"Unavailable";
    if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr))
    {
        std::string response;

        for (;;)
        {
            DWORD availableBytes = 0;
            if (!WinHttpQueryDataAvailable(request, &availableBytes) || availableBytes == 0)
            {
                break;
            }

            std::vector<char> buffer(availableBytes);
            DWORD downloadedBytes = 0;
            if (!WinHttpReadData(request, buffer.data(), availableBytes, &downloadedBytes) || downloadedBytes == 0)
            {
                break;
            }

            response.append(buffer.data(), buffer.data() + downloadedBytes);
            if (response.size() > 128)
            {
                break;
            }
        }

        if (!response.empty())
        {
            std::wstring decoded = DecodeConsoleBytes(response);
            decoded = TrimTrailingWhitespace(decoded);
            if (!decoded.empty())
            {
                result = decoded;
            }
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return result;
}

bool IsCandidateNetworkAdapter(const IP_ADAPTER_ADDRESSES* adapter)
{
    if (adapter == nullptr)
    {
        return false;
    }

    if (adapter->OperStatus != IfOperStatusUp)
    {
        return false;
    }

    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL)
    {
        return false;
    }

    return adapter->FirstUnicastAddress != nullptr;
}

int GetIpv6AddressPriority(const IP_ADAPTER_UNICAST_ADDRESS* address)
{
    if (address == nullptr || address->Address.lpSockaddr == nullptr || address->Address.lpSockaddr->sa_family != AF_INET6)
    {
        return (std::numeric_limits<int>::max)();
    }

    const auto* ipv6Address = reinterpret_cast<const SOCKADDR_IN6*>(address->Address.lpSockaddr);
    if (IN6_IS_ADDR_LOOPBACK(&ipv6Address->sin6_addr) || IN6_IS_ADDR_MULTICAST(&ipv6Address->sin6_addr))
    {
        return (std::numeric_limits<int>::max)();
    }

    const UCHAR* bytes = ipv6Address->sin6_addr.u.Byte;
    const bool isUniqueLocal = (bytes[0] & 0xFE) == 0xFC;
    const bool isLinkLocal = IN6_IS_ADDR_LINKLOCAL(&ipv6Address->sin6_addr) != 0;
    const bool isTemporary = address->SuffixOrigin == IpSuffixOriginRandom;
    const bool isPreferred = address->DadState == IpDadStatePreferred;

    int score = 30;
    if (isUniqueLocal)
    {
        score = 0;
    }
    else if (isLinkLocal)
    {
        score = 10;
    }
    else
    {
        score = 20;
    }

    if (isTemporary)
    {
        score += 5;
    }

    if (!isPreferred)
    {
        score += 2;
    }

    return score;
}

struct ActiveNetworkSnapshot
{
    std::wstring adapterName;
    std::wstring adapterType;
    std::wstring macAddress;
    std::wstring networkName;
    std::wstring ipv4Address;
    std::wstring ipv6Address;
    std::wstring defaultGateway;
    std::wstring publicIpv4Address;
    std::wstring publicIpv6Address;
    std::wstring diagnostic;
    bool hasPublicAddressLookup = false;
};

ActiveNetworkSnapshot QueryActiveNetworkSnapshot()
{
    ActiveNetworkSnapshot snapshot;

    ULONG bufferSize = 0;
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &bufferSize);
    if (result != ERROR_BUFFER_OVERFLOW)
    {
        snapshot.diagnostic = L"GetAdaptersAddresses failed: " + FormatStatusCode(result);
        return snapshot;
    }

    std::vector<BYTE> buffer(bufferSize);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferSize);
    if (result != NO_ERROR)
    {
        snapshot.diagnostic = L"GetAdaptersAddresses failed: " + FormatStatusCode(result);
        return snapshot;
    }

    DWORD bestInterfaceIndex = 0;
    IN_ADDR internetProbeAddress{};
    if (InetPtonW(AF_INET, L"8.8.8.8", &internetProbeAddress) != 1 ||
        GetBestInterface(internetProbeAddress.S_un.S_addr, &bestInterfaceIndex) != NO_ERROR)
    {
        bestInterfaceIndex = 0;
    }

    PIP_ADAPTER_ADDRESSES chosenAdapter = nullptr;
    PIP_ADAPTER_ADDRESSES fallbackWithGateway = nullptr;
    PIP_ADAPTER_ADDRESSES fallbackAdapter = nullptr;

    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
    {
        if (!IsCandidateNetworkAdapter(adapter))
        {
            continue;
        }

        if (fallbackAdapter == nullptr)
        {
            fallbackAdapter = adapter;
        }

        if (adapter->FirstGatewayAddress != nullptr && fallbackWithGateway == nullptr)
        {
            fallbackWithGateway = adapter;
        }

        if (bestInterfaceIndex != 0 &&
            (adapter->IfIndex == bestInterfaceIndex || adapter->Ipv6IfIndex == bestInterfaceIndex))
        {
            chosenAdapter = adapter;
            break;
        }
    }

    if (chosenAdapter == nullptr)
    {
        chosenAdapter = fallbackWithGateway != nullptr ? fallbackWithGateway : fallbackAdapter;
    }

    if (chosenAdapter == nullptr)
    {
        snapshot.diagnostic = L"No active network adapter found.";
        return snapshot;
    }

    snapshot.adapterName = chosenAdapter->FriendlyName != nullptr ? chosenAdapter->FriendlyName : L"Unavailable";
    snapshot.adapterType = AdapterTypeToString(chosenAdapter->IfType);
    snapshot.macAddress = FormatMacAddress(chosenAdapter->PhysicalAddress, chosenAdapter->PhysicalAddressLength);
    snapshot.hasPublicAddressLookup =
        chosenAdapter->IfType == IF_TYPE_IEEE80211 ||
        chosenAdapter->IfType == IF_TYPE_ETHERNET_CSMACD;

    std::vector<std::wstring> ipv4Addresses;
    std::wstring bestIpv6Address;
    int bestIpv6Priority = (std::numeric_limits<int>::max)();
    for (auto* address = chosenAdapter->FirstUnicastAddress; address != nullptr; address = address->Next)
    {
        const std::wstring addressText = SockaddrToAddressString(address->Address.lpSockaddr);
        if (addressText.empty())
        {
            continue;
        }

        if (address->Address.lpSockaddr->sa_family == AF_INET)
        {
            AddUniqueValue(ipv4Addresses, addressText);
        }
        else if (address->Address.lpSockaddr->sa_family == AF_INET6)
        {
            const int priority = GetIpv6AddressPriority(address);
            if (priority < bestIpv6Priority)
            {
                bestIpv6Priority = priority;
                bestIpv6Address = addressText;
            }
        }
    }

    snapshot.ipv4Address = JoinValues(ipv4Addresses);
    snapshot.ipv6Address = DefaultIfEmpty(bestIpv6Address, L"Unavailable");

    if (chosenAdapter->FirstGatewayAddress != nullptr)
    {
        snapshot.defaultGateway = SockaddrToAddressString(chosenAdapter->FirstGatewayAddress->Address.lpSockaddr);
    }
    if (snapshot.defaultGateway.empty())
    {
        snapshot.defaultGateway = L"Unavailable";
    }

    if (chosenAdapter->IfType == IF_TYPE_IEEE80211)
    {
        snapshot.networkName = DefaultIfEmpty(QueryWifiNetworkName(snapshot.adapterName), L"Unavailable");
    }
    else
    {
        snapshot.networkName = L"Not applicable";
    }

    if (snapshot.hasPublicAddressLookup)
    {
        snapshot.publicIpv4Address = QueryPublicIpAddress(L"api4.ipify.org");
        snapshot.publicIpv6Address = QueryPublicIpAddress(L"api6.ipify.org");
    }

    return snapshot;
}

struct BitLockerVolumeSummary
{
    std::wstring volume;
    std::wstring size;
    std::wstring conversionStatus;
    std::wstring percentageEncrypted;
    std::wstring protectionStatus;
    std::wstring lockStatus;
    std::wstring recoveryProtectorId;
    std::wstring recoveryPassword;
};

std::wstring ExtractLabeledValue(const std::wstring& line, const wchar_t* label)
{
    if (!StartsWithIgnoreCase(line, label))
    {
        return {};
    }

    const std::size_t separator = line.find(L':');
    if (separator == std::wstring::npos)
    {
        return {};
    }

    return TrimWhitespace(line.substr(separator + 1));
}

bool IsEncryptedBitLockerVolume(const BitLockerVolumeSummary& volume)
{
    const std::wstring normalizedStatus = ToLowerInvariant(volume.conversionStatus);
    if (!normalizedStatus.empty())
    {
        if (normalizedStatus.find(L"decryption") != std::wstring::npos)
        {
            return true;
        }

        if (normalizedStatus.find(L"encrypted") != std::wstring::npos ||
            normalizedStatus.find(L"encryption") != std::wstring::npos)
        {
            return true;
        }

        if (normalizedStatus.find(L"decrypted") != std::wstring::npos)
        {
            return false;
        }
    }

    const std::wstring normalizedPercentage = TrimWhitespace(volume.percentageEncrypted);
    return !normalizedPercentage.empty() && normalizedPercentage != L"0%" && normalizedPercentage != L"0.0%";
}

bool IsLockedBitLockerVolume(const BitLockerVolumeSummary& volume)
{
    const std::wstring normalizedLockStatus = ToLowerInvariant(volume.lockStatus);
    return normalizedLockStatus.find(L"locked") != std::wstring::npos &&
        normalizedLockStatus.find(L"unlocked") == std::wstring::npos;
}

void FinalizeBitLockerVolume(BitLockerVolumeSummary& currentVolume, std::vector<BitLockerVolumeSummary>& encryptedVolumes)
{
    if (!currentVolume.volume.empty() && IsEncryptedBitLockerVolume(currentVolume))
    {
        encryptedVolumes.push_back(currentVolume);
    }

    currentVolume = {};
}

std::vector<BitLockerVolumeSummary> ParseBitLockerStatusOutput(const std::wstring& statusOutput)
{
    std::vector<BitLockerVolumeSummary> encryptedVolumes;
    std::wistringstream input(statusOutput);
    std::wstring line;
    BitLockerVolumeSummary currentVolume;

    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == L'\r')
        {
            line.pop_back();
        }

        const std::wstring trimmedLine = TrimWhitespace(line);
        if (trimmedLine.empty())
        {
            continue;
        }

        if (StartsWithIgnoreCase(trimmedLine, L"Volume "))
        {
            FinalizeBitLockerVolume(currentVolume, encryptedVolumes);
            currentVolume.volume = trimmedLine;
            continue;
        }

        if (currentVolume.volume.empty())
        {
            continue;
        }

        if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Size"); !value.empty())
        {
            currentVolume.size = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Conversion Status"); !value.empty())
        {
            currentVolume.conversionStatus = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Percentage Encrypted"); !value.empty())
        {
            currentVolume.percentageEncrypted = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Protection Status"); !value.empty())
        {
            currentVolume.protectionStatus = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Lock Status"); !value.empty())
        {
            currentVolume.lockStatus = value;
        }
    }

    FinalizeBitLockerVolume(currentVolume, encryptedVolumes);
    return encryptedVolumes;
}

std::wstring FormatBitLockerVolumeLabel(const std::wstring& volumeHeader)
{
    std::wstring value = TrimWhitespace(volumeHeader);

    if (StartsWithIgnoreCase(value, L"Volume "))
    {
        value = TrimWhitespace(value.substr(wcslen(L"Volume ")));
    }

    return DefaultIfEmpty(value, L"Unavailable");
}

std::wstring ExtractVolumeMountPoint(const std::wstring& volumeHeader)
{
    std::wistringstream stream(volumeHeader);
    std::wstring keyword;
    std::wstring mountPoint;
    stream >> keyword >> mountPoint;
    return mountPoint;
}

struct BitLockerRecoveryProtector
{
    std::wstring id;
    std::wstring password;
};

BitLockerRecoveryProtector QueryRecoveryProtector(const std::wstring& volumeHeader)
{
    BitLockerRecoveryProtector protector;

    const std::wstring mountPoint = ExtractVolumeMountPoint(volumeHeader);
    if (mountPoint.empty())
    {
        return protector;
    }

    const std::wstring output = NormalizeDisplayText(RunCommandCapture(L"manage-bde -protectors -get " + mountPoint));
    if (output.empty() || output.find(L"ERROR:") != std::wstring::npos)
    {
        return protector;
    }

    std::wistringstream input(output);
    std::wstring line;

    bool inNumericalPassword = false;
    bool waitingForPasswordValue = false;

    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == L'\r')
        {
            line.pop_back();
        }

        const std::wstring trimmedLine = TrimWhitespace(line);
        if (trimmedLine.empty())
        {
            continue;
        }

        if (StartsWithIgnoreCase(trimmedLine, L"Numerical Password"))
        {
            inNumericalPassword = true;
            waitingForPasswordValue = true;

            continue;
        }

        if (!inNumericalPassword)
        {
            continue;
        }

        if (const std::wstring id = ExtractLabeledValue(trimmedLine, L"ID"); !id.empty())
        {
            protector.id = id;
            continue;
        }

        if (StartsWithIgnoreCase(trimmedLine, L"Password"))
        {
            const std::wstring passwordOnSameLine = ExtractLabeledValue(trimmedLine, L"Password");

            if (!passwordOnSameLine.empty())
            {
                protector.password = passwordOnSameLine;
                waitingForPasswordValue = false;
            }
            else
            {
                waitingForPasswordValue = true;
            }

            continue;
        }

        if (waitingForPasswordValue)
        {
            protector.password = trimmedLine;
            waitingForPasswordValue = false;
            continue;
        }

        if (trimmedLine.back() == L'.' && !StartsWithIgnoreCase(trimmedLine, L"ID") && !StartsWithIgnoreCase(trimmedLine, L"Password"))
        {
            break;
        }
    }

    return protector;
}

bool IsUserCreatedShare(const SHARE_INFO_2& share)
{
    if ((share.shi2_type & STYPE_SPECIAL) != 0)
    {
        return false;
    }

    if ((share.shi2_type & 0xFF) != STYPE_DISKTREE)
    {
        return false;
    }

    if (share.shi2_netname == nullptr || *share.shi2_netname == L'\0')
    {
        return false;
    }

    if (wcschr(share.shi2_netname, L'$') != nullptr)
    {
        return false;
    }

    return true;
}

void AppendTcp4Entries(std::wostringstream& stream)
{
    AppendHeader(stream, L"TCP IPv4", L'-');

    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER)
    {
        stream << L"Unable to query TCP IPv4 connections: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    std::vector<BYTE> buffer(size);
    result = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR)
    {
        stream << L"Unable to query TCP IPv4 connections: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    if (table->dwNumEntries == 0)
    {
        stream << L"No TCP IPv4 connections found.\r\n";
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const auto& row = table->table[i];
        stream << L"Local: " << FormatIpv4Address(row.dwLocalAddr) << L":" << FormatPort(row.dwLocalPort)
               << L" | Remote: " << FormatIpv4Address(row.dwRemoteAddr) << L":" << FormatPort(row.dwRemotePort)
               << L" | State: " << TcpStateToString(row.dwState)
               << L" | PID: " << row.dwOwningPid << L"\r\n";
    }
}

void AppendTcp6Entries(std::wostringstream& stream)
{
    AppendHeader(stream, L"TCP IPv6", L'-');

    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER)
    {
        stream << L"Unable to query TCP IPv6 connections: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    std::vector<BYTE> buffer(size);
    result = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR)
    {
        stream << L"Unable to query TCP IPv6 connections: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    auto* table = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());
    if (table->dwNumEntries == 0)
    {
        stream << L"No TCP IPv6 connections found.\r\n";
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const auto& row = table->table[i];
        stream << L"Local: [" << FormatIpv6Address(row.ucLocalAddr, row.dwLocalScopeId) << L"]:" << FormatPort(row.dwLocalPort)
               << L" | Remote: [" << FormatIpv6Address(row.ucRemoteAddr, row.dwRemoteScopeId) << L"]:" << FormatPort(row.dwRemotePort)
               << L" | State: " << TcpStateToString(row.dwState)
               << L" | PID: " << row.dwOwningPid << L"\r\n";
    }
}

void AppendUdp4Entries(std::wostringstream& stream)
{
    AppendHeader(stream, L"UDP IPv4", L'-');

    DWORD size = 0;
    DWORD result = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER)
    {
        stream << L"Unable to query UDP IPv4 listeners: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    std::vector<BYTE> buffer(size);
    result = GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (result != NO_ERROR)
    {
        stream << L"Unable to query UDP IPv4 listeners: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
    if (table->dwNumEntries == 0)
    {
        stream << L"No UDP IPv4 listeners found.\r\n";
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const auto& row = table->table[i];
        stream << L"Local: " << FormatIpv4Address(row.dwLocalAddr) << L":" << FormatPort(row.dwLocalPort)
               << L" | State: LISTEN"
               << L" | PID: " << row.dwOwningPid << L"\r\n";
    }
}

void AppendUdp6Entries(std::wostringstream& stream)
{
    AppendHeader(stream, L"UDP IPv6", L'-');

    DWORD size = 0;
    DWORD result = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER)
    {
        stream << L"Unable to query UDP IPv6 listeners: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    std::vector<BYTE> buffer(size);
    result = GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (result != NO_ERROR)
    {
        stream << L"Unable to query UDP IPv6 listeners: " << FormatStatusCode(result) << L"\r\n";
        return;
    }

    auto* table = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());
    if (table->dwNumEntries == 0)
    {
        stream << L"No UDP IPv6 listeners found.\r\n";
        return;
    }

    for (DWORD i = 0; i < table->dwNumEntries; ++i)
    {
        const auto& row = table->table[i];
        stream << L"Local: [" << FormatIpv6Address(row.ucLocalAddr, row.dwLocalScopeId) << L"]:" << FormatPort(row.dwLocalPort)
               << L" | State: LISTEN"
               << L" | PID: " << row.dwOwningPid << L"\r\n";
    }
}

void AppendSharedFolders(std::wostringstream& stream)
{
    AppendHeader(stream, L"Shared Resources", L'=');

    SHARE_INFO_2* shares = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    DWORD totalCollected = 0;

    NET_API_STATUS status = NERR_Success;
    do
    {
        status = NetShareEnum(
            nullptr,
            2,
            reinterpret_cast<LPBYTE*>(&shares),
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle);

        if (status != NERR_Success && status != ERROR_MORE_DATA)
        {
            stream << L"NetShareEnum failed: " << FormatStatusCode(status) << L"\r\n";
            return;
        }

        for (DWORD i = 0; i < entriesRead; ++i)
        {
            const SHARE_INFO_2& share = shares[i];
            if (!IsUserCreatedShare(share))
            {
                continue;
            }

            if (totalCollected > 0)
            {
                stream << L"\r\n";
            }

            AppendField(stream, L"Name", share.shi2_netname ? share.shi2_netname : L"(unknown)", L"(unknown)");
            AppendField(stream, L"Path", share.shi2_path && *share.shi2_path ? share.shi2_path : L"(not applicable)", L"(not applicable)");
            AppendField(stream, L"Remark", share.shi2_remark && *share.shi2_remark ? share.shi2_remark : L"(none)", L"(none)");
            ++totalCollected;
        }

        if (shares != nullptr)
        {
            NetApiBufferFree(shares);
            shares = nullptr;
        }
    } while (status == ERROR_MORE_DATA);

    if (totalCollected == 0)
    {
        stream << L"No user shared folders found.\r\n";
    }
}

std::wstring CollectNetworkAndShareInformation()
{
    std::wostringstream stream;
    AppendHeader(stream, L"Active Network", L'=');

    WSADATA winsockData{};
    const int winsockResult = WSAStartup(MAKEWORD(2, 2), &winsockData);
    if (winsockResult != 0)
    {
        stream << L"WSAStartup failed: " << winsockResult << L"\r\n";
        return NormalizeDisplayText(stream.str());
    }

    const ActiveNetworkSnapshot snapshot = QueryActiveNetworkSnapshot();
    if (!snapshot.diagnostic.empty())
    {
        stream << snapshot.diagnostic << L"\r\n";
    }
    else
    {
        AppendField(stream, L"Adapter Type", snapshot.adapterType, L"Unavailable");
        AppendField(stream, L"MAC Address", snapshot.macAddress, L"Unavailable");
        AppendField(stream, L"Network Name", snapshot.networkName, L"Unavailable");
        AppendField(stream, L"Local IPv4 Address", snapshot.ipv4Address, L"Unavailable");
        AppendField(stream, L"Local IPv6 Address", snapshot.ipv6Address, L"Unavailable");
        if (snapshot.hasPublicAddressLookup)
        {
            AppendField(stream, L"Public IPv4 Address", snapshot.publicIpv4Address, L"Unavailable");
            AppendField(stream, L"Public IPv6 Address", snapshot.publicIpv6Address, L"Unavailable");
        }
    }

    AppendSharedFolders(stream);

    WSACleanup();

    return NormalizeDisplayText(stream.str());
}

std::wstring CollectBitLockerInformation()
{
    const std::wstring output = NormalizeDisplayText(RunCommandCapture(L"manage-bde -status"));
    if (output.empty())
    {
        return L"No BitLocker data available.";
    }

    if (output.find(L"ERROR:") != std::wstring::npos && output.find(L"Volume ") == std::wstring::npos)
    {
        return output;
    }

    std::vector<BitLockerVolumeSummary> encryptedVolumes = ParseBitLockerStatusOutput(output);

    std::wostringstream stream;
    AppendHeader(stream, L"Encrypted Volumes", L'=');

    if (encryptedVolumes.empty())
    {
        stream << L"No encrypted volumes found.\r\n";
        return NormalizeDisplayText(stream.str());
    }

    for (std::size_t index = 0; index < encryptedVolumes.size(); ++index)
    {
        if (index > 0)
        {
            stream << L"\r\n";
        }

        BitLockerVolumeSummary& volume = encryptedVolumes[index];
        if (volume.recoveryProtectorId.empty() || volume.recoveryPassword.empty())
        {
            const BitLockerRecoveryProtector protector = QueryRecoveryProtector(volume.volume);

            volume.recoveryProtectorId = protector.id;
            volume.recoveryPassword = protector.password;
        }

        AppendField(stream, L"Volume", FormatBitLockerVolumeLabel(volume.volume), L"Unavailable");
        AppendField(stream, L"Size", volume.size, L"Unavailable");
        AppendField(stream, L"Protection Status", volume.protectionStatus, L"Unavailable");
        AppendField(stream, L"Lock Status", volume.lockStatus, L"Unavailable");
        AppendField(stream, L"Recovery Protector ID", volume.recoveryProtectorId, L"Not found");
        if (!IsLockedBitLockerVolume(volume))
        {
            AppendField(stream, L"Recovery Key", volume.recoveryPassword, L"Not found");
        }
    }

    return NormalizeDisplayText(stream.str());
}

} // namespace

std::wstring ForensicCollector::CollectSection(ForensicSection section) const
{
    switch (section)
    {
    case ForensicSection::OperatingSystem:
        return CollectOperatingSystemInformation();
    case ForensicSection::UserAccounts:
        return CollectUserAccountInformation();
    case ForensicSection::NetworkShares:
        return CollectNetworkAndShareInformation();
    case ForensicSection::BitLocker:
        return CollectBitLockerInformation();
    default:
        return L"Unsupported forensic section.";
    }
}
} // namespace Sothoth::Core
