#include "framework.h"
#include "SystemCollector.h"
#include "../Support/CollectorSupport.h"

#include <lm.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "netapi32.lib")

namespace Sothoth::Core
{
using namespace Support;
namespace
{
/// Captures the machine's local time as a stable, human-readable collection timestamp.
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

/// Converts a Windows registry Unix timestamp to local time for the system report.
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

/// Reads a DWORD registry value and reports whether the query succeeded.
bool QueryRegistryDwordValue(HKEY rootKey, const wchar_t* subKey, const wchar_t* valueName, DWORD& value)
{
    DWORD size = sizeof(value);
    return RegGetValueW(rootKey, subKey, valueName, RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS;
}

/// Queries a computer name using the requested Windows name format and a correctly sized buffer.
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

/// Formats a locale identifier for display, retaining a fallback when descriptive lookup fails.
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

/// Reads the machine's default system locale for the regional settings section.
std::wstring QuerySystemLocaleValue()
{
    wchar_t localeName[LOCALE_NAME_MAX_LENGTH]{};
    if (GetSystemDefaultLocaleName(localeName, static_cast<int>(std::size(localeName))) == 0)
    {
        return L"Unavailable";
    }

    return QueryLocaleDisplayValue(localeName);
}

/// Reads the active input locale for the regional settings section.
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

/// Formats the Windows time-zone bias as a signed UTC offset.
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

/// Combines the current time-zone name and effective UTC offset, including daylight-saving bias.
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

/// Reports domain or workgroup membership using the local machine's join information.
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

/// Reads the system model from firmware-backed registry values.
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

/// Reads the Windows build number used to distinguish client OS generations.
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

/// Corrects the Windows product label using the build number while preserving the edition.
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

/// Formats OS version, build, and revision from the available system metadata.
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

/// Reports physical memory using the installed-memory API with a memory-status fallback.
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
} // namespace

/// Collects and formats this category using the existing filtering and display rules.
std::wstring SystemCollector::Collect() const
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
} // namespace Sothoth::Core
