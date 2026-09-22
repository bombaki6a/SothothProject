#include "framework.h"
#include "UserCollector.h"
#include "../Support/CollectorSupport.h"

#include <lm.h>
#include <sddl.h>

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
/// Maps the local account privilege level to the label shown in the user report.
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

/// Converts an account SID to its registry-compatible text representation and releases the API allocation.
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

/// Checks whether a profile location exists and is a directory.
bool DirectoryExists(const std::wstring& path)
{
    if (path.empty())
    {
        return false;
    }

    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

/// Checks whether a profile marker exists and is a regular file.
bool FileExists(const std::wstring& path)
{
    if (path.empty())
    {
        return false;
    }

    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

/// Resolves an account SID to its registered Windows profile directory.
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

/// Extracts the final relative identifier from a valid account SID.
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

/// Filters built-in and system-managed accounts using account names and well-known relative identifiers.
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

/// Applies the existing name heuristics for excluding application and service accounts.
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

/// Checks profile locations and markers used to identify ordinary interactive profiles.
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

/// Combines enabled-state, account-name, SID, and profile checks to filter the user report.
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

/// Normalizes cached account identifiers for matching local profiles to Microsoft identities.
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

/// Returns the final component of a registry or profile path for identity matching.
std::wstring ExtractLeafName(const std::wstring& path)
{
    const std::size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

/// Adds a usable cached identity from the given registry key when its required values are present.
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

/// Walks the identity cache with a bounded recursion depth and closes each opened registry key.
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

/// Loads locally cached Microsoft identity hints without contacting an external service.
std::vector<CachedMicrosoftIdentity> QueryCachedMicrosoftIdentities()
{
    std::vector<CachedMicrosoftIdentity> identities;
    EnumerateCachedMicrosoftIdentities(L"SOFTWARE\\Microsoft\\IdentityStore\\LogonCache", 0, identities);
    return identities;
}

/// Matches a local account to cached Microsoft identity hints and otherwise uses the local-account label.
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
} // namespace

/// Collects and formats this category using the existing filtering and display rules.
std::wstring UserCollector::Collect() const
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
} // namespace Sothoth::Core
