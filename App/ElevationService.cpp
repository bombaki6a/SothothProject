#include "framework.h"

#include "ElevationService.h"

#include <array>
#include <shellapi.h>
#include <string>

namespace
{
constexpr wchar_t kElevationAttemptSwitch[] = L"--elevation-attempted";

/// Checks the elevation-attempt marker to prevent a relaunch loop.
bool CurrentCommandLineHasSwitch(const wchar_t* expectedSwitch)
{
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (arguments == nullptr)
    {
        return false;
    }

    bool found = false;
    for (int index = 1; index < argumentCount; ++index)
    {
        if (CompareStringOrdinal(arguments[index], -1, expectedSwitch, -1, TRUE) == CSTR_EQUAL)
        {
            found = true;
            break;
        }
    }

    LocalFree(arguments);
    return found;
}
} // namespace

namespace Sothoth::App
{
/// Checks effective membership in the local administrators group using the process token.
bool CurrentProcessHasAdministratorRights()
{
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup = nullptr;
    BOOL isMember = FALSE;

    if (!AllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &administratorsGroup))
    {
        return false;
    }

    const BOOL membershipResult = CheckTokenMembership(nullptr, administratorsGroup, &isMember);
    FreeSid(administratorsGroup);

    return membershipResult == TRUE && isMember == TRUE;
}

/// Offers a UAC relaunch once; a declined prompt lets the current process continue.
bool TryRelaunchElevatedAndExitCurrentIfAccepted(const wchar_t* commandLine)
{
    if (CurrentProcessHasAdministratorRights() || CurrentCommandLineHasSwitch(kElevationAttemptSwitch))
    {
        return false;
    }

    wchar_t executablePath[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, executablePath, static_cast<DWORD>(std::size(executablePath))) == 0)
    {
        return false;
    }

    std::wstring parameters = kElevationAttemptSwitch;
    if (commandLine != nullptr && *commandLine != L'\0')
    {
        parameters += L' ';
        parameters += commandLine;
    }

    const auto launchResult = reinterpret_cast<INT_PTR>(
        ShellExecuteW(nullptr, L"runas", executablePath, parameters.c_str(), nullptr, SW_SHOWNORMAL));

    return launchResult > 32;
}

/// Formats the privilege indicator shown alongside report status.
std::wstring BuildPrivilegeStateText(bool isElevated)
{
    return isElevated ? L"Administrator: Yes" : L"Administrator: No";
}
} // namespace Sothoth::App
