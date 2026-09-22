#pragma once

#include <string>

namespace Sothoth::App
{
/// Checks effective membership in the local administrators group using the process token.
bool CurrentProcessHasAdministratorRights();
/// Offers a UAC relaunch once; a declined prompt lets the current process continue.
bool TryRelaunchElevatedAndExitCurrentIfAccepted(const wchar_t* commandLine);
/// Formats the privilege indicator shown alongside report status.
std::wstring BuildPrivilegeStateText(bool isElevated);
} // namespace Sothoth::App
