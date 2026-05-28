#pragma once

#include <string>

namespace Sothoth::App
{
bool CurrentProcessHasAdministratorRights();
bool TryRelaunchElevatedAndExitCurrentIfAccepted(const wchar_t* commandLine);
std::wstring BuildPrivilegeStateText(bool isElevated);
} // namespace Sothoth::App
