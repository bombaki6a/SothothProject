#pragma once

#include "framework.h"
#include <string>

/// Handles report-name entry independently of collection and export.
class ReportNameDialog
{
public:
    /// Prompts for a nonempty name; returns false on cancellation or dialog creation failure.
    static bool Show(HINSTANCE instance, HWND owner, std::wstring& name);
private:
    /// Updates validation state and commits the entered name only when the user confirms.
    static INT_PTR CALLBACK DialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam);
};
