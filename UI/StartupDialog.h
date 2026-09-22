#pragma once

#include "framework.h"
#include "../Core/Reports/CollectionReport.h"

/// Owns category selection, worker lifetime, and automatic report generation.
class StartupDialog
{
public:
    /// Configures the dialog for the process privilege level and target report.
    StartupDialog(HINSTANCE instance, bool isElevated, Sothoth::Core::CollectionReport& report);
    /// Runs the initial modal workflow; cancellation returns false and leaves the app free to exit.
    bool Show();
private:
    /// Handles selection, progress polling, and completion without blocking the dialog during collection.
    static INT_PTR CALLBACK DialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam);
    /// Prompts for a report name and rejects destinations that already exist.
    bool ChooseReportName(HWND owner);
    /// Saves the collected snapshot and displays a recoverable error when writing fails.
    bool SaveReport();
    /// Allows encryption only on a 64-bit build with administrator privileges.
    bool IsEncryptionAvailable() const;

    HINSTANCE instance_ = nullptr;
    bool isElevated_ = false;
    HWND startupDialog_ = nullptr;
    HANDLE collectionThread_ = nullptr;
    HICON startupIcon_ = nullptr;
    bool isCollecting_ = false;
    Sothoth::Core::CollectionReport& report_;
};
